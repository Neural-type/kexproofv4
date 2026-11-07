#import "KPAuditCoW112576Module.h"
#import "KPLog.h"
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>
#import <sys/mman.h>
#import <sys/wait.h>
#import <unistd.h>
#import <fcntl.h>

extern kern_return_t mach_vm_behavior_set(vm_map_t target_task, mach_vm_address_t address,
                                          mach_vm_size_t size, vm_behavior_t new_behavior);
extern kern_return_t mach_vm_msync(vm_map_t target_task, mach_vm_address_t address,
                                   mach_vm_size_t size, vm_sync_t sync_flags);

@interface KPAuditCoW112576Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditCoW112576Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"cow112576.armed" : @"cow112576.baseline";
        _title = armed ? @"Kernel CoW integrity (armed)" : @"Kernel CoW (baseline)";
        _subtitle = armed
            ? @"CoW + behavior/msync + remap inheritance; native-gated race; pread verify"
            : @"Benign private copy sanity: copy mutates destination only";
        _icon = armed ? @"doc.on.doc" : @"square.stack.3d.down.right";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Setup

static const size_t kKPPageSize = 0x4000;

- (nullable NSString *)writeSourceFileWithPattern {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-cow-src.bin"];
    NSMutableData *data = [NSMutableData dataWithLength:kKPPageSize];
    uint8_t *bytes = data.mutableBytes;
    for (size_t i = 0; i < kKPPageSize; i++) bytes[i] = (uint8_t)(i & 0xFF);
    if (![data writeToFile:path atomically:YES]) return nil;
    return path;
}

- (BOOL)fileStillOriginalAtPath:(NSString *)path {
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) return NO;
    uint8_t buffer[512];
    size_t offset = 0;
    while (offset < kKPPageSize) {
        size_t chunk = MIN(sizeof(buffer), kKPPageSize - offset);
        ssize_t amount = pread(fd, buffer, chunk, (off_t)offset);
        if (amount <= 0) {
            close(fd);
            return NO;
        }
        for (ssize_t i = 0; i < amount; i++) {
            if (buffer[i] != (uint8_t)((offset + (size_t)i) & 0xFF)) {
                close(fd);
                return NO;
            }
        }
        offset += (size_t)amount;
    }
    uint8_t extra = 0;
    BOOL exactSize = pread(fd, &extra, 1, (off_t)kKPPageSize) == 0;
    close(fd);
    return exactSize;
}

#pragma mark - CoW shapes

typedef struct {
    _Atomic int stop;
    char *mapping;
    size_t length;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    BOOL go;
} KPCoWRaceArgs;

static BOOL KPCoWGateInit(KPCoWRaceArgs *args) {
    if (pthread_mutex_init(&args->mutex, NULL) != 0) return NO;
    if (pthread_cond_init(&args->condition, NULL) != 0) {
        pthread_mutex_destroy(&args->mutex);
        return NO;
    }
    return YES;
}

static void KPCoWArriveAndWait(KPCoWRaceArgs *args) {
    pthread_mutex_lock(&args->mutex);
    args->ready++;
    pthread_cond_broadcast(&args->condition);
    while (!args->go) pthread_cond_wait(&args->condition, &args->mutex);
    pthread_mutex_unlock(&args->mutex);
}

static void *KPCoWMadviseLoop(void *arg) {
    KPCoWRaceArgs *args = (KPCoWRaceArgs *)arg;
    KPCoWArriveAndWait(args);
    while (!atomic_load_explicit(&args->stop, memory_order_relaxed)) {
        madvise(args->mapping, args->length, MADV_FREE);
        madvise(args->mapping, args->length, MADV_DONTNEED);
        madvise(args->mapping, args->length, MADV_FREE_REUSABLE);
    }
    return NULL;
}

static void *KPCoWWriteLoop(void *arg) {
    KPCoWRaceArgs *args = (KPCoWRaceArgs *)arg;
    KPCoWArriveAndWait(args);
    char value = 0x41;
    while (!atomic_load_explicit(&args->stop, memory_order_relaxed)) {
        memset(args->mapping, value, 16);
    }
    return NULL;
}

// Shape 1: mach_vm_copy + MADV_FREE_REUSABLE (original hunter hypothesis)
- (NSDictionary *)runShapeMachVMCopyAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED) {
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }
    uint32_t changed = 0;
    for (uint32_t i = 0; i < iters; i++) {
        vm_address_t dst = 0;
        kern_return_t kr = vm_allocate(mach_task_self(), &dst, kKPPageSize, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) break;
        vm_copy(mach_task_self(), (vm_address_t)src, kKPPageSize, dst);
        madvise((void *)dst, kKPPageSize, MADV_FREE_REUSABLE);
        memset((void *)dst, 0x42, 64);
        vm_deallocate(mach_task_self(), dst, kKPPageSize);
        if (![self fileStillOriginalAtPath:path]) { changed++; break; }
    }
    munmap(src, kKPPageSize);
    close(fd);
    return @{@"shape": @"vm_copy+MADV_FREE_REUSABLE", @"iterations": @(iters),
             @"file_changed": @(changed > 0)};
}

// Shape 2: file-backed MAP_PRIVATE + native-gated madvise/write threads (dirty-CoW)
- (NSDictionary *)runShapeThreadedAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED) {
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }

    KPCoWRaceArgs args = {.mapping = (char *)src, .length = kKPPageSize};
    if (!KPCoWGateInit(&args)) {
        munmap(src, kKPPageSize);
        close(fd);
        return @{@"status": @"GATE_INIT_FAILED"};
    }

    pthread_t tMadvise, tWrite;
    int madviseRC = pthread_create(&tMadvise, NULL, KPCoWMadviseLoop, &args);
    int writeRC = madviseRC == 0 ? pthread_create(&tWrite, NULL, KPCoWWriteLoop, &args) : -1;
    if (madviseRC != 0 || writeRC != 0) {
        pthread_mutex_lock(&args.mutex);
        atomic_store_explicit(&args.stop, 1, memory_order_relaxed);
        args.go = YES;
        pthread_cond_broadcast(&args.condition);
        pthread_mutex_unlock(&args.mutex);
        if (madviseRC == 0) pthread_join(tMadvise, NULL);
        pthread_cond_destroy(&args.condition);
        pthread_mutex_destroy(&args.mutex);
        munmap(src, kKPPageSize);
        close(fd);
        return @{@"status": @"THREAD_CREATE_FAILED", @"madvise_rc": @(madviseRC), @"write_rc": @(writeRC)};
    }

    pthread_mutex_lock(&args.mutex);
    while (args.ready != 2) pthread_cond_wait(&args.condition, &args.mutex);
    args.go = YES;
    pthread_cond_broadcast(&args.condition);
    pthread_mutex_unlock(&args.mutex);

    uint32_t completed = 0;
    for (uint32_t i = 0; i < iters; i++) {
        completed++;
        if (![self fileStillOriginalAtPath:path]) break;
        usleep(200);
    }
    atomic_store_explicit(&args.stop, 1, memory_order_relaxed);
    pthread_join(tMadvise, NULL);
    pthread_join(tWrite, NULL);
    pthread_cond_destroy(&args.condition);
    pthread_mutex_destroy(&args.mutex);

    BOOL changed = ![self fileStillOriginalAtPath:path];
    munmap(src, kKPPageSize);
    close(fd);
    return @{@"shape": @"MAP_PRIVATE+native-gate+madvise/write-threads", @"iterations": @(completed),
             @"gate_ready": @(args.ready), @"file_changed": @(changed)};
}

// Shape 3: vm_copy (BSD) + MADV_DONTNEED
- (NSDictionary *)runShapeVMCopyAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    void *dst = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (src == MAP_FAILED || dst == MAP_FAILED) {
        if (src != MAP_FAILED) munmap(src, kKPPageSize);
        if (dst != MAP_FAILED) munmap(dst, kKPPageSize);
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }
    uint32_t changed = 0;
    for (uint32_t i = 0; i < iters; i++) {
        vm_copy(mach_task_self(), (vm_address_t)src, kKPPageSize, (vm_address_t)dst);
        madvise(dst, kKPPageSize, MADV_DONTNEED);
        memset(dst, 0x43, 64);
        if (![self fileStillOriginalAtPath:path]) { changed++; break; }
    }
    munmap(src, kKPPageSize);
    munmap(dst, kKPPageSize);
    close(fd);
    return @{@"shape": @"vm_copy+MADV_DONTNEED", @"iterations": @(iters),
             @"file_changed": @(changed > 0)};
}

// Shape 4: fork() child writes through inherited private mapping (classic CoW)
- (NSDictionary *)runShapeForkAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED) {
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }
    uint32_t changed = 0;
    for (uint32_t i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            memset(src, 0x44, 256);
            madvise(src, kKPPageSize, MADV_FREE);
            _exit(0);
        } else if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
        }
        if (![self fileStillOriginalAtPath:path]) { changed++; break; }
    }
    munmap(src, kKPPageSize);
    close(fd);
    return @{@"shape": @"fork()+child-write", @"iterations": @(iters),
             @"file_changed": @(changed > 0)};
}

#pragma mark - vm_object_update diagnostics

- (NSDictionary *)runVMObjectUpdateDiagnosticsAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    uint8_t *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    uint8_t *peer = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED || peer == MAP_FAILED) {
        if (src != MAP_FAILED) munmap(src, kKPPageSize);
        if (peer != MAP_FAILED) munmap(peer, kKPPageSize);
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }

    NSArray *behaviors = @[
        @{@"name": @"default", @"value": @(VM_BEHAVIOR_DEFAULT)},
        @{@"name": @"random", @"value": @(VM_BEHAVIOR_RANDOM)},
        @{@"name": @"sequential", @"value": @(VM_BEHAVIOR_SEQUENTIAL)},
        @{@"name": @"reverse_sequential", @"value": @(VM_BEHAVIOR_RSEQNTL)},
        @{@"name": @"willneed", @"value": @(VM_BEHAVIOR_WILLNEED)},
        @{@"name": @"dontneed", @"value": @(VM_BEHAVIOR_DONTNEED)},
        @{@"name": @"reusable", @"value": @(VM_BEHAVIOR_REUSABLE)},
        @{@"name": @"reuse", @"value": @(VM_BEHAVIOR_REUSE)},
        @{@"name": @"can_reuse", @"value": @(VM_BEHAVIOR_CAN_REUSE)},
    ];
    NSMutableArray *behaviorResults = [NSMutableArray array];
    uint32_t peerChanges = 0, fileChanges = 0, operationFailures = 0;
    for (NSDictionary *behavior in behaviors) {
        kern_return_t kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)src,
                                                kKPPageSize, (vm_behavior_t)[behavior[@"value"] intValue]);
        uint32_t completed = 0;
        BOOL sourceChanged = NO, peerChanged = NO, fileChanged = NO;
        if (kr == KERN_SUCCESS) {
            for (uint32_t i = 0; i < iters; i++) {
                src[0] = 0x41;
                sourceChanged = sourceChanged || src[0] == 0x41;
                completed++;
                if (peer[0] != 0) {
                    peerChanged = YES;
                    peerChanges++;
                    break;
                }
                if (![self fileStillOriginalAtPath:path]) {
                    fileChanged = YES;
                    fileChanges++;
                    break;
                }
                src[0] = 0;
            }
        } else {
            operationFailures++;
        }
        [behaviorResults addObject:@{
            @"behavior": behavior[@"name"], @"kr": @(kr), @"iterations": @(completed),
            @"source_changed": @(sourceChanged), @"peer_changed": @(peerChanged),
            @"file_changed": @(fileChanged),
        }];
        if (peerChanged || fileChanged) break;
    }

    NSArray *syncModes = @[
        @{@"name": @"async", @"value": @(VM_SYNC_ASYNCHRONOUS)},
        @{@"name": @"sync", @"value": @(VM_SYNC_SYNCHRONOUS)},
        @{@"name": @"async_invalidate", @"value": @(VM_SYNC_ASYNCHRONOUS | VM_SYNC_INVALIDATE)},
        @{@"name": @"sync_invalidate", @"value": @(VM_SYNC_SYNCHRONOUS | VM_SYNC_INVALIDATE)},
        @{@"name": @"deactivate", @"value": @(VM_SYNC_DEACTIVATE)},
        @{@"name": @"reusablepages", @"value": @(VM_SYNC_REUSABLEPAGES)},
    ];
    NSMutableArray *msyncResults = [NSMutableArray array];
    if (peerChanges == 0 && fileChanges == 0) {
        for (NSDictionary *mode in syncModes) {
            src[0] = 0;
            uint32_t completed = 0;
            BOOL sourceChanged = NO, peerChanged = NO, fileChanged = NO;
            kern_return_t kr = KERN_SUCCESS;
            for (uint32_t i = 0; i < iters; i++) {
                src[0] = 0x42;
                sourceChanged = sourceChanged || src[0] == 0x42;
                kr = mach_vm_msync(mach_task_self(), (mach_vm_address_t)src,
                                   kKPPageSize, (vm_sync_t)[mode[@"value"] intValue]);
                completed++;
                if (kr != KERN_SUCCESS) {
                    operationFailures++;
                    break;
                }
                if (peer[0] != 0) {
                    peerChanged = YES;
                    peerChanges++;
                    break;
                }
                if (![self fileStillOriginalAtPath:path]) {
                    fileChanged = YES;
                    fileChanges++;
                    break;
                }
                src[0] = 0;
            }
            [msyncResults addObject:@{
                @"mode": mode[@"name"], @"kr": @(kr), @"iterations": @(completed),
                @"source_changed": @(sourceChanged), @"peer_changed": @(peerChanged),
                @"file_changed": @(fileChanged),
            }];
            if (peerChanged || fileChanged) break;
        }
    }

    munmap(src, kKPPageSize);
    munmap(peer, kKPPageSize);
    close(fd);
    return @{
        @"shape": @"vm_object_update: mach_vm_behavior_set + mach_vm_msync",
        @"behavior_cases": behaviorResults, @"msync_cases": msyncResults,
        @"operation_failures": @(operationFailures),
        @"peer_changes": @(peerChanges), @"file_changes": @(fileChanges),
    };
}

#pragma mark - vm_map_remap inheritance diagnostics

- (NSDictionary *)runRemapInheritanceDiagnosticsIterations:(uint32_t)iters {
    vm_address_t src = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &src, kKPPageSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return @{@"status": @"SRC_ALLOC_FAILED", @"kr": @(kr)};
    memset((void *)src, 0xCC, kKPPageSize);

    NSArray *inheritances = @[
        @{@"name": @"copy", @"value": @(VM_INHERIT_COPY)},
        @{@"name": @"share", @"value": @(VM_INHERIT_SHARE)},
        @{@"name": @"none", @"value": @(VM_INHERIT_NONE)},
        @{@"name": @"default", @"value": @(VM_INHERIT_DEFAULT)},
    ];
    NSMutableArray *cases = [NSMutableArray array];
    uint32_t remapFailures = 0, copyViolations = 0, sharedCases = 0, writeMisses = 0;
    for (NSNumber *copyNumber in @[@NO, @YES]) {
        for (NSNumber *overwriteNumber in @[@NO, @YES]) {
            for (NSDictionary *inheritance in inheritances) {
                BOOL copy = copyNumber.boolValue;
                BOOL overwrite = overwriteNumber.boolValue;
                vm_address_t dst = 0;
                if (overwrite) {
                    kr = vm_allocate(mach_task_self(), &dst, kKPPageSize, VM_FLAGS_ANYWHERE);
                    if (kr != KERN_SUCCESS) {
                        remapFailures++;
                        [cases addObject:@{@"copy": @(copy), @"overwrite": @(overwrite),
                                           @"inheritance": inheritance[@"name"],
                                           @"kr": @(kr), @"status": @"DST_ALLOC_FAILED"}];
                        continue;
                    }
                    memset((void *)dst, 0x44, kKPPageSize);
                }

                uint32_t completed = 0, caseViolations = 0;
                BOOL sharedObserved = NO, writeObserved = NO;
                kern_return_t lastKR = KERN_SUCCESS;
                for (uint32_t i = 0; i < iters; i++) {
                    vm_prot_t cur = 0, max = 0;
                    int flags = overwrite ? (VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE) : VM_FLAGS_ANYWHERE;
                    lastKR = vm_remap(mach_task_self(), &dst, kKPPageSize, 0, flags,
                                      mach_task_self(), src, copy, &cur, &max,
                                      (vm_inherit_t)[inheritance[@"value"] intValue]);
                    if (lastKR != KERN_SUCCESS) {
                        remapFailures++;
                        break;
                    }
                    ((uint8_t *)dst)[0] = 0xDD;
                    writeObserved = writeObserved || ((uint8_t *)dst)[0] == 0xDD;
                    BOOL sourceChanged = ((uint8_t *)src)[0] != 0xCC;
                    if (!copy && sourceChanged) sharedObserved = YES;
                    if (copy && sourceChanged) {
                        caseViolations++;
                        copyViolations++;
                    }
                    ((uint8_t *)src)[0] = 0xCC;
                    completed++;
                    if (!overwrite) {
                        vm_deallocate(mach_task_self(), dst, kKPPageSize);
                        dst = 0;
                    }
                    if (sourceChanged) break;
                }
                if (overwrite && dst) vm_deallocate(mach_task_self(), dst, kKPPageSize);
                if (sharedObserved) sharedCases++;
                if (!writeObserved && lastKR == KERN_SUCCESS) writeMisses++;
                [cases addObject:@{
                    @"copy": @(copy), @"overwrite": @(overwrite),
                    @"inheritance": inheritance[@"name"], @"kr": @(lastKR),
                    @"iterations": @(completed), @"write_observed": @(writeObserved),
                    @"shared_observed": @(sharedObserved), @"copy_isolation_violations": @(caseViolations),
                }];
            }
        }
    }

    vm_deallocate(mach_task_self(), src, kKPPageSize);
    return @{
        @"shape": @"vm_map_remap: copy x inheritance x overwrite",
        @"cases": cases, @"remap_failures": @(remapFailures),
        @"copy_isolation_violations": @(copyViolations),
        @"shared_cases_observed": @(sharedCases), @"write_misses": @(writeMisses),
    };
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-112576 · Kernel CoW ===\n"];
    [report appendString:@"Apple 149230: 'unexpected changes to copy-on-write memory',\n"];
    [report appendString:@"fixed with improved handling of copy-on-write pages (fixed 27.2).\n"];
    [report appendString:@"Runs four original shapes plus vm_object_update and vm_map_remap matrices.\n"];
    [report appendString:@"Changed-family context: vm_owned_objects_disown, vm_object_update, vm_map_remap.\n"];
    [report appendFormat:@"Target: iOS %@\n", UIDevice.currentDevice.systemVersion];

    NSString *path = [self writeSourceFileWithPattern];
    if (!path) {
        [report appendString:@"VERDICT: NOT_RUN (source file failed)\n"];
        return report;
    }

    uint32_t iters = self.armed ? 256 : 8;
    if (!self.armed) {
        int fd = open(path.fileSystemRepresentation, O_RDWR);
        if (fd < 0) {
            [report appendFormat:@"VERDICT: NOT_RUN (open failed errno=%d)\n", errno];
            return report;
        }
        void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (src == MAP_FAILED) {
            close(fd);
            [report appendFormat:@"VERDICT: NOT_RUN (mmap failed errno=%d)\n", errno];
            return report;
        }
        memset(src, 0x99, 128);
        munmap(src, kKPPageSize);
        close(fd);
        BOOL unchanged = [self fileStillOriginalAtPath:path];
        [report appendFormat:@"baseline-private-copy file_unchanged=%d\n", unchanged];
        [report appendFormat:@"\nVERDICT: %@\n", unchanged ? @"SURVIVED (control)" : @"CONTROL_FAILED"];
        return report;
    }

    [report appendFormat:@"%@\n", [self runShapeMachVMCopyAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeVMCopyAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeThreadedAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeForkAtPath:path iterations:iters]];

    NSDictionary *update = [self fileStillOriginalAtPath:path]
        ? [self runVMObjectUpdateDiagnosticsAtPath:path iterations:iters]
        : @{@"status": @"SKIPPED_FILE_ALREADY_CHANGED"};
    NSDictionary *remap = [self runRemapInheritanceDiagnosticsIterations:32];
    [report appendFormat:@"%@\n", update];
    [report appendFormat:@"%@\n", remap];

    uint32_t integrityViolations = [update[@"peer_changes"] unsignedIntValue] +
                                   [update[@"file_changes"] unsignedIntValue] +
                                   [remap[@"copy_isolation_violations"] unsignedIntValue];
    BOOL fileOriginal = [self fileStillOriginalAtPath:path];
    [report appendString:@"\nVERDICT: "];
    if (!fileOriginal || integrityViolations > 0) {
        [report appendFormat:@"INTEGRITY_VIOLATION_CANDIDATE (signals=%u, file_original=%d)\n",
         integrityViolations, fileOriginal];
    } else {
        [report appendString:@"NOT_REPRODUCED_IN_TESTED_SHAPES\n"];
    }
    [report appendString:
     @"Interpretation: results are bounded to the reported iterations and syscall return codes.\n"
     @"A rejected behavior/msync/remap operation is an unavailable lane, not a negative proof.\n"
     @"For remap(copy=FALSE), shared_observed is an expected propagation control, not a bug.\n"
     @"Only copy=TRUE source changes, private-peer changes, or independent pread file changes\n"
     @"count as integrity signals. vm_owned_objects_disown has no direct oracle in this module.\n"];
    return report;
}

@end
