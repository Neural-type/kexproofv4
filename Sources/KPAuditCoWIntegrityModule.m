#import "KPAuditCoWIntegrityModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <sys/mman.h>
#import <unistd.h>
#import <fcntl.h>

// vm_remap is a standard MIG routine; declared here so the build never depends
// on which SDK header happens to expose it (mach_vm.h is macOS-only).
extern kern_return_t vm_remap(vm_map_t target_task, vm_address_t *target_address,
                              vm_size_t size, vm_address_t mask, int flags,
                              vm_map_t src_task, vm_address_t src_address,
                              boolean_t copy, vm_prot_t *cur_protection,
                              vm_prot_t *max_protection, vm_inherit_t inheritance);
// Memory-entry lane (CVE family: CoW over a shared named object).
extern kern_return_t mach_make_memory_entry(vm_map_t target_task, vm_size_t *size,
                                            vm_offset_t offset, vm_prot_t permission,
                                            mach_port_t *object_handle,
                                            mach_port_t parent_entry);
// vm_map: the SDK's declaration already exists (prot parameters are values in
// this SDK); no re-declaration here.

static const size_t kKPCoWPage = 0x4000; // 16 KB — the lsl #14 page stride in the fix

@interface KPAuditCoWIntegrityModule ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditCoWIntegrityModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"cow112576.integrity.armed" : @"cow112576.integrity.control";
        _title = armed ? @"CoW integrity (armed)" : @"CoW integrity (control)";
        _subtitle = armed
            ? @"CVE-2026-112576: private-mapping isolation + remap-copy + pressure"
            : @"Oracle self-test: copy=FALSE must propagate, file-private must not";
        _icon = armed ? @"arrow.triangle.branch" : @"doc.on.doc";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Pressure helper (compressor lane)

static NSArray<NSValue *> *KPCoWDirtySlabs(void) {
    NSMutableArray *slabs = [NSMutableArray array];
    for (int i = 0; i < 16; i++) {
        uint8_t *slab = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON, -1, 0);
        if (slab == MAP_FAILED) break;
        memset(slab, (uint8_t)(0x10 + i), 8 * 1024 * 1024);
        [slabs addObject:[NSValue valueWithPointer:slab]];
    }
    return slabs;
}

static void KPCoWFreeSlabs(NSArray<NSValue *> *slabs) {
    for (NSValue *v in slabs) {
        munmap((void *)v.pointerValue, 8 * 1024 * 1024);
    }
}

#pragma mark - O1: two MAP_PRIVATE mappings of one file

- (NSDictionary *)privateFileIsolationIterations:(uint32_t)iters pressure:(BOOL)pressure {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-cow-int.bin"];
    NSMutableData *seed = [NSMutableData dataWithLength:kKPCoWPage];
    memset(seed.mutableBytes, 0xAA, kKPCoWPage);
    if (![seed writeToFile:path atomically:YES]) {
        result[@"status"] = @"SEED_WRITE_FAILED";
        return result;
    }
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) {
        result[@"status"] = @"OPEN_FAILED";
        result[@"errno"] = @(errno);
        return result;
    }

    uint8_t *mapA = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    uint8_t *mapB = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mapA == MAP_FAILED || mapB == MAP_FAILED) {
        result[@"status"] = @"MMAP_FAILED";
        close(fd);
        return result;
    }

    NSArray *slabs = pressure ? KPCoWDirtySlabs() : @[];
    uint32_t leaks = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        memset(mapA, 0x41, 16);          // CoW write through A
        if (mapB[0] != 0xAA || mapB[15] != 0xAA) {
            leaks++;
            firstLeak = i;
            break;
        }
        memset(mapA, 0xAA, 16);          // restore for the next round
    }
    KPCoWFreeSlabs(slabs);
    munmap(mapA, kKPCoWPage);
    munmap(mapB, kKPCoWPage);
    close(fd);

    result[@"oracle"] = @"O1 file MAP_PRIVATE x2: write A, B must stay 0xAA";
    result[@"iterations"] = @(iters);
    result[@"pressure_slabs"] = @(slabs.count);
    result[@"leaks"] = @(leaks);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - O2/O3: vm_remap copy flag

- (NSDictionary *)remapIsolationCopy:(BOOL)copy iterations:(uint32_t)iters pressure:(BOOL)pressure {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    vm_address_t src = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &src, kKPCoWPage, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        result[@"status"] = @"VM_ALLOCATE_FAILED";
        result[@"kr"] = @(kr);
        return result;
    }
    memset((void *)src, 0xCC, kKPCoWPage);

    NSArray *slabs = pressure ? KPCoWDirtySlabs() : @[];
    uint32_t leaks = 0, failures = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        vm_address_t dst = 0;
        vm_size_t size = kKPCoWPage;
        vm_prot_t cur = 0, max = 0;
        kr = vm_remap(mach_task_self(), &dst, size, 0,
                      VM_FLAGS_ANYWHERE,
                      mach_task_self(), src, copy, &cur, &max, VM_INHERIT_COPY);
        if (kr != KERN_SUCCESS) {
            failures++;
            continue;
        }
        memset((void *)dst, 0xDD, kKPCoWPage);
        BOOL changed = (((uint8_t *)src)[0] != 0xCC);
        vm_deallocate(mach_task_self(), dst, size);
        if (changed) {
            leaks++;
            firstLeak = i;
            if (!copy) break;               // O3 sanity: expected to fire on 1
            else break;                      // O2: any leak is the CVE
        }
        memset((void *)src, 0xCC, kKPCoWPage);
    }
    KPCoWFreeSlabs(slabs);
    vm_deallocate(mach_task_self(), src, kKPCoWPage);

    result[@"oracle"] = copy
        ? @"O2 vm_remap(copy=TRUE): write copy, original must stay 0xCC"
        : @"O3 SANITY vm_remap(copy=FALSE): MUST propagate (oracle self-test)";
    result[@"copy"] = @(copy);
    result[@"iterations"] = @(iters);
    result[@"leaks"] = @(leaks);
    result[@"remap_failures"] = @(failures);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - O5: madvise race on private copies (no fork — sandbox blocks it)

- (NSDictionary *)madviseRaceIterations:(uint32_t)iters {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-cow-race.bin"];
    NSMutableData *seed = [NSMutableData dataWithLength:kKPCoWPage];
    memset(seed.mutableBytes, 0xEE, kKPCoWPage);
    if (![seed writeToFile:path atomically:YES]) {
        result[@"status"] = @"SEED_WRITE_FAILED";
        return result;
    }
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) {
        result[@"status"] = @"OPEN_FAILED";
        return result;
    }
    uint8_t *mapA = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    uint8_t *mapB = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mapA == MAP_FAILED || mapB == MAP_FAILED) {
        result[@"status"] = @"MMAP_FAILED";
        close(fd);
        return result;
    }

    uint32_t leaks = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        // contend on A's private-copy path: madvise + write in the same thread
        for (int j = 0; j < 32; j++) {
            madvise(mapA, kKPCoWPage, MADV_FREE);
            mapA[0] = 0x41;
        }
        if (mapB[0] != 0xEE) {
            leaks++;
            firstLeak = i;
            break;
        }
        mapA[0] = 0xEE;
    }
    munmap(mapA, kKPCoWPage);
    munmap(mapB, kKPCoWPage);
    close(fd);

    result[@"oracle"] = @"O5 file MAP_PRIVATE x2 + madvise(MADV_FREE)/write on A";
    result[@"iterations"] = @(iters);
    result[@"leaks"] = @(leaks);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - O6: CoW over a shared memory entry (the named-object lane)

// mach_make_memory_entry names a range of this task's memory; vm_map(copy=TRUE)
// over that entry twice gives two CoW peers over ONE shared object — the
// canonical shape for "unexpected changes to copy-on-write memory".
- (NSDictionary *)memoryEntryCoWIterations:(uint32_t)iters pressure:(BOOL)pressure {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    vm_address_t backing = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &backing, kKPCoWPage, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        result[@"status"] = @"VM_ALLOCATE_FAILED";
        result[@"kr"] = @(kr);
        return result;
    }
    memset((void *)backing, 0x11, kKPCoWPage);

    vm_size_t entrySize = kKPCoWPage;
    mach_port_t entry = MACH_PORT_NULL;
    kr = mach_make_memory_entry(mach_task_self(), &entrySize, (vm_offset_t)backing,
                                VM_PROT_READ | VM_PROT_WRITE, &entry, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS || entry == MACH_PORT_NULL) {
        result[@"status"] = @"MAKE_MEMORY_ENTRY_FAILED";
        result[@"kr"] = @(kr);
        vm_deallocate(mach_task_self(), backing, kKPCoWPage);
        return result;
    }
    result[@"entry_size"] = @(entrySize);

    NSArray *slabs = pressure ? KPCoWDirtySlabs() : @[];
    uint32_t leaks = 0, mapFailures = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        vm_address_t dst1 = 0, dst2 = 0;
        kr = vm_map(mach_task_self(), &dst1, entrySize, 0, VM_FLAGS_ANYWHERE,
                    entry, 0, TRUE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_COPY);
        if (kr != KERN_SUCCESS) { mapFailures++; continue; }
        kr = vm_map(mach_task_self(), &dst2, entrySize, 0, VM_FLAGS_ANYWHERE,
                    entry, 0, TRUE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_COPY);
        if (kr != KERN_SUCCESS) {
            vm_deallocate(mach_task_self(), dst1, entrySize);
            mapFailures++;
            continue;
        }

        memset((void *)dst1, 0x22, 16); // write the first CoW peer
        BOOL peerSees = (((uint8_t *)dst2)[0] != 0x11);
        BOOL srcSees = (((uint8_t *)backing)[0] != 0x11);
        vm_deallocate(mach_task_self(), dst1, entrySize);
        vm_deallocate(mach_task_self(), dst2, entrySize);
        memset((void *)backing, 0x11, 16);

        if (peerSees || srcSees) {
            leaks++;
            firstLeak = i;
            if (peerSees) result[@"peer_saw_write"] = @YES;
            if (srcSees) result[@"source_saw_write"] = @YES;
            break;
        }
    }
    KPCoWFreeSlabs(slabs);
    mach_port_deallocate(mach_task_self(), entry);
    vm_deallocate(mach_task_self(), backing, kKPCoWPage);

    result[@"oracle"] = @"O6 memory-entry x2 vm_map(copy=TRUE): write peer1; peer2 & source must stay 0x11";
    result[@"iterations"] = @(iters);
    result[@"pressure_slabs"] = @(slabs.count);
    result[@"leaks"] = @(leaks);
    result[@"map_failures"] = @(mapFailures);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - O7: overwrite-remap (the vm_map_remap fix lane)

// vm_remap(FIXED|OVERWRITE, copy=TRUE) lays a CoW copy over an existing
// mapping — the exact family the 27.2 fix touched in vm_map_remap (+216B).
- (NSDictionary *)overwriteRemapIterations:(uint32_t)iters {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    vm_address_t src = 0, dst = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &src, kKPCoWPage, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        result[@"status"] = @"SRC_ALLOC_FAILED";
        return result;
    }
    kr = vm_allocate(mach_task_self(), &dst, kKPCoWPage, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), src, kKPCoWPage);
        result[@"status"] = @"DST_ALLOC_FAILED";
        return result;
    }
    memset((void *)src, 0x33, kKPCoWPage);
    memset((void *)dst, 0x44, kKPCoWPage);

    uint32_t leaks = 0, failures = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        vm_prot_t cur = 0, max = 0;
        // overwrite dst with a CoW copy of src
        kr = vm_remap(mach_task_self(), &dst, kKPCoWPage, 0,
                      VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                      mach_task_self(), src, TRUE, &cur, &max, VM_INHERIT_COPY);
        if (kr != KERN_SUCCESS) {
            failures++;
            // re-arm dst for the next round
            vm_allocate(mach_task_self(), &dst, kKPCoWPage, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
            memset((void *)dst, 0x44, kKPCoWPage);
            continue;
        }
        memset((void *)dst, 0x55, kKPCoWPage); // write the overlaid copy
        BOOL changed = (((uint8_t *)src)[0] != 0x33);
        if (changed) {
            leaks++;
            firstLeak = i;
            break;
        }
        memset((void *)src, 0x33, 16);
    }
    vm_deallocate(mach_task_self(), src, kKPCoWPage);
    vm_deallocate(mach_task_self(), dst, kKPCoWPage);

    result[@"oracle"] = @"O7 vm_remap(FIXED|OVERWRITE, copy=TRUE): write overlay, source must stay 0x33";
    result[@"iterations"] = @(iters);
    result[@"leaks"] = @(leaks);
    result[@"remap_failures"] = @(failures);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - O8: CoW over a SHARED file object (cache-family shape)

- (NSDictionary *)sharedFileCoWIterations:(uint32_t)iters pressure:(BOOL)pressure {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-cow-shared.bin"];
    NSMutableData *seed = [NSMutableData dataWithLength:kKPCoWPage];
    memset(seed.mutableBytes, 0x66, kKPCoWPage);
    if (![seed writeToFile:path atomically:YES]) {
        result[@"status"] = @"SEED_WRITE_FAILED";
        return result;
    }
    int fd = open(path.fileSystemRepresentation, O_RDWR);
    if (fd < 0) {
        result[@"status"] = @"OPEN_FAILED";
        return result;
    }
    // one shared mapping (the "cache"), one private copy over it
    uint8_t *shared = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint8_t *cow = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (shared == MAP_FAILED || cow == MAP_FAILED) {
        result[@"status"] = @"MMAP_FAILED";
        close(fd);
        return result;
    }

    NSArray *slabs = pressure ? KPCoWDirtySlabs() : @[];
    uint32_t leaks = 0, firstLeak = 0;
    for (uint32_t i = 1; i <= iters; i++) {
        memset(cow, 0x77, 16); // CoW write
        if (shared[0] != 0x66) {
            leaks++;
            firstLeak = i;
            break;
        }
    }
    KPCoWFreeSlabs(slabs);
    munmap(shared, kKPCoWPage);
    munmap(cow, kKPCoWPage);
    close(fd);

    result[@"oracle"] = @"O8 MAP_SHARED cache + MAP_PRIVATE cow: write cow, shared must stay 0x66";
    result[@"iterations"] = @(iters);
    result[@"pressure_slabs"] = @(slabs.count);
    result[@"leaks"] = @(leaks);
    if (leaks) result[@"first_leak_iteration"] = @(firstLeak);
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112576 · CoW integrity ===\n"];
    [report appendString:@"Apple: 'unexpected changes to copy-on-write memory' (fixed 26.7.2/27.2).\n"];
    [report appendString:@"Fix family: vm_fault_page, vm_object_update, vm_pageout_compress_page x2,\n"];
    [report appendString:@"vm_map_remap, vm_owned_objects_disown. Our 27.0.1 is LIVE.\n"];
    [report appendString:@"Contract: writes through one CoW mapping must never appear in its peer.\n"];
    [report appendString:@"fork() is not available to sandboxed apps — all oracles are fork-free.\n"];
    [report appendString:@"v3 lanes: O6 shared memory-entry (named object), O7 overwrite-remap,\n"];
    [report appendString:@"O8 CoW over a MAP_SHARED cache — the shapes the fix family points to.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    uint32_t iters = self.armed ? 256 : 8;
    [report appendFormat:@"\n%@", [self remapIsolationCopy:NO iterations:8 pressure:NO]];
    [report appendFormat:@"\n%@", [self privateFileIsolationIterations:iters pressure:NO]];
    if (self.armed) {
        [report appendFormat:@"\n%@", [self remapIsolationCopy:YES iterations:128 pressure:NO]];
        [report appendFormat:@"\n%@", [self privateFileIsolationIterations:64 pressure:YES]];
        [report appendFormat:@"\n%@", [self remapIsolationCopy:YES iterations:64 pressure:YES]];
        [report appendFormat:@"\n%@", [self madviseRaceIterations:128]];
        [report appendFormat:@"\n%@", [self memoryEntryCoWIterations:128 pressure:NO]];
        [report appendFormat:@"\n%@", [self memoryEntryCoWIterations:64 pressure:YES]];
        [report appendFormat:@"\n%@", [self overwriteRemapIterations:128]];
        [report appendFormat:@"\n%@", [self sharedFileCoWIterations:128 pressure:NO]];
        [report appendFormat:@"\n%@", [self sharedFileCoWIterations:64 pressure:YES]];
    }

    [report appendString:@"\n\nVERDICT: "];
    [report appendString:self.armed ? @"SEE_LEAKS_FIELDS\n" : @"SURVIVED (control)\n"];
    [report appendString:
     @"Reading the table:\n"
     @"  O3 sanity MUST show leaks>=1 (it proves the oracle observes propagation;\n"
     @"  leaks=0 there means the instrument is blind — distrust everything else).\n"
     @"  O1/O2/O5/O6/O7/O8 leaks>0 = confirmed CoW integrity break (CVE-2026-112576).\n"
     @"  O6 note: map_failures>0 means the named-entry lane was unavailable in\n"
     @"  this sandbox — report it rather than reading silence as safety.\n"
     @"  leaks=0 everywhere does NOT close the CVE: the fix also touches the\n"
     @"  compressor restore and fault paths and may need cross-process peers.\n"];
    return report;
}

@end
