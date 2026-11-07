#import "KPKReadProbeModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <mach/mach.h>

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
        _title = @"Userspace alias + filtered candidate probe";
        _subtitle = @"Benign vm_remap alias self-test; no kread/kwrite claim";
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
    return KPIsKernelPointerCandidate(v);
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · userspace alias + candidate probe ===\n"];
    [report appendString:@"Technique: benign vm_remap alias self-test and filtered read-only scan.\n"];
    [report appendString:@"Aliasing userspace pages alone does not provide a kernel read/write primitive.\n"];
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

    // --- Phase 3: fresh-alias stability control ---
    [report appendString:@"\n--- Phase 3: fresh-alias stability control ---\n"];
    for (size_t i = 0; i < regionSize / 8; i++) {
        in64[i] = 0xDEADBEEFDEADBEEFULL;
    }

    int unexpected = 0;
    int freshCandidateCount = 0;
    for (size_t i = 0; i < regionSize / 8; i++) {
        uint64_t v = out64[i];
        if (v != 0xDEADBEEFDEADBEEFULL) {
            unexpected++;
            if (isKernelPointer(v) && !KPIsKnownDiagnosticConstant(v)) {
                freshCandidateCount++;
                if (freshCandidateCount <= 16) {
                    [report appendFormat:@"candidate @ +0x%zx: 0x%llx\n", i * 8, v];
                }
            }
        }
    }

    [report appendFormat:@"unexpected values: %d (address-shaped candidates: %d)\n",
     unexpected, freshCandidateCount];
    [report appendString:@"No candidate is modified: userspace alias propagation is not a kernel read/write oracle.\n"];

    // --- Phase 4: filtered, read-only RW region candidate scan ---
    [report appendString:@"\n--- Phase 4: filtered read-only candidate scan ---\n"];

    vm_address_t scanAddr = 0;
    vm_size_t scanSize = 0;
    uint32_t scanDepth = 0;
    vm_region_submap_info_data_64_t scanInfo;
    mach_msg_type_number_t scanCount;
    vm_address_t excludedAddresses[] = {inputAddr, outputAddr};
    vm_size_t excludedSizes[] = {regionSize, regionSize};
    int regionWithCandidates = 0;
    int scannedRegions = 0;
    int skippedRegions = 0;
    int filteredConstants = 0;
    int totalCandidates = 0;

    while (regionWithCandidates < 8) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &scanDepth,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS || scanSize == 0) break;
        if (scanInfo.is_submap) { scanDepth++; continue; }
        if ((scanInfo.protection & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;
        if (KPVMShouldSkipRegion(&scanInfo, scanAddr, scanSize, &scanDepth,
                                 excludedAddresses, excludedSizes, 2)) {
            skippedRegions++;
            continue;
        }
        scannedRegions++;

        volatile uint64_t *p = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;
        int candidates = 0;
        uint64_t firstCandidate = 0;
        size_t firstOffset = 0;

        for (size_t i = 0; i < words; i++) {
            uint64_t v = p[i];
            if (!isKernelPointer(v)) continue;
            if (KPIsKnownDiagnosticConstant(v)) {
                filteredConstants++;
                continue;
            }
            candidates++;
            if (candidates == 1) { firstCandidate = v; firstOffset = i * 8; }
        }

        if (candidates > 0) {
            regionWithCandidates++;
            totalCandidates += candidates;
            [report appendFormat:@"region 0x%lx (size=0x%zx): %d candidates, first=0x%llx @ +0x%zx\n",
             (unsigned long)scanAddr, scanSize, candidates, firstCandidate, firstOffset];
        }
    }

    [report appendFormat:@"scanned regions: %d; skipped local regions: %d\n", scannedRegions, skippedRegions];
    [report appendFormat:@"regions with candidates: %d; values: %d; known constants filtered: %d\n",
     regionWithCandidates, totalCandidates, filteredConstants];
    [report appendString:@"The scan performs no writes outside the freshly allocated alias buffers.\n"];

    // --- Verdict ---
    [report appendString:@"\n"];
    if (freshCandidateCount > 0) {
        [report appendString:@"VERDICT: FRESH_ALIAS_CHANGED_UNVERIFIED\n"];
        [report appendString:@"Unexpected alias values require an independent producer before attribution to the kernel.\n"];
    } else if (regionWithCandidates > 0) {
        [report appendString:@"VERDICT: ALIAS_CONFIRMED_ADDRESS_CANDIDATES_UNVERIFIED\n"];
        [report appendString:@"Userspace aliasing is confirmed; candidate values do not establish kread64 or kwrite64.\n"];
    } else if (shared) {
        [report appendString:@"VERDICT: ALIAS_CONFIRMED_NO_ADDRESS_CANDIDATES\n"];
        [report appendString:@"Userspace aliasing works; no filtered address-shaped candidates were observed.\n"];
    } else {
        [report appendString:@"VERDICT: NO_MAPPING\n"];
    }

    // Cleanup
    vm_deallocate(mach_task_self(), inputAddr, regionSize);
    vm_deallocate(mach_task_self(), outputAddr, regionSize);

    return report;
}

@end
