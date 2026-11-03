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

    // Cleanup
    for (int i = 0; i < MARKER_COUNT; i++) {
        free(markers[i]);
    }

    [report appendString:@"\nVERDICT: RECON_COMPLETE\n"];
    return report;
}

@end
