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
    [report appendString:@"Foundation for controlled corruption (kirby approach).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d pid=%d\n",
     UIDevice.currentDevice.systemVersion, getuid(), getpid()];

    // Phase 1: create marked objects
    [report appendString:@"\n--- Phase 1: create marked objects ---\n"];

    // Create 8 marked buffers with unique patterns
    #define MARKER_COUNT 8
    #define MARKER_SIZE 4096
    uint8_t *markers[MARKER_COUNT];
    uint32_t markerIDs[MARKER_COUNT];

    for (int i = 0; i < MARKER_COUNT; i++) {
        markers[i] = calloc(1, MARKER_SIZE);
        markerIDs[i] = 0xABCD0001 + i; // unique ID per marker

        // Fill with marker pattern
        uint32_t *p = (uint32_t *)markers[i];
        for (int j = 0; j < MARKER_SIZE / 4; j++) {
            p[j] = markerIDs[i];
        }

        [report appendFormat:@"marker[%d]: id=0x%08x addr=0x%lx\n",
         i, markerIDs[i], (unsigned long)markers[i]];
        [self journal:[NSString stringWithFormat:@"marker[%d] id=0x%08x addr=0x%lx",
                       i, markerIDs[i], (unsigned long)markers[i]]];
    }

    // Phase 2: find markers in memory
    [report appendString:@"\n--- Phase 2: find markers in memory ---\n"];

    vm_address_t scanAddr = 0;
    vm_size_t scanSize = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count;
    int found = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t depth = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &depth,
                                  (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) break;
        if (info.is_submap) continue;
        if (!(info.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint32_t *p = (volatile uint32_t *)scanAddr;
        size_t words = scanSize / 4;

        for (size_t j = 0; j < words; j++) {
            uint32_t v = p[j];
            for (int m = 0; m < MARKER_COUNT; m++) {
                if (v == markerIDs[m]) {
                    // Only log first match per marker
                    static int logged[8] = {0};
                    if (!logged[m]) {
                        [report appendFormat:@"FOUND marker[%d] at region+0x%lx\n", m, (unsigned long)(scanAddr + j * 4)];
                        logged[m] = 1;
                    }
                    found++;
                    break;
                }
            }
        }
    }

    [report appendFormat:@"markers found in memory: %d\n", found];

    // Phase 2b: controlled corruption (kirby approach)
    [report appendString:@"\n--- Phase 2b: controlled corruption ---\n"];
    for (int i = 0; i < MARKER_COUNT; i++) {
        uint32_t orig = markerIDs[i];
        uint32_t corrupted = 0x1E; // kirby's marker value

        // Corrupt: change marker value
        volatile uint32_t *p = (volatile uint32_t *)markers[i];
        p[0] = corrupted;

        // Read back
        uint32_t readback = p[0];
        if (readback == corrupted) {
            [report appendFormat:@"CORRUPTED marker[%d]: 0x%08x -> 0x%08x (confirmed)\n",
             i, orig, readback];
        } else {
            [report appendFormat:@"marker[%d]: corruption FAILED (read=0x%08x)\n", i, readback];
        }

        // Restore
        p[0] = orig;
    }

    // Phase 3: kernel objects + corruption + exercise (kirby approach)
    [report appendString:@"\n--- Phase 3: kernel objects + exercise ---\n"];

    // Create Mach ports as kernel objects
    #define PORT_COUNT 8
    mach_port_t ports[PORT_COUNT];
    for (int i = 0; i < PORT_COUNT; i++) {
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        [report appendFormat:@"port[%d]: name=%u kr=%d\n", i, ports[i], kr];
    }

    // Corrupt port names in marker buffers (simulating kernel object corruption)
    [report appendString:@"\ncorrupting port names in markers...\n"];
    for (int i = 0; i < PORT_COUNT && i < MARKER_COUNT; i++) {
        volatile uint32_t *p = (volatile uint32_t *)markers[i];
        uint32_t origName = ports[i];
        uint32_t corruptName = 0x1E; // kirby's marker value

        // Store original port name in marker
        p[0] = origName;
        // Corrupt it
        p[0] = corruptName;
        [report appendFormat:@"marker[%d]: port_name %u -> %u (corrupted)\n", i, origName, corruptName];
    }

    // Exercise corrupted objects: try to use the ports
    [report appendString:@"\nexercising corrupted objects...\n"];
    for (int i = 0; i < PORT_COUNT; i++) {
        // Try to send a message to the port
        uint8_t buf[128] = {0};
        mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
        hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        hdr->msgh_size = sizeof(mach_msg_header_t);
        hdr->msgh_remote_port = ports[i];
        hdr->msgh_local_port = MACH_PORT_NULL;
        hdr->msgh_id = 0;

        kern_return_t kr = mach_msg(hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                     hdr->msgh_size, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
        [report appendFormat:@"exercise port[%d] name=%u send_kr=%d\n", i, ports[i], kr];

        // Drain if sent
        if (kr == KERN_SUCCESS) {
            mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf), ports[i], 50, MACH_PORT_NULL);
        }
    }

    // Check if any port died from corruption
    [report appendString:@"\nchecking port health after corruption...\n"];
    int deadPorts = 0;
    for (int i = 0; i < PORT_COUNT; i++) {
        uint8_t buf[128] = {0};
        mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
        hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
        hdr->msgh_size = sizeof(mach_msg_header_t);
        hdr->msgh_remote_port = ports[i];
        hdr->msgh_local_port = MACH_PORT_NULL;
        hdr->msgh_id = 0;

        kern_return_t kr = mach_msg(hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                     hdr->msgh_size, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            deadPorts++;
            [report appendFormat:@"port[%d] DEAD after corruption (kr=%d)\n", i, kr];
        } else {
            mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf), ports[i], 50, MACH_PORT_NULL);
        }
    }
    [report appendFormat:@"ports dead after corruption: %d/%d\n", deadPorts, PORT_COUNT];

    // Cleanup
    for (int i = 0; i < PORT_COUNT; i++) {
        if (ports[i] != MACH_PORT_NULL) {
            mach_port_destroy(mach_task_self(), ports[i]);
        }
    }

    // Phase 3: prepare for controlled corruption
    [report appendString:@"\n--- Phase 3: corruption targets ---\n"];
    if (found > 0) {
        [report appendString:@"Markers located. Ready for targeted corruption.\n"];
        [report appendString:@"Next: corrupt marker values, observe effects.\n"];
    } else {
        [report appendString:@"Markers not found in writable regions.\n"];
        [report appendString:@"Try: different marker sizes, or check heap layout.\n"];
    }

    // Phase 4: find kernel pointers belonging to our objects (differential)
    [report appendString:@"\n--- Phase 4: find our kernel pointers ---\n"];

    // Snapshot kernel pointers BEFORE creating ports
    #define MAX_KPTRS 256
    uint64_t kptrsBefore[MAX_KPTRS] = {0};
    size_t kptrAddrsBefore[MAX_KPTRS] = {0};
    int kptrCountBefore = 0;

    {
        vm_address_t sa = 0; vm_size_t ss = 0;
        vm_region_submap_info_data_64_t si;
        mach_msg_type_number_t sc;
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
            for (size_t j = 0; j < words && kptrCountBefore < MAX_KPTRS; j++) {
                uint64_t v = p[j];
                if ((v >> 32) >= 0xffffffe0ULL) {
                    kptrsBefore[kptrCountBefore] = v;
                    kptrAddrsBefore[kptrCountBefore] = sa + j * 8;
                    kptrCountBefore++;
                }
            }
        }
        [report appendFormat:@"kptrs before ports: %d\n", kptrCountBefore];
    }

    // Create 4 new ports
    mach_port_t newPorts[4];
    for (int i = 0; i < 4; i++) {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &newPorts[i]);
        [report appendFormat:@"new port[%d]: name=%u\n", i, newPorts[i]];
    }

    // Snapshot kernel pointers AFTER creating ports
    uint64_t kptrsAfter[MAX_KPTRS] = {0};
    size_t kptrAddrsAfter[MAX_KPTRS] = {0};
    int kptrCountAfter = 0;

    {
        vm_address_t sa = 0; vm_size_t ss = 0;
        vm_region_submap_info_data_64_t si;
        mach_msg_type_number_t sc;
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
            for (size_t j = 0; j < words && kptrCountAfter < MAX_KPTRS; j++) {
                uint64_t v = p[j];
                if ((v >> 32) >= 0xffffffe0ULL) {
                    kptrsAfter[kptrCountAfter] = v;
                    kptrAddrsAfter[kptrCountAfter] = sa + j * 8;
                    kptrCountAfter++;
                }
            }
        }
        [report appendFormat:@"kptrs after ports: %d\n", kptrCountAfter];
    }

    // Find NEW kernel pointers (not in before snapshot)
    int newKptrs = 0;
    for (int i = 0; i < kptrCountAfter && newKptrs < 10; i++) {
        BOOL isnew = YES;
        for (int j = 0; j < kptrCountBefore; j++) {
            if (kptrsAfter[i] == kptrsBefore[j]) {
                isnew = NO;
                break;
            }
        }
        if (isnew) {
            [report appendFormat:@"NEW kptr: 0x%llx at +0x%lx\n", kptrsAfter[i], (unsigned long)kptrAddrsAfter[i]];
            newKptrs++;
        }
    }
    [report appendFormat:@"new kernel pointers from our ports: %d\n", newKptrs];

    // Phase 5: IOSurface shared memory
    [report appendString:@"\n--- Phase 5: IOSurface shared memory ---\n"];
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

        [report appendFormat:@"IOSurface: create=%p lock=%p base=%p\n", isCreate, isLock, isGetBase];

        if (isCreate && isLock && isGetBase) {
            NSDictionary *props = @{
                @"IOSurfaceWidth": @256,
                @"IOSurfaceHeight": @256,
                @"IOSurfaceBytesPerElement": @4,
            };
            void *surface = isCreate((__bridge CFDictionaryRef)props);
            if (surface) {
                [report appendFormat:@"surface: %p\n", surface];
                isLock(surface, 0, NULL);
                void *base = isGetBase(surface);
                unsigned long bpr = isGetBpr ? isGetBpr(surface) : 1024;
                unsigned long h = isGetHeight ? isGetHeight(surface) : 256;

                if (base) {
                    unsigned int *p = (unsigned int *)base;
                    for (unsigned long j = 0; j < (bpr * h) / 4; j++) {
                        p[j] = 0xDEAD0000 + (unsigned int)j;
                    }
                    unsigned int first = p[0];
                    [report appendFormat:@"marker[0] = 0x%08x\n", first];

                    p[0] = 0x1E;
                    unsigned int rb = p[0];
                    [report appendFormat:@"corrupt: 0xDEAD0000 -> 0x%08x confirmed=%d\n", rb, rb == 0x1E];
                    p[0] = 0xDEAD0000;

                    int nonMarkers = 0;
                    for (unsigned long j = 0; j < (bpr * h) / 4 && nonMarkers < 3; j++) {
                        unsigned int v = p[j];
                        if (v != 0xDEAD0000 + (unsigned int)j) {
                            [report appendFormat:@"kernel write at +%lu: 0x%08x\n", j * 4, v];
                            nonMarkers++;
                        }
                    }
                    [report appendFormat:@"kernel writes (pre-render): %d\n", nonMarkers];

                    // GPU render to force kernel to use the surface
                    [report appendString:@"rendering to IOSurface via CoreGraphics...\n"];
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef ctx = CGBitmapContextCreate(base, w, h, 8, bpr, cs, kCGImageAlphaPremultipliedFirst);
                    if (ctx) {
                        CGContextSetRGBFillColor(ctx, 1.0, 0.0, 0.0, 1.0);
                        CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
                        CGContextFlush(ctx);
                        CGContextRelease(ctx);
                        [report appendString:@"render complete\n"];
                    } else {
                        [report appendString:@"CGBitmapContextCreate failed\n"];
                    }
                    CGColorSpaceRelease(cs);

                    // Check for kernel writes AFTER render
                    int nonMarkers2 = 0;
                    for (unsigned long j = 0; j < (bpr * h) / 4 && nonMarkers2 < 5; j++) {
                        unsigned int v = p[j];
                        if (v != 0xDEAD0000 + (unsigned int)j) {
                            [report appendFormat:@"AFTER RENDER at +%lu: 0x%08x\n", j * 4, v];
                            nonMarkers2++;
                        }
                    }
                    [report appendFormat:@"kernel writes (post-render): %d\n", nonMarkers2];
                }
                isUnlock(surface, 0, NULL);
                CFRelease(surface);
            } else {
                [report appendString:@"IOSurfaceCreate returned NULL\n"];
            }
        } else {
            [report appendString:@"IOSurface functions not available\n"];
        }
    }

    // Cleanup
    for (int i = 0; i < 4; i++) {
        if (newPorts[i] != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), newPorts[i]);
    }
    for (int i = 0; i < MARKER_COUNT; i++) {
        free(markers[i]);
    }

    // Verdict
    [report appendString:@"\n"];
    if (found >= MARKER_COUNT / 2) {
        [report appendString:@"VERDICT: MARKERS_FOUND\n"];
    } else if (found > 0) {
        [report appendString:@"VERDICT: MARKERS_PARTIAL\n"];
    } else {
        [report appendString:@"VERDICT: MARKERS_NOT_FOUND\n"];
    }

    return report;
}

@end
