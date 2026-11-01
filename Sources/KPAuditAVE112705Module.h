#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112705 — AppleAVE2 kernel OOB write via VideoToolbox
/// NumberOfTemporalLayers (public PoC: MchinaMd57764/AVETemporalPoC).
/// Exact trigger: vtCompressionSessionCreate succeeds, then the FIRST encode
/// with NumberOfTemporalLayers=16463 panics the kernel (16462 survives).
/// Panic fingerprint: Kernel data abort, AppleAVE2+0xDA78, far=0x59, x19=0x1,
/// crashing process videocodecd. Fixed in 27.2 (NTL returns -12900 there).
/// Our 27.0.1 is LIVE. NOTE: the first encode may panic the device — journal
/// is fsynced before every encode so the run survives the reboot.
@interface KPAuditAVE112705Module : NSObject <KPTestModule>
- (instancetype)initWithTemporalLayers:(int)ntl;
@end

NS_ASSUME_NONNULL_END
