#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112705 weaponization probe — SPRAY influence on the OOB read.
/// Model (from fix-diff RE): user-controlled counts (NTL family) index arrays
/// inside the AppleAVE2 session struct (pInfo->VideoParamsDriver) with NO
/// bounds check on 27.0.1; the OOB read feeds a pointer-shaped value into a
/// list-init self-write at +0x58. Oracle: the panic's far/x0 register READS
/// OUT what the OOB read consumed.
///   no spray:  far = 0x59 (baseline, already recorded)
///   with spray: far = our marker => the neighbour memory is OURS => the
///               pointer is ours => silent kernel write becomes buildable.
/// Order matters: allocate the VICTIM session first, then spray siblings,
/// so the spray lands AFTER the victim in the zone (the OOB reads forward).
@interface KPAuditAVESpriteModule : NSObject <KPTestModule>
- (instancetype)initWithSprayCount:(int)count marker:(uint32_t)marker;
@end

NS_ASSUME_NONNULL_END
