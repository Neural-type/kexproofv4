#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112688 — CoreMedia "parsing a file" memory corruption (Apple 149230,
/// fixed 27.2). Audit vector: Dolby Vision RPU RBSP parsed by
/// CMGetDMVersionLevelFromRPU / FigHEVCBridge_GetRPUMetadata.
/// Generator: reference RBSP prefix + ue(num_ext_blocks) + per-block
/// ue(ext_block_length), u(8) blockID, payload; CRC-32/MPEG-2 over RBSP[1:]
/// + 0x80 terminator. Over-capacity block counts (A10 cap 4, B2 cap 8,
/// C6 cap 5) are the OOB candidates.
@interface KPAuditRPU112688Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
