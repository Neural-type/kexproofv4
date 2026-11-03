#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// KRW via H9 video encoder OOB write (CVE-2026-112705-adjacent).
/// AVE_HEVC_ST_RPS_Retrieve: unbounded copy in UserRPSForFaceTime.
/// Overwrites FPS* pointer in encoder session -> controlled write.
/// Used by Calif in iOS 27.0.1 jailbreak (Hexacon demo).
@interface KPH9EncoderModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
