#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// Sandbox escape via CVE-2026-112692: INFile security scope bypass.
/// Intents.framework INFile deserialization doesn't validate security scope
/// against fileURL. Crafted INFile -> privileged consumer -> file read.
/// iOS 26.5-27.0.1 (patched in 27.2).
@interface KPINFileLeakModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
