#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// Read-only KASLR candidate scan over selected user-space RW regions.
/// Stack, malloc regions and known diagnostic constants are excluded.
/// Address-shaped values and alignment-derived slides remain unverified until
/// corroborated by an independent kernel-backed oracle.
@interface KPKASLRBypassModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
