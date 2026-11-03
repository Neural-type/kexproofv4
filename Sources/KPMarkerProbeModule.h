#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// Controlled corruption step 1: create objects with markers, find them in memory.
/// Foundation for targeted corruption (like kirby's session markers).
@interface KPMarkerProbeModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
