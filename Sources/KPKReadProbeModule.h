#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// Benign vm_remap alias self-test plus a read-only candidate scan.
/// Input/output propagation proves aliasing of userspace pages only; it is not
/// a kread64 primitive. Stack, malloc regions, the alias buffers and known
/// diagnostic constants are excluded from the candidate scan.
@interface KPKReadProbeModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
