#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// KRW lane #3 — input→output mapped kread64 probe.
/// Technique ref: kirby_swift (@kirby_swiftios) — region mapped twice,
/// modifying input changes output => shared physical page => kread64.
///
/// This probe creates aliased mappings via vm_remap and checks for:
///   1. Shared-page confirmation (write input, read output)
///   2. Kernel pointers in the mapped region (0xfffffff... pattern)
///   3. Diff-test: modify a candidate pointer, observe output change
///
/// If kernel pointers appear in user-mapped pages, kread64 is live.
@interface KPKReadProbeModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
