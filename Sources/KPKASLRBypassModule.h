#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// KRW lane #4 — KASLR bypass via user-space RW region scan.
/// Technique ref: asuka4scape — kernel leaves pointers in user-accessible
/// memory. Scan all RW VM regions for kernel pointer range values,
/// subtract known static segment bases, pick most frequent slide.
///
/// Also scans for: task/proc pointers, known structure offsets.
@interface KPKASLRBypassModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
