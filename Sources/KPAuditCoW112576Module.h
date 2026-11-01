#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112576 — Kernel, "unexpected changes to copy-on-write memory"
/// (Apple 149230, fixed 27.2, reported by Pedro Pinho). Audit strategy:
/// run SEVERAL CoW overwrite shapes instead of one hypothesis — file-backed
/// private mappings raced with madvise variants, mach_vm_copy, and classic
/// two-thread dirty-CoW loops — then verify the source file via pread.
@interface KPAuditCoW112576Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
