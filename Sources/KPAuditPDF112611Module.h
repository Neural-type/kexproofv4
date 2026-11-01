#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112611 — CoreGraphics, "maliciously crafted PDF" OOB write
/// (Apple 149230, fixed in 27.2). Audit vector: function-based shading
/// (PDF ShadingType 5) whose /Function array carries R FunctionType-2
/// entries; CG tessellation copies the C0/C1 doubles past a 5-slot buffer
/// => 8*(R-5) bytes of controlled IEEE-754 doubles (1.0, 2.0, ...).
@interface KPAuditPDF112611Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
