#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-86950 — CoreGraphics anti-aliased path rasterizer OOB write.
/// Public facts (Apple 149226): OOB write, fixed in iOS 26.7.1, exploited on
/// versions "before iOS 27". Mechanism (Calif Glyph Grift): inlined
/// aa_double_to_fixed — moveto saturates (FCVTZS Wd), lineto truncates
/// (FCVTZS Vd.2D + XTN) => signed wrap in add_edges => undersized coverage.
/// Trigger surface: CGPath filled in a bitmap context with coordinates that
/// straddle the int32 fixed-point boundary (0.5 + 4096*c).
/// Also audits the GlyphNormalization feature flag (polygon vs edgepool backend).
@interface KPAuditGlyph86950Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
