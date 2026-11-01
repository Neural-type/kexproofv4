#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112621 — LinkPresentation LPAnimatedImageTranscoder OOB write.
/// Public mechanics (Xplo8E / Appknox, Apple advisory 149230):
///   multi-frame HEIC, frame 0 = 256x16, later frame = 256x48 (same width),
///   pixel pool sized from frame 0, later frame drawn taller => CGContextClearRect
///   writes past the pool (bzero fault on transcoder queue).
/// Reachability: LPMetadataProvider (public LinkPresentation API) with a
/// multi-frame HEIC; `_isAnimated` accepts image/heic and image/gif.
/// Fixed in iOS 27.2 => expected LIVE on 27.0.1.
@interface KPAuditLP112621Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
