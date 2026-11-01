#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112705 — final AVE question: is the kernel store PAN-transparent?
/// The crash write goes to ((NTL-16463)<<32)|0x59 — a USER-range address.
/// If the kernel store can land in a user page we map there, the page will
/// contain the self-pointer (x0) — read it back = kernel->user write proof.
/// If PAN blocks it, the kernel panics at the mapped address (far = our addr).
/// One experiment, two clean answers.
@interface KPAuditAVEPANModule : NSObject <KPTestModule>
- (instancetype)initWithTemporalLayers:(int)ntl;
@end

NS_ASSUME_NONNULL_END
