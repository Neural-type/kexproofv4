#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-84495 — Kernel use-after-free, "unexpected system termination or
/// write kernel memory" (Apple 149230, fixed 27.2, reported by Wang Yu).
/// IMPORTANT: the advisory names NO surface. The prior "BPF detach race"
/// attribution in local reports is UNVERIFIED. This module (1) records that
/// gap honestly, (2) enumerates every /dev/bpf node and access mode and
/// names the exact gate that denies (node perms vs sandbox vs entitlement),
/// so an EPERM from one open() can never again close the whole line.
@interface KPAuditUAF84495Module : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
