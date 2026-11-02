#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// KRW lane #5 — SPTM race + kernel read (asuka4scape technique).
/// Two threads race mach_vm_protect (READ vs READ|WRITE) on a page.
/// During the race window, mach_vm_write can write to READ-only pages.
/// Kernel read via sysctlbyname copyout during race window.
@interface KPSPTMRaceModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
