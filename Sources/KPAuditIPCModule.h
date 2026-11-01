#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// KRW lane #2 — ipc_port_translate_receive index OOB (LIVE on 27.0.1).
/// Fix-diff RE (27.0.1 -> 27.2, com.apple.kernel):
///   vuln:  add x8, base, w2, uxtw#4 ; ldr x9,[x8] ; tbz bit1 ; orr #1 ; str  <- NO bounds
///   fixed: ubfiz x8, w2, #4 ; cmp x8, capacity ; b.hi error ; then PAC-authed load
/// w2 is an attacker-influenced index into a 16-byte-stride table; the vuln
/// path reads table[w2] and SETS BIT 1 back — a conditional bit-set write at a
/// controlled offset. Oracle: a panic's far register reveals base+16*index
/// (index control + table base leak); survival at some values maps the kernel
/// mapping around the table.
/// This probe loops mach messages with crafted port descriptors (counts and
/// name values) through a local port pair and journals each result.
@interface KPAuditIPCModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
