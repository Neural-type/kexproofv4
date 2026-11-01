#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112576 — kernel CoW memory-integrity write (live on 27.0.1, fixed 27.2).
/// Apple: "An app may be able to cause unexpected changes to copy-on-write
/// memory" — the earlier audit's oracle (source FILE via pread) was wrong:
/// the contract under test is memory isolation between CoW peers.
/// Oracles here:
///   1. fork(): child writes its private copy, parent must NOT see the write.
///   2. mach_vm_remap(COPY): write to the copy, the original must NOT change.
///   3. both repeated under memory pressure (the 27.2 fix touched
///      vm_pageout_compress_page — the compressor is in the blast radius).
///   4. a madvise(MADV_FREE) race on the copy path.
@interface KPAuditCoWIntegrityModule : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
