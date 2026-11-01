#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// CVE-2026-112576 — kernel CoW memory-integrity write (live on 27.0.1, fixed 27.2).
/// Contract under test: a write through ONE CoW mapping must NEVER appear in
/// its peer. Fork-free oracles (iOS blocks fork() from the sandbox):
///   O1  two MAP_PRIVATE mappings of the SAME file: write A, check B.
///   O2  vm_remap(copy=TRUE): write the copy, check the original.
///   O3  sanity: vm_remap(copy=FALSE) MUST propagate (proves the oracle sees it).
///   O4  O1/O2 under compressor pressure (the fix touched vm_pageout_compress_page).
///   O5  madvise(MADV_FREE) race on the private-copy path.
/// Only leaks in O1/O2/O5 are CVE evidence; O3 leaking is EXPECTED.
@interface KPAuditCoWIntegrityModule : NSObject <KPTestModule>
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
