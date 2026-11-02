#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

/// Sandbox escape via CVE-2026-112706: CoreMedia bytestream XPC fd leak.
/// mediaplaybackd vends live file descriptors for protected paths to any
/// sandboxed app. iOS 26.5-27.0.1 (patched in 27.2).
///
/// Chain: xpc_connection -> FigXPC handshake (.rp1/.rp2/.org)
///        -> Curl create with client-controlled CreationURL
///        -> reply ByteStreamDetails.FileDescriptor -> dup/pread
@interface KPFDLeakModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
