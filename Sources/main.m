#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <unistd.h>
#import <xpc/xpc.h>
#import "KPAppDelegate.h"

// FD leak runs BEFORE UIKit to avoid XPC conflict with scene management
static int fdleak_preflight(void) {
    // Load XPC
    void *xpcLib = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
    typedef void* (*xpc_create_t)(const char *, void *, uint64_t);
    typedef void (*xpc_fn_t)(void *);
    xpc_create_t xpc_create = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_fn_t xpc_resume = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_resume");
    xpc_fn_t xpc_cancel = dlsym(xpcLib ? xpcLib : RTLD_DEFAULT, "xpc_connection_cancel");

    if (!xpc_create) {
        NSLog(@"[fdleak] XPC functions not available");
        return -1;
    }

    // Test connection
    void *conn = xpc_create("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
    if (!conn) {
        NSLog(@"[fdleak] connection failed");
        return -2;
    }
    NSLog(@"[fdleak] connection created");
    if (xpc_resume) xpc_resume(conn);
    NSLog(@"[fdleak] connection resumed");
    usleep(100000);
    if (xpc_cancel) xpc_cancel(conn);
    NSLog(@"[fdleak] connection cancelled (clean)");
    return 0;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSLog(@"[KexProofV4] launch");

        return UIApplicationMain(argc, argv, nil, NSStringFromClass(KPAppDelegate.class));
    }
}
