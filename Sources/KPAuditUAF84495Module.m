#import "KPAuditUAF84495Module.h"
#import "KPLog.h"
#import <sys/stat.h>
#import <sandbox.h>

@interface KPAuditUAF84495Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditUAF84495Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"uaf84495.armed" : @"uaf84495.survey";
        _title = armed ? @"Kernel UAF surface (armed)" : @"Kernel UAF surface survey";
        _subtitle = armed
            ? @"CVE-2026-84495: BPF node gate classification + pending detach race"
            : @"CVE-2026-84495: identify the real /dev/bpf gate; surface is unpublished";
        _icon = @"network";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)describeErrno:(int)code {
    return [NSString stringWithFormat:@"%d(%s)", code, strerror(code)];
}

- (NSString *)gateClassificationForPath:(NSString *)path {
    struct stat st;
    if (stat(path.fileSystemRepresentation, &st) != 0) {
        return [NSString stringWithFormat:@"stat-fail %@", [self describeErrno:errno]];
    }
    NSString *perms = [NSString stringWithFormat:@"mode=%o uid=%d gid=%d",
        st.st_mode & 07777, st.st_uid, st.st_gid];
    if ((st.st_mode & 0777) == 0600 && st.st_uid == 0) {
        return [NSString stringWithFormat:@"%@ => NODE-PERMS root-only (open from uid %d is expected EPERM/EACCES)",
                perms, getuid()];
    }
    return perms;
}

- (NSDictionary *)probeOpenAtPath:(NSString *)path flags:(int)flags label:(NSString *)label {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"label"] = label;
    errno = 0;
    int fd = open(path.fileSystemRepresentation, flags);
    if (fd >= 0) {
        result[@"fd"] = @(fd);
        result[@"status"] = @"OPEN_OK";
        close(fd);
    } else {
        result[@"status"] = @"DENIED";
        result[@"errno"] = [self describeErrno:errno];
    }
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-84495 · Kernel UAF ===\n"];
    [report appendString:@"Apple 149230: use-after-free -> app termination or WRITE KERNEL MEMORY.\n"];
    [report appendString:@"Reported by: Wang Yu. Component: Kernel. Surface: NOT PUBLISHED.\n"];
    [report appendString:@"WARNING: 'BPF detach race' in local reports is an unverified guess.\n"];
    [report appendString:@"This module classifies the /dev/bpf gate so that one EPERM cannot\n"];
    [report appendString:@"be mistaken for 'the CVE cannot exist'.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d euid=%d\n",
        UIDevice.currentDevice.systemVersion, getuid(), geteuid()];

    [report appendString:@"--- node survey ---\n"];
    NSMutableArray<NSString *> *present = [NSMutableArray array];
    for (int i = 0; i < 16; i++) {
        NSString *path = [NSString stringWithFormat:@"/dev/bpf%d", i];
        struct stat st;
        if (stat(path.fileSystemRepresentation, &st) == 0) {
            [present addObject:path];
            [report appendFormat:@"%@ %@\n", path, [self gateClassificationForPath:path]];
        }
    }
    if (!present.count) {
        struct stat st;
        if (stat("/dev/bpf", &st) == 0) {
            [present addObject:@"/dev/bpf"];
            [report appendFormat:@"/dev/bpf %@\n", [self gateClassificationForPath:@"/dev/bpf"]];
        } else {
            [report appendFormat:@"/dev/bpf missing (%@)\n", [self describeErrno:errno]];
        }
    }

    [report appendString:@"--- access matrix ---\n"];
    NSArray<NSString *> *targets = present.count ? present : @[@"/dev/bpf0"];
    struct { int flags; const char *label; } modes[] = {
        {O_RDWR, "O_RDWR"}, {O_RDONLY, "O_RDONLY"}, {O_WRONLY, "O_WRONLY"},
        {O_RDWR | O_NONBLOCK, "O_RDWR|O_NONBLOCK"}
    };
    for (NSString *target in targets) {
        for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
            [report appendFormat:@"%@ %@\n", target,
                [self probeOpenAtPath:target flags:modes[m].flags label:@(modes[m].label)]];
        }
    }

    [report appendString:@"--- sandbox probes ---\n"];
    if (getuid() == 501) {
        int check = sandbox_check(getpid(), "file-write-data",
                                  SANDBOX_FILTER_PATH, "/dev/bpf0");
        [report appendFormat:@"sandbox_check(file-write-data,/dev/bpf0)=%d "
                             @"(0=allowed, -1=denied errno=%@)\n",
            check, [self describeErrno:errno]];
        check = sandbox_check(getpid(), "file-read-data",
                              SANDBOX_FILTER_PATH, "/dev/bpf0");
        [report appendFormat:@"sandbox_check(file-read-data,/dev/bpf0)=%d\n", check];
    }

    if (self.armed) {
        [report appendString:@"--- armed detach race ---\n"];
        [report appendString:@"NOT RUN in this build: without a BPF descriptor the race has no\n"];
        [report appendString:@"meaningful state, and the real CVE-2026-84495 surface is still\n"];
        [report appendString:@"unknown. Arming a blind BPF race would test OUR guess, not Apple's bug.\n"];
    }

    [report appendString:@"\nVERDICT: "];
    [report appendString:present.count ? @"SURFACE_BLOCKED_AT_NODE\n" : @"SURFACE_ABSENT\n"];
    [report appendString:
     @"Interpretation: if opens were denied by NODE-PERMS (0600 root:wheel),\n"
     @"the denial is environmental and says NOTHING about CVE-2026-84495 —\n"
     @"a kernel UAF reachable through some other privileged deputy would\n"
     @"never touch /dev/bpf. Do NOT close this CVE on EPERM.\n"
     @"Decisive next step: diff 27.0.1 vs 27.2 kernel free() paths and\n"
     @"identify which subsystem Wang Yu's UAF lives in.\n"];
    return report;
}

@end
