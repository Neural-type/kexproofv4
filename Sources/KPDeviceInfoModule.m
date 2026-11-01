#import "KPDeviceInfoModule.h"

#import <errno.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

@interface KPDeviceInfoModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPDeviceInfoModule

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"device.info";
        _title = @"Device Info";
        _subtitle = @"Model, iOS, kernel and iOS 27 target validation";
        _icon = @"iphone";
        _section = KPTestSectionDevice;
    }
    return self;
}

static NSString *KPStringFromSysctl(const char *name) {
    size_t size = 0;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0 || size > 4096) {
        return @"unavailable";
    }
    NSMutableData *data = [NSMutableData dataWithLength:size];
    if (sysctlbyname(name, data.mutableBytes, &size, NULL, 0) != 0) {
        return @"unavailable";
    }
    const char *bytes = data.bytes;
    size_t length = strnlen(bytes, size);
    NSString *value = [[NSString alloc] initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
    return value.length ? value : @"unavailable";
}

static NSString *KPFriendlyModel(NSString *machine) {
    NSDictionary<NSString *, NSString *> *models = @{
        @"iPhone15,4": @"iPhone 15",
        @"iPhone15,5": @"iPhone 15 Plus",
        @"iPhone16,1": @"iPhone 15 Pro",
        @"iPhone16,2": @"iPhone 15 Pro Max"
    };
    return models[machine] ?: machine;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString stringWithString:@"=== KexProofV4 Device Info ===\n"];
    [report appendFormat:@"Collected: %@\n", [NSDate date]];

    NSProcessInfo *process = NSProcessInfo.processInfo;
    NSOperatingSystemVersion version = process.operatingSystemVersion;
    NSString *versionString = [NSString stringWithFormat:@"%ld.%ld.%ld",
                               (long)version.majorVersion,
                               (long)version.minorVersion,
                               (long)version.patchVersion];

    struct utsname systemInfo = {0};
    NSString *machine = @"unavailable";
    if (uname(&systemInfo) == 0) {
        machine = [NSString stringWithUTF8String:systemInfo.machine] ?: @"unknown";
        [report appendFormat:@"Model: %@ (%@)\n", KPFriendlyModel(machine), machine];
        [report appendFormat:@"System name: %s\n", systemInfo.sysname];
        [report appendFormat:@"Kernel release: %s\n", systemInfo.release];
        [report appendFormat:@"Kernel version: %s\n", systemInfo.version];
    } else {
        [report appendFormat:@"uname failed: %s\n", strerror(errno)];
    }

    [report appendFormat:@"iOS version: %@\n", versionString];
    [report appendFormat:@"OS build (kern.osversion): %@\n", KPStringFromSysctl("kern.osversion")];
    [report appendFormat:@"Kernel release (sysctl): %@\n", KPStringFromSysctl("kern.osrelease")];
    [report appendFormat:@"Hardware model (hw.model): %@\n", KPStringFromSysctl("hw.model")];
    [report appendFormat:@"Physical memory: %llu bytes\n", (unsigned long long)process.physicalMemory];
    [report appendFormat:@"Logical CPUs: %ld\n", (long)process.processorCount];

    [report appendFormat:@"iOS 27.x target: %@\n", version.majorVersion == 27 ? @"CONFIRMED" : @"NOT CONFIRMED"];
    [report appendFormat:@"iPhone 15 Pro target: %@\n", [machine isEqualToString:@"iPhone16,1"] ? @"CONFIRMED" : @"NOT CONFIRMED"];
    [report appendFormat:@"iOS 27.0.1 exact target: %@\n", [versionString isEqualToString:@"27.0.1"] ? @"CONFIRMED" : @"NOT CONFIRMED"];

    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    [report appendFormat:@"App: %@ %@ (%@)\n",
     info[@"CFBundleDisplayName"] ?: @"KexProofV4",
     info[@"CFBundleShortVersionString"] ?: @"unknown",
     info[@"CFBundleIdentifier"] ?: @"unknown"];
    return report;
}

@end
