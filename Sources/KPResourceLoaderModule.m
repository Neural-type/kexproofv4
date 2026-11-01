#import "KPResourceLoaderModule.h"

#import <CoreFoundation/CoreFoundation.h>
#import <mach-o/loader.h>
#import <string.h>

@interface KPResourceLoaderModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPResourceLoaderModule

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"resources.loader";
        _title = @"Resource Loader";
        _subtitle = @"Validate optional kernelcache, SPTM and TXM bundles";
        _icon = @"doc.text.magnifyingglass";
        _section = KPTestSectionResources;
    }
    return self;
}

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t vmaddr;
    uint64_t fileoff;
    uint32_t entryID;
    uint32_t reserved;
} KPFilesetEntryCommand;

static NSData *KPReadRange(NSFileHandle *handle, unsigned long long offset, NSUInteger length) {
    @try {
        [handle seekToFileOffset:offset];
        return [handle readDataOfLength:length];
    } @catch (NSException *exception) {
        return [NSData data];
    }
}

static BOOL KPStringIsRelevant(NSString *string) {
    NSArray<NSString *> *needles = @[@"darwin", @"kernel version", @"iboot", @"sptm", @"txm", @"27.0", @"18.6"];
    for (NSString *needle in needles) {
        if ([string rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static NSArray<NSString *> *KPVersionStrings(NSData *data) {
    const unsigned char *bytes = data.bytes;
    NSMutableArray<NSString *> *results = [NSMutableArray array];
    NSUInteger start = 0;
    NSUInteger run = 0;
    for (NSUInteger index = 0; index <= data.length && results.count < 16; index++) {
        BOOL printable = index < data.length && bytes[index] >= 0x20 && bytes[index] <= 0x7e;
        if (printable && run < 512) {
            if (run == 0) start = index;
            run++;
            continue;
        }
        if (run >= 8) {
            NSString *candidate = [[NSString alloc] initWithBytes:bytes + start
                                                           length:run
                                                         encoding:NSUTF8StringEncoding];
            if (candidate && KPStringIsRelevant(candidate) && ![results containsObject:candidate]) {
                [results addObject:candidate];
            }
        }
        run = 0;
    }
    return results;
}

static void KPAppendVersionStrings(NSMutableString *report, NSArray<NSData *> *samples) {
    NSMutableArray<NSString *> *strings = [NSMutableArray array];
    for (NSData *sample in samples) {
        for (NSString *string in KPVersionStrings(sample)) {
            if (![strings containsObject:string] && strings.count < 16) {
                [strings addObject:string];
            }
        }
    }
    if (!strings.count) {
        [report appendString:@"Version strings: none found in sampled data\n"];
        return;
    }
    [report appendString:@"Version strings:\n"];
    for (NSString *string in strings) {
        [report appendFormat:@"  %@\n", string];
    }
}

static void KPInspectMachO(NSMutableString *report, NSData *data, unsigned long long fileSize) {
    if (data.length < sizeof(struct mach_header_64)) {
        [report appendString:@"Validation: truncated Mach-O header\n"];
        return;
    }
    struct mach_header_64 header = {0};
    [data getBytes:&header length:sizeof(header)];
    [report appendFormat:@"Mach-O: 64-bit, cputype=0x%x, cpusubtype=0x%x, commands=%u\n",
     header.cputype, header.cpusubtype, header.ncmds];
    if ((unsigned long long)sizeof(header) + header.sizeofcmds > fileSize ||
        (NSUInteger)sizeof(header) + header.sizeofcmds > data.length) {
        [report appendString:@"Validation: invalid or unsampled load-command area\n"];
        return;
    }

    NSUInteger offset = sizeof(header);
    NSUInteger end = offset + header.sizeofcmds;
    NSUInteger filesetCount = 0;
    NSMutableArray<NSString *> *entries = [NSMutableArray array];
    for (uint32_t index = 0; index < header.ncmds && offset + 8 <= end; index++) {
        uint32_t command = 0;
        uint32_t commandSize = 0;
        [data getBytes:&command range:NSMakeRange(offset, sizeof(command))];
        [data getBytes:&commandSize range:NSMakeRange(offset + 4, sizeof(commandSize))];
        if (commandSize < 8 || offset + commandSize > end || offset + commandSize > data.length) {
            [report appendFormat:@"Validation: malformed load command at offset %lu\n", (unsigned long)offset];
            return;
        }
        if (command == 0x80000035 && commandSize >= sizeof(KPFilesetEntryCommand)) {
            KPFilesetEntryCommand entry = {0};
            [data getBytes:&entry range:NSMakeRange(offset, sizeof(entry))];
            filesetCount++;
            if (entry.entryID < commandSize && entries.count < 8) {
                NSUInteger nameOffset = offset + entry.entryID;
                NSUInteger maximum = commandSize - entry.entryID;
                const char *name = (const char *)data.bytes + nameOffset;
                size_t length = strnlen(name, maximum);
                NSString *entryName = [[NSString alloc] initWithBytes:name length:length encoding:NSUTF8StringEncoding];
                if (entryName.length) [entries addObject:entryName];
            }
        }
        offset += commandSize;
    }
    [report appendFormat:@"Validation: recognized Mach-O container; %lu fileset entries\n",
     (unsigned long)filesetCount];
    [report appendFormat:@"Fileset magic (LC_FILESET_ENTRY): %@\n", filesetCount ? @"present" : @"not present"];
    for (NSString *entry in entries) {
        [report appendFormat:@"  entry: %@\n", entry];
    }
}

static NSString *KPInspectResource(NSString *name, NSString *path) {
    NSMutableString *report = [NSMutableString stringWithFormat:@"\n--- %@ ---\n", name];
    NSError *attributesError = nil;
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&attributesError];
    if (!attributes) {
        [report appendFormat:@"Validation: unreadable (%@)\n", attributesError.localizedDescription];
        return report;
    }
    unsigned long long fileSize = attributes.fileSize;
    [report appendFormat:@"Path: %@\nSize: %llu bytes\n", path, fileSize];
    if (!fileSize) {
        [report appendString:@"Validation: empty file\n"];
        return report;
    }

    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!handle) {
        [report appendString:@"Validation: cannot open file\n"];
        return report;
    }
    NSData *head = KPReadRange(handle, 0, 4 * 1024 * 1024);
    NSData *tail = fileSize > 1024 * 1024 ? KPReadRange(handle, fileSize - 1024 * 1024, 1024 * 1024) : [NSData data];
    [handle closeFile];

    if (head.length < 4) {
        [report appendString:@"Validation: truncated file\n"];
        return report;
    }
    uint32_t magic = 0;
    [head getBytes:&magic length:sizeof(magic)];
    const unsigned char *bytes = head.bytes;
    if (magic == MH_MAGIC_64) {
        KPInspectMachO(report, head, fileSize);
    } else if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_CIGAM_64) {
        [report appendString:@"Validation: non-native or 32-bit Mach-O container\n"];
    } else if (magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca) {
        [report appendFormat:@"Validation: recognized universal Mach-O container (magic 0x%08x)\n", magic];
    } else if (memcmp(bytes, "IM4P", 4) == 0 || memcmp(bytes, "IM4R", 4) == 0) {
        [report appendFormat:@"Validation: recognized %.4s IMG4 container\n", bytes];
    } else if (bytes[0] == 0x30) {
        [report appendString:@"Validation: DER SEQUENCE container (IMG4 candidate)\n"];
    } else {
        [report appendFormat:@"Validation: unrecognized container (magic 0x%08x)\n", magic];
    }
    KPAppendVersionStrings(report, @[head, tail]);
    return report;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString stringWithString:@"=== KexProofV3 Resource Loader ===\n"];
    [report appendFormat:@"Checked: %@\n", [NSDate date]];
    [report appendString:@"Expected target resources: iOS 27.0.1 / iPhone 15 Pro\n"];

    NSArray<NSString *> *names = @[@"kernelcache", @"sptm.img4", @"txm.img4"];
    NSUInteger bundled = 0;
    for (NSString *name in names) {
        NSString *path = [name isEqualToString:@"kernelcache"]
            ? [NSBundle.mainBundle pathForResource:@"kernelcache" ofType:nil]
            : [NSBundle.mainBundle pathForResource:name.stringByDeletingPathExtension ofType:name.pathExtension];
        if (!path) {
            [report appendFormat:@"\n--- %@ ---\nStatus: NOT BUNDLED\nValidation: skipped; add the matching iOS 27.0.1 file later\n", name];
            continue;
        }
        bundled++;
        [report appendString:KPInspectResource(name, path)];
    }
    [report appendFormat:@"\nBundled resources: %lu of %lu\n", (unsigned long)bundled, (unsigned long)names.count];
    if (!bundled) {
        [report appendString:@"Result: clean workbench; no binary research resources are bundled.\n"];
    }
    if ([report rangeOfString:@"18.6" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        [report appendString:@"WARNING: a sampled resource contains an iOS 18.6 version string.\n"];
    }
    return report;
}

@end
