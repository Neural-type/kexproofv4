#import "KPReportStore.h"
#import "KPLog.h"

@implementation KPReportStore

static NSString *KPReportTimestamp(void) {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.dateFormat = @"yyyyMMdd-HHmmss-SSS";
    return [formatter stringFromDate:[NSDate date]];
}

static NSString *KPReportDirectory(NSError **error) {
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return nil;
    }
    return documents;
}

static NSString *KPSafeIdentifier(NSString *identifier) {
    NSMutableCharacterSet *allowed = [NSMutableCharacterSet alphanumericCharacterSet];
    [allowed addCharactersInString:@"-."];
    NSArray<NSString *> *parts = [identifier componentsSeparatedByCharactersInSet:allowed.invertedSet];
    NSString *safe = [parts componentsJoinedByString:@"-"];
    return safe.length ? safe : @"report";
}

+ (NSURL *)saveReport:(NSString *)report identifier:(NSString *)identifier error:(NSError **)error {
    NSString *documents = KPReportDirectory(error);
    if (!documents) return nil;
    NSString *name = [NSString stringWithFormat:@"kexproofv3-%@-%@.txt", KPSafeIdentifier(identifier), KPReportTimestamp()];
    NSURL *URL = [NSURL fileURLWithPath:[documents stringByAppendingPathComponent:name]];
    NSString *full = [NSString stringWithFormat:
                      @"=== KexProofV3 module report ===\nModule: %@\nSaved: %@\n\n%@\n",
                      identifier, [NSDate date], report];
    return [full writeToURL:URL atomically:YES encoding:NSUTF8StringEncoding error:error] ? URL : nil;
}

+ (NSURL *)createShareURLWithError:(NSError **)error {
    NSString *documents = KPReportDirectory(error);
    if (!documents) return nil;
    NSString *name = [NSString stringWithFormat:@"kexproofv3-share-%@.txt", KPReportTimestamp()];
    NSURL *URL = [NSURL fileURLWithPath:[documents stringByAppendingPathComponent:name]];
    NSMutableString *output = [NSMutableString stringWithFormat:
                               @"=== KexProofV3 share ===\nCreated: %@\nVersion: %@\n\n",
                               [NSDate date],
                               [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.4.0"];

    // Only include the LATEST module report (not all files)
    NSArray<NSString *> *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:documents error:nil] ?: @[];
    NSArray<NSString *> *sorted = [files sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    NSString *latestReport = nil;
    NSString *latestName = nil;
    for (NSString *file in [sorted reverseObjectEnumerator]) {
        if (![file hasPrefix:@"kexproofv3-"] || [file hasPrefix:@"kexproofv3-share-"]) continue;
        if (![file hasSuffix:@".txt"]) continue;
        NSString *path = [documents stringByAppendingPathComponent:file];
        NSString *body = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        if (!body) continue;
        latestReport = body;
        latestName = file;
        break;
    }
    if (latestReport) {
        [output appendFormat:@"--- Latest report: %@ ---\n%@\n", latestName, latestReport];
    } else {
        [output appendString:@"No reports found.\n"];
    }
    return [output writeToURL:URL atomically:YES encoding:NSUTF8StringEncoding error:error] ? URL : nil;
}

@end
