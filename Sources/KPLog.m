#import "KPLog.h"

#import <errno.h>
#import <fcntl.h>
#import <os/log.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

static NSString *gKPLivePath;
static NSFileHandle *gKPLiveHandle;
static BOOL gKPRotationDone;

static BOOL KPOpenLiveLog(void) {
    if (gKPLiveHandle) return YES;
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSError *error = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:&error]) {
        os_log_error(OS_LOG_DEFAULT, "[KexProofV3] log directory: %{public}s", error.localizedDescription.UTF8String);
        return NO;
    }
    if (!gKPLivePath) {
        gKPLivePath = [documents stringByAppendingPathComponent:@"kexproofv3-live.log"];
    }
    if (!gKPRotationDone) {
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = @"yyyyMMdd-HHmmss";
        NSString *previous = [documents stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"kexproofv3-prev-%@.log",
                               [formatter stringFromDate:[NSDate date]]]];
        if (rename(gKPLivePath.fileSystemRepresentation, previous.fileSystemRepresentation) != 0 && errno != ENOENT) {
            os_log_error(OS_LOG_DEFAULT, "[KexProofV3] log rotation: %{public}s", strerror(errno));
            return NO;
        }
        gKPRotationDone = YES;
    }
    int descriptor = open(gKPLivePath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        os_log_error(OS_LOG_DEFAULT, "[KexProofV3] log open: %{public}s", strerror(errno));
        return NO;
    }
    gKPLiveHandle = [[NSFileHandle alloc] initWithFileDescriptor:descriptor closeOnDealloc:YES];
    return YES;
}

@interface KPLog () {
    NSMutableString *_transcript;
    dispatch_queue_t _queue;
}
@end

@implementation KPLog

+ (instancetype)shared {
    static KPLog *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[KPLog alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _transcript = [NSMutableString string];
        _queue = dispatch_queue_create("com.stealth.kexproofv3.log", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)append:(NSString *)text {
    if (!text.length) return;
    NSString *line = [text hasSuffix:@"\n"] ? text : [text stringByAppendingString:@"\n"];
    os_log(OS_LOG_DEFAULT, "[KexProofV3] %{public}s",
           [line stringByTrimmingCharactersInSet:NSCharacterSet.newlineCharacterSet].UTF8String);
    @synchronized (KPLog.class) {
        if (KPOpenLiveLog()) {
            @try {
                [gKPLiveHandle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [gKPLiveHandle synchronizeFile];
            } @catch (NSException *exception) {
                os_log_error(OS_LOG_DEFAULT, "[KexProofV3] log write: %{public}s", exception.reason.UTF8String);
                @try { [gKPLiveHandle closeFile]; } @catch (NSException *ignored) {}
                gKPLiveHandle = nil;
            }
        }
    }
    dispatch_async(_queue, ^{
        [_transcript appendString:line];
        if (_transcript.length > 524288) {
            [_transcript deleteCharactersInRange:NSMakeRange(0, _transcript.length - 393216)];
        }
        void (^handler)(NSString *) = self.onAppend;
        if (handler) {
            dispatch_async(dispatch_get_main_queue(), ^{
                handler(line);
            });
        }
    });
}

- (void)appendFormat:(NSString *)format, ... {
    va_list arguments;
    va_start(arguments, format);
    NSString *text = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    [self append:text];
}

- (NSString *)transcript {
    __block NSString *result;
    dispatch_sync(_queue, ^{
        result = [_transcript copy];
    });
    return result ?: @"";
}

@end
