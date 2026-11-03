#import "KPMarkerProbeModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>

@interface KPMarkerProbeModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPMarkerProbeModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"marker.probe";
        _title = @"Marker objects (controlled corruption)";
        _subtitle = @"Create marked objects, find in memory, prepare for targeted write";
        _icon = @"flag";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-marker-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · Marker Objects ===\n"];
    [report appendString:@"Step 1: create marked objects, find in memory.\n"];
    [report appendString:@"Foundation for controlled corruption (kirby approach).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d pid=%d\n",
     UIDevice.currentDevice.systemVersion, getuid(), getpid()];

    // Phase 1: create marked objects
    [report appendString:@"\n--- Phase 1: create marked objects ---\n"];

    // Create 8 marked buffers with unique patterns
    #define MARKER_COUNT 8
    #define MARKER_SIZE 4096
    uint8_t *markers[MARKER_COUNT];
    uint32_t markerIDs[MARKER_COUNT];

    for (int i = 0; i < MARKER_COUNT; i++) {
        markers[i] = calloc(1, MARKER_SIZE);
        markerIDs[i] = 0xABCD0001 + i; // unique ID per marker

        // Fill with marker pattern
        uint32_t *p = (uint32_t *)markers[i];
        for (int j = 0; j < MARKER_SIZE / 4; j++) {
            p[j] = markerIDs[i];
        }

        [report appendFormat:@"marker[%d]: id=0x%08x addr=0x%lx\n",
         i, markerIDs[i], (unsigned long)markers[i]];
        [self journal:[NSString stringWithFormat:@"marker[%d] id=0x%08x addr=0x%lx",
                       i, markerIDs[i], (unsigned long)markers[i]]];
    }

    // Phase 2: find markers in memory
    [report appendString:@"\n--- Phase 2: find markers in memory ---\n"];

    vm_address_t scanAddr = 0;
    vm_size_t scanSize = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count;
    int found = 0;

    while (1) {
        scanAddr = (scanAddr == 0) ? 0 : scanAddr + scanSize;
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        uint32_t depth = 0;
        if (vm_region_recurse_64(mach_task_self(), &scanAddr, &scanSize, &depth,
                                  (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) break;
        if (info.is_submap) continue;
        if (!(info.protection & VM_PROT_WRITE)) continue;
        if (scanSize > 16 * 1024 * 1024) continue;

        volatile uint32_t *p = (volatile uint32_t *)scanAddr;
        size_t words = scanSize / 4;

        for (size_t j = 0; j < words; j++) {
            uint32_t v = p[j];
            for (int m = 0; m < MARKER_COUNT; m++) {
                if (v == markerIDs[m]) {
                    [report appendFormat:@"FOUND marker[%d] at region+0x%lx (value=0x%08x)\n",
                     m, (unsigned long)(scanAddr + j * 4), v];
                    found++;
                    break;
                }
            }
        }
    }

    [report appendFormat:@"markers found in memory: %d\n", found];

    // Phase 3: prepare for controlled corruption
    [report appendString:@"\n--- Phase 3: corruption targets ---\n"];
    if (found > 0) {
        [report appendString:@"Markers located. Ready for targeted corruption.\n"];
        [report appendString:@"Next: corrupt marker values, observe effects.\n"];
    } else {
        [report appendString:@"Markers not found in writable regions.\n"];
        [report appendString:@"Try: different marker sizes, or check heap layout.\n"];
    }

    // Cleanup
    for (int i = 0; i < MARKER_COUNT; i++) {
        free(markers[i]);
    }

    // Verdict
    [report appendString:@"\n"];
    if (found >= MARKER_COUNT / 2) {
        [report appendString:@"VERDICT: MARKERS_FOUND\n"];
    } else if (found > 0) {
        [report appendString:@"VERDICT: MARKERS_PARTIAL\n"];
    } else {
        [report appendString:@"VERDICT: MARKERS_NOT_FOUND\n"];
    }

    return report;
}

@end
