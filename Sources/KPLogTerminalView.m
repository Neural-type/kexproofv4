#import "KPLogTerminalView.h"
#import "KPLog.h"

@interface KPLogTerminalView () {
    NSMutableString *_pendingBuffer;
    NSTimer *_flushTimer;
    BOOL _needsScroll;
}
@end

@implementation KPLogTerminalView

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame textContainer:nil];
    if (self) {
        self.translatesAutoresizingMaskIntoConstraints = NO;
        self.editable = NO;
        self.selectable = YES;
        self.alwaysBounceVertical = YES;
        self.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        self.backgroundColor = [UIColor colorWithRed:0.03 green:0.03 blue:0.04 alpha:1.0];
        self.textColor = [UIColor colorWithRed:0.75 green:0.95 blue:0.75 alpha:1.0];
        self.layer.cornerRadius = 10;
        self.layer.borderWidth = 1;
        self.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.15].CGColor;
        self.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
        self.accessibilityLabel = @"KexProof terminal log";
        self.text = @"";
        _pendingBuffer = [NSMutableString string];
        _needsScroll = NO;

        __weak typeof(self) weakSelf = self;
        KPLog.shared.onAppend = ^(NSString *text) {
            [weakSelf appendRaw:text];
        };

        // Flush timer: batch UI updates every 300ms
        _flushTimer = [NSTimer scheduledTimerWithTimeInterval:0.3
                                                       target:self
                                                     selector:@selector(flushBuffer)
                                                     userInfo:nil
                                                      repeats:YES];
    }
    return self;
}

- (void)dealloc {
    [_flushTimer invalidate];
}

- (void)appendLine:(NSString *)text {
    [self appendRaw:[text stringByAppendingString:@"\n"]];
}

- (void)appendRaw:(NSString *)text {
    if (!text.length) return;
    @synchronized (_pendingBuffer) {
        [_pendingBuffer appendString:text];
        _needsScroll = YES;
    }
}

- (void)flushBuffer {
    NSString *pending;
    BOOL scroll;
    @synchronized (_pendingBuffer) {
        if (_pendingBuffer.length == 0) return;
        pending = [_pendingBuffer copy];
        [_pendingBuffer setString:@""];
        scroll = _needsScroll;
        _needsScroll = NO;
    }

    NSDictionary *attributes = @{
        NSFontAttributeName: self.font,
        NSForegroundColorAttributeName: self.textColor
    };
    NSTextStorage *storage = self.textStorage;
    [storage appendAttributedString:[[NSAttributedString alloc] initWithString:pending attributes:attributes]];
    if (storage.length > 524288) {
        [storage deleteCharactersInRange:NSMakeRange(0, storage.length - 393216)];
    }
    if (scroll) {
        [self scrollToBottom];
    }
}

- (void)scrollToBottom {
    if (!self.text.length) return;
    [self scrollRangeToVisible:NSMakeRange(self.text.length - 1, 1)];
}

@end
