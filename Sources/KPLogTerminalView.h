#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// Legacy KexProof terminal panel: dark console, green mono text,
/// rounded frame — matches the original v1 in-app log window.
@interface KPLogTerminalView : UITextView
- (void)appendLine:(NSString *)text;
- (void)appendRaw:(NSString *)text;
- (void)scrollToBottom;
@end

NS_ASSUME_NONNULL_END
