#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface KPTestCell : UITableViewCell
- (void)configureWithTitle:(NSString *)title
                  subtitle:(NSString *)subtitle
                      icon:(NSString *)icon
                 showsPlay:(BOOL)showsPlay;
- (void)setRunning:(BOOL)running;
- (void)setModuleEnabled:(BOOL)enabled;
@end

NS_ASSUME_NONNULL_END
