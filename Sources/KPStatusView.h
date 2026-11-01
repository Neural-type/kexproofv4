#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, KPStatusState) {
    KPStatusStateIdle = 0,
    KPStatusStateRunning,
    KPStatusStateSuccess,
    KPStatusStateError
};

@interface KPStatusView : UIView
- (void)updateWithState:(KPStatusState)state title:(NSString *)title detail:(NSString *)detail;
@end

NS_ASSUME_NONNULL_END
