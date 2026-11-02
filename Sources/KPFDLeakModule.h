#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPFDLeakModule : NSObject <KPTestModule>
@property (nonatomic, assign, readonly, getter=isArmed) BOOL armed;
- (instancetype)initWithArmed:(BOOL)armed;
- (instancetype)initWithTargetPath:(NSString *)targetPath sessionName:(NSString *)sessionName;
@end

NS_ASSUME_NONNULL_END
