#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, KPTestSection) {
    KPTestSectionDevice = 0,
    KPTestSectionResources,
    KPTestSectionKernelProbes
};

@protocol KPTestModule <NSObject>
@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, copy, readonly) NSString *title;
@property (nonatomic, copy, readonly) NSString *subtitle;
@property (nonatomic, copy, readonly) NSString *icon;
@property (nonatomic, assign, readonly) KPTestSection section;
- (NSString *)runReport;
@end

NS_ASSUME_NONNULL_END
