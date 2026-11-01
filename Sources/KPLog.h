#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface KPLog : NSObject
@property (nonatomic, copy, nullable) void (^onAppend)(NSString *text);
+ (instancetype)shared;
- (void)append:(NSString *)text;
- (void)appendFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (NSString *)transcript;
@end

NS_ASSUME_NONNULL_END
