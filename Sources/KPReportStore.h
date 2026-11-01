#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface KPReportStore : NSObject
+ (nullable NSURL *)saveReport:(NSString *)report
                    identifier:(NSString *)identifier
                         error:(NSError **)error;
+ (nullable NSURL *)createShareURLWithError:(NSError **)error;
@end

NS_ASSUME_NONNULL_END
