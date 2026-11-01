#import "KPAppDelegate.h"
#import "KPViewController.h"

@implementation KPAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSLog(@"[KexProofV4] didFinishLaunching");
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    KPViewController *workbench = [[KPViewController alloc] init];
    UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:workbench];
    navigation.navigationBar.prefersLargeTitles = YES;

    UINavigationBarAppearance *appearance = [[UINavigationBarAppearance alloc] init];
    [appearance configureWithDefaultBackground];
    navigation.navigationBar.standardAppearance = appearance;
    navigation.navigationBar.scrollEdgeAppearance = appearance;
    navigation.navigationBar.compactAppearance = appearance;
    self.window.tintColor = UIColor.systemIndigoColor;
    self.window.rootViewController = navigation;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
