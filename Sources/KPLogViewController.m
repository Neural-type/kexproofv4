#import "KPLogViewController.h"
#import "KPLog.h"
#import "KPLogTerminalView.h"
#import "KPReportStore.h"

@interface KPLogViewController ()
@property (nonatomic, strong) KPLogTerminalView *terminal;
@end

@implementation KPLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Session Log";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:1.0];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
        style:UIBarButtonItemStylePlain
        target:self
        action:@selector(shareTapped:)];

    self.terminal = [[KPLogTerminalView alloc] initWithFrame:CGRectZero];
    [self.view addSubview:self.terminal];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.terminal.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12],
        [self.terminal.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.terminal.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.terminal.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12]
    ]];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.terminal.text = KPLog.shared.transcript;
    __weak typeof(self) weakSelf = self;
    KPLog.shared.onAppend = ^(NSString *text) {
        [weakSelf.terminal appendRaw:text];
    };
    [self.terminal scrollToBottom];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    KPLog.shared.onAppend = nil;
}

- (void)shareTapped:(id)sender {
    NSError *error = nil;
    NSURL *URL = [KPReportStore createShareURLWithError:&error];
    if (!URL) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Export Failed"
                                                                       message:error.localizedDescription
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[URL]
                                                                           applicationActivities:nil];
    activity.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItem;
    [self presentViewController:activity animated:YES completion:nil];
}

@end
