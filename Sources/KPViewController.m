#import "KPViewController.h"
#import "KPDeviceInfoModule.h"
#import "KPResourceLoaderModule.h"
#import "KPAuditLP112621Module.h"
#import "KPAuditGlyph86950Module.h"
#import "KPAuditPDF112611Module.h"
#import "KPAuditRPU112688Module.h"
#import "KPAuditCoW112576Module.h"
#import "KPAuditCoWIntegrityModule.h"
#import "KPAuditAVE112705Module.h"
#import "KPAuditAVESpriteModule.h"
#import "KPAuditAVEPANModule.h"
#import "KPAuditIPCModule.h"
#import "KPKReadProbeModule.h"
#import "KPKASLRBypassModule.h"
#import "KPMarkerProbeModule.h"
#import "KPH9EncoderModule.h"
#import "KPRootExploitModule.h"
#import "KPSPTMRaceModule.h"
#import "KPFDLeakModule.h"
#import "KPINFileLeakModule.h"
#import "KPAuditUAF84495Module.h"
#import "KPLog.h"
#import "KPLogTerminalView.h"
#import "KPLogViewController.h"
#import "KPReportStore.h"
#import "KPStatusView.h"
#import "KPTestCell.h"
#import "KPTestModule.h"

@interface KPViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UIView *headerView;
@property (nonatomic, strong) KPStatusView *statusView;
@property (nonatomic, strong) KPLogTerminalView *terminal;
@property (nonatomic, strong) UIButton *runButton;
@property (nonatomic, copy) NSArray<id<KPTestModule>> *modules;
@property (nonatomic, copy) NSArray<NSArray<id<KPTestModule>> *> *groupedModules;
@property (nonatomic, copy) NSArray<NSString *> *sectionTitles;
@property (nonatomic, copy, nullable) NSString *runningModuleID;
@property (nonatomic, assign) BOOL jobRunning;
@property (nonatomic, strong) dispatch_queue_t workQueue;
@end

@implementation KPViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"KexProof";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
        style:UIBarButtonItemStylePlain
        target:self
        action:@selector(shareTapped:)];

    self.workQueue = dispatch_queue_create("com.stealth.kexproofv4.audit", DISPATCH_QUEUE_SERIAL);
    self.sectionTitles = @[@"Device", @"Resources", @"Independent Audit"];
    [self configureModules];
    [self configureHeader];
    [self configureTable];
    [self updateRunButton];

    NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"4.0.0";
    [KPLog.shared appendFormat:@"=== KexProofV4 %@ @ %@ ===", version, [NSDate date]];
    [KPLog.shared append:@"Independent CVE re-audit rig. Sources: Apple advisories 149226/149230,"];
    [KPLog.shared append:@"Xplo8E PoC, Appknox write-up — not the local hunter reports."];
    [KPLog.shared append:@"Terminal log: legacy v1 panel. Target: iPhone 15 Pro / iOS 27.0.1."];
    [self scheduleAutoRunFromArguments];
}

// PC-driven sessions: launch-application ... --run=<module-id> [--run-all-armed]
- (void)scheduleAutoRunFromArguments {
    NSMutableArray<NSString *> *wanted = [NSMutableArray array];
    BOOL allArmed = NO;
    for (NSString *arg in NSProcessInfo.processInfo.arguments) {
        if ([arg hasPrefix:@"--run="]) {
            [wanted addObject:[arg substringFromIndex:6]];
        } else if ([arg isEqualToString:@"--run-all-armed"]) {
            allArmed = YES;
        }
    }
    if (!wanted.count && !allArmed) return;
    [KPLog.shared appendFormat:@"[auto-run] scheduled: %@%@",
        wanted.count ? [wanted componentsJoinedByString:@","] : @"(none)",
        allArmed ? @" + all-armed" : @""];

    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        NSMutableArray<id<KPTestModule>> *queue = [NSMutableArray array];
        if (allArmed) {
            for (id<KPTestModule> module in self.modules) {
                if ([module.identifier containsString:@"armed"] ||
                    [module.identifier containsString:@"survey"]) {
                    [queue addObject:module];
                }
            }
        }
        for (NSString *identifier in wanted) {
            for (id<KPTestModule> module in self.modules) {
                if ([module.identifier isEqualToString:identifier] && ![queue containsObject:module]) {
                    [queue addObject:module];
                }
            }
        }
        if (queue.count) {
            [KPLog.shared appendFormat:@"[auto-run] firing %lu module(s)", (unsigned long)queue.count];
            [self startModules:queue];
        } else {
            [KPLog.shared append:@"[auto-run] no matching modules"];
        }
    });
}

- (void)configureModules {
    self.modules = @[
        [[KPDeviceInfoModule alloc] init],
        [[KPResourceLoaderModule alloc] init],
        [[KPAuditIPCModule alloc] initWithNameSweep],
        [[KPH9EncoderModule alloc] initWithNameSweep],
        [[KPFDLeakModule alloc] initWithArmed:YES],
        [[KPINFileLeakModule alloc] initWithNameSweep],
        [[KPAuditLP112621Module alloc] initWithArmed:NO],
        [[KPAuditLP112621Module alloc] initWithArmed:YES],
        [[KPAuditGlyph86950Module alloc] initWithArmed:NO],
        [[KPAuditGlyph86950Module alloc] initWithArmed:YES],
        [[KPAuditPDF112611Module alloc] initWithArmed:NO],
        // CG PDF armed: disabled � OOB write corrupts system memory, causes crashes
        // [[KPAuditPDF112611Module alloc] initWithArmed:YES],
        [[KPAuditRPU112688Module alloc] initWithArmed:NO],
        [[KPAuditRPU112688Module alloc] initWithArmed:YES],
        [[KPAuditCoW112576Module alloc] initWithArmed:NO],
        [[KPAuditCoW112576Module alloc] initWithArmed:YES],
        [[KPAuditCoWIntegrityModule alloc] initWithArmed:NO],
        [[KPAuditCoWIntegrityModule alloc] initWithArmed:YES],
        [[KPAuditAVE112705Module alloc] initWithTemporalLayers:1],
        [[KPAuditAVE112705Module alloc] initWithTemporalLayers:16462],
        [[KPAuditAVE112705Module alloc] initWithTemporalLayers:16463],
        [[KPAuditAVESpriteModule alloc] initWithSprayCount:24 marker:0x42424242],
        [[KPAuditAVESpriteModule alloc] initWithSprayCount:64 marker:0x43434343],
        [[KPAuditAVESpriteModule alloc] initWithSprayCount:64 marker:0x44444444 ntl:16000],
        [[KPAuditAVEPANModule alloc] initWithTemporalLayers:16467],
        [[KPAuditAVEPANModule alloc] initWithTemporalLayers:16471],
        [[KPAuditUAF84495Module alloc] initWithArmed:NO],
        [[KPAuditUAF84495Module alloc] initWithArmed:YES],
    ];
    NSMutableArray<NSMutableArray<id<KPTestModule>> *> *groups = [NSMutableArray array];
    for (NSUInteger index = 0; index < self.sectionTitles.count; index++) {
        [groups addObject:[NSMutableArray array]];
    }
    for (id<KPTestModule> module in self.modules) {
        [groups[(NSUInteger)module.section] addObject:module];
    }
    self.groupedModules = [[NSArray alloc] initWithArray:groups copyItems:YES];
}

- (void)configureHeader {
    self.headerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 390, 480)];

    UILabel *versionLabel = [[UILabel alloc] init];
    NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"4.0.0";
    versionLabel.text = [NSString stringWithFormat:@"KexProofV4 · %@", version];
    versionLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    versionLabel.textColor = UIColor.labelColor;

    UILabel *targetLabel = [[UILabel alloc] init];
    targetLabel.text = @"Independent CVE re-audit · iPhone 15 Pro / iOS 27.0.1";
    targetLabel.numberOfLines = 0;
    targetLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    targetLabel.textColor = UIColor.secondaryLabelColor;

    self.statusView = [[KPStatusView alloc] init];
    [self.statusView updateWithState:KPStatusStateIdle
                               title:@"Ready"
                              detail:@"Baseline rows are safe. Armed rows may crash the app."];

    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *configuration = [UIButtonConfiguration filledButtonConfiguration];
    configuration.title = @"Run Audit (safe)";
    configuration.image = [UIImage systemImageNamed:@"play.fill"];
    configuration.imagePadding = 8;
    configuration.baseBackgroundColor = UIColor.systemIndigoColor;
    configuration.baseForegroundColor = UIColor.whiteColor;
    configuration.cornerStyle = UIButtonConfigurationCornerStyleLarge;
    configuration.contentInsets = NSDirectionalEdgeInsetsMake(12, 20, 12, 20);
    self.runButton.configuration = configuration;
    [self.runButton addTarget:self action:@selector(runAllTapped) forControlEvents:UIControlEventTouchUpInside];

    // Legacy v1 terminal panel (dark console, green mono).
    self.terminal = [[KPLogTerminalView alloc] initWithFrame:CGRectZero];
    [self.terminal.heightAnchor constraintGreaterThanOrEqualToConstant:220].active = YES;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        versionLabel, targetLabel, self.statusView, self.runButton, self.terminal]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    [stack setCustomSpacing:16 afterView:targetLabel];
    [stack setCustomSpacing:14 afterView:self.statusView];
    [stack setCustomSpacing:14 afterView:self.runButton];
    [self.headerView addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.headerView.topAnchor constant:8],
        [stack.leadingAnchor constraintEqualToAnchor:self.headerView.leadingAnchor constant:20],
        [stack.trailingAnchor constraintEqualToAnchor:self.headerView.trailingAnchor constant:-20],
        [stack.bottomAnchor constraintEqualToAnchor:self.headerView.bottomAnchor constant:-18],
        [self.runButton.heightAnchor constraintEqualToConstant:50]
    ]];
}

- (void)configureTable {
    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.translatesAutoresizingMaskIntoConstraints = NO;
    self.tableView.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 72;
    self.tableView.tableHeaderView = self.headerView;
    [self.tableView registerClass:KPTestCell.class forCellReuseIdentifier:@"KPTestCell"];
    [self.view addSubview:self.tableView];
    [NSLayoutConstraint activateConstraints:@[
        [self.tableView.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [self.tableView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.tableView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.tableView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor]
    ]];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat width = self.tableView.bounds.size.width;
    if (width <= 0) return;
    CGSize fitting = [self.headerView systemLayoutSizeFittingSize:CGSizeMake(width, UILayoutFittingCompressedSize.height)
                                    withHorizontalFittingPriority:UILayoutPriorityRequired
                                          verticalFittingPriority:UILayoutPriorityFittingSizeLevel];
    CGFloat height = ceil(fitting.height);
    if (ABS(CGRectGetWidth(self.headerView.frame) - width) > 0.5 ||
        ABS(CGRectGetHeight(self.headerView.frame) - height) > 0.5) {
        self.headerView.frame = CGRectMake(0, 0, width, height);
        self.tableView.tableHeaderView = self.headerView;
    }
}

- (void)updateRunButton {
    UIButtonConfiguration *configuration = self.runButton.configuration ?: [UIButtonConfiguration filledButtonConfiguration];
    configuration.title = self.jobRunning ? @"Running Audit…" : @"Run Audit (safe)";
    configuration.image = self.jobRunning ? nil : [UIImage systemImageNamed:@"play.fill"];
    configuration.showsActivityIndicator = self.jobRunning;
    self.runButton.configuration = configuration;
    self.runButton.enabled = !self.jobRunning;
}

- (void)runAllTapped {
    if (self.jobRunning) return;
    NSMutableArray<id<KPTestModule>> *safe = [NSMutableArray array];
    for (id<KPTestModule> module in self.modules) {
        if ([module.identifier containsString:@"armed"]) continue;
        if ([module.identifier containsString:@"survey"]) {
            [safe addObject:module];
            continue;
        }
        [safe addObject:module];
    }
    [self startModules:safe];
}

- (void)startModules:(NSArray<id<KPTestModule>> *)modules {
    if (self.jobRunning || !modules.count) return;
    self.jobRunning = YES;
    self.runningModuleID = nil;
    [self.statusView updateWithState:KPStatusStateRunning
                               title:@"Running"
                              detail:modules.count == 1 ? modules.firstObject.title : @"Independent audit pass"];
    [self updateRunButton];
    [self.tableView reloadData];

    NSArray<id<KPTestModule>> *queue = [modules copy];
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    dispatch_async(self.workQueue, ^{
        for (id<KPTestModule> module in queue) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.runningModuleID = module.identifier;
                [self.statusView updateWithState:KPStatusStateRunning
                                           title:@"Running"
                                          detail:module.title];
                [self.tableView reloadData];
            });
            @try {
                NSString *report = nil;
                @try {
                    report = [module runReport];
                } @catch (NSException *exception) {
                    [KPLog.shared appendFormat:@"EXCEPTION in module %@: %@", module.identifier, exception.reason];
                    report = [NSString stringWithFormat:@"VERDICT: EXCEPTION (%@)", exception.reason];
                }
                if (!report.length) {
                    [NSException raise:@"KPEmptyReport" format:@"%@ returned empty", module.identifier];
                }
                [KPLog.shared appendFormat:@"\n=== %@ [%@] ===\n%@", module.title, module.identifier, report];
                NSError *saveError = nil;
                NSURL *savedURL = [KPReportStore saveReport:report identifier:module.identifier error:&saveError];
                if (savedURL) {
                    [KPLog.shared appendFormat:@"Report saved: %@", savedURL.lastPathComponent];
                } else {
                    [failures addObject:[NSString stringWithFormat:@"%@: %@", module.title, saveError.localizedDescription]];
                }
            } @catch (NSException *exception) {
                NSString *reason = exception.reason ?: exception.name;
                [failures addObject:[NSString stringWithFormat:@"%@: %@", module.title, reason]];
                [KPLog.shared appendFormat:@"Module %@ failed: %@", module.identifier, reason];
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.jobRunning = NO;
            self.runningModuleID = nil;
            if (failures.count) {
                [self.statusView updateWithState:KPStatusStateError
                                           title:@"Completed with errors"
                                          detail:failures.firstObject];
            } else {
                [self.statusView updateWithState:KPStatusStateSuccess
                                           title:@"Audit Complete"
                                          detail:[NSString stringWithFormat:@"%lu reports saved", (unsigned long)queue.count]];
            }
            [self updateRunButton];
            [self.tableView reloadData];
        });
    });
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return self.groupedModules.count + 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section < (NSInteger)self.groupedModules.count ? self.groupedModules[(NSUInteger)section].count : 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section < (NSInteger)self.sectionTitles.count ? self.sectionTitles[(NSUInteger)section] : @"Logs";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == (NSInteger)self.groupedModules.count - 1) {
        return @"Armed rows exercise the public CVE mechanics (LinkPresentation HEIC mismatch, "
               @"CG saturating/truncating pair, PDF shading R=36, RPU overrun counts, CoW races). "
               @"They are excluded from Run Audit (safe) and may crash the app.";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    KPTestCell *cell = [tableView dequeueReusableCellWithIdentifier:@"KPTestCell" forIndexPath:indexPath];
    if (indexPath.section == (NSInteger)self.groupedModules.count) {
        if (indexPath.row == 0) {
            [cell configureWithTitle:@"Full Session Log"
                            subtitle:@"Legacy terminal transcript (push)"
                                icon:@"doc.plaintext"
                           showsPlay:NO];
        } else {
            [cell configureWithTitle:@"Export Report"
                            subtitle:@"Share transcript and saved reports"
                                icon:@"square.and.arrow.up"
                           showsPlay:NO];
        }
        [cell setRunning:NO];
        [cell setModuleEnabled:YES];
        return cell;
    }

    id<KPTestModule> module = self.groupedModules[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    [cell configureWithTitle:module.title subtitle:module.subtitle icon:module.icon showsPlay:YES];
    BOOL running = self.jobRunning && [self.runningModuleID isEqualToString:module.identifier];
    [cell setRunning:running];
    [cell setModuleEnabled:!self.jobRunning];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == (NSInteger)self.groupedModules.count) {
        if (indexPath.row == 0) {
            KPLogViewController *logs = [[KPLogViewController alloc] init];
            [self.navigationController pushViewController:logs animated:YES];
        } else {
            [self shareTapped:tableView];
        }
        return;
    }
    if (self.jobRunning) return;
    id<KPTestModule> module = self.groupedModules[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    [self startModules:@[module]];
}

- (void)shareTapped:(id)sender {
    NSError *error = nil;
    NSURL *URL = [KPReportStore createShareURLWithError:&error];
    if (!URL) {
        [self.statusView updateWithState:KPStatusStateError title:@"Export Failed" detail:error.localizedDescription];
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[URL]
                                                                           applicationActivities:nil];
    if ([sender isKindOfClass:UIBarButtonItem.class]) {
        activity.popoverPresentationController.barButtonItem = sender;
    } else {
        activity.popoverPresentationController.sourceView = self.tableView;
        activity.popoverPresentationController.sourceRect = self.tableView.bounds;
    }
    [self presentViewController:activity animated:YES completion:nil];
}

@end
