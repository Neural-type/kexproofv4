#import "KPTestCell.h"

@interface KPTestCell ()
@property (nonatomic, strong) UIView *iconContainer;
@property (nonatomic, strong) UIImageView *iconView;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *subtitleLabel;
@property (nonatomic, strong) UIImageView *accessoryIcon;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@end

@implementation KPTestCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    self = [super initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuseIdentifier];
    if (self) {
        self.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
        self.selectedBackgroundView = [[UIView alloc] init];
        self.selectedBackgroundView.backgroundColor = UIColor.tertiarySystemFillColor;

        _iconContainer = [[UIView alloc] init];
        _iconContainer.translatesAutoresizingMaskIntoConstraints = NO;
        _iconContainer.backgroundColor = UIColor.tertiarySystemFillColor;
        _iconContainer.layer.cornerRadius = 9;
        _iconContainer.layer.cornerCurve = kCACornerCurveContinuous;

        _iconView = [[UIImageView alloc] init];
        _iconView.translatesAutoresizingMaskIntoConstraints = NO;
        _iconView.tintColor = UIColor.systemIndigoColor;
        _iconView.contentMode = UIViewContentModeScaleAspectFit;
        [_iconContainer addSubview:_iconView];

        _titleLabel = [[UILabel alloc] init];
        _titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
        _titleLabel.textColor = UIColor.labelColor;
        _titleLabel.numberOfLines = 0;

        _subtitleLabel = [[UILabel alloc] init];
        _subtitleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
        _subtitleLabel.textColor = UIColor.secondaryLabelColor;
        _subtitleLabel.numberOfLines = 2;

        UIStackView *labels = [[UIStackView alloc] initWithArrangedSubviews:@[_titleLabel, _subtitleLabel]];
        labels.translatesAutoresizingMaskIntoConstraints = NO;
        labels.axis = UILayoutConstraintAxisVertical;
        labels.spacing = 3;

        [self.contentView addSubview:_iconContainer];
        [self.contentView addSubview:labels];
        [NSLayoutConstraint activateConstraints:@[
            [_iconContainer.leadingAnchor constraintEqualToAnchor:self.contentView.layoutMarginsGuide.leadingAnchor],
            [_iconContainer.centerYAnchor constraintEqualToAnchor:self.contentView.centerYAnchor],
            [_iconContainer.widthAnchor constraintEqualToConstant:38],
            [_iconContainer.heightAnchor constraintEqualToConstant:38],
            [_iconView.centerXAnchor constraintEqualToAnchor:_iconContainer.centerXAnchor],
            [_iconView.centerYAnchor constraintEqualToAnchor:_iconContainer.centerYAnchor],
            [_iconView.widthAnchor constraintEqualToConstant:21],
            [_iconView.heightAnchor constraintEqualToConstant:21],
            [labels.leadingAnchor constraintEqualToAnchor:_iconContainer.trailingAnchor constant:12],
            [labels.trailingAnchor constraintEqualToAnchor:self.contentView.layoutMarginsGuide.trailingAnchor],
            [labels.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:12],
            [labels.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-12]
        ]];

        _accessoryIcon = [[UIImageView alloc] initWithFrame:CGRectMake(0, 0, 20, 20)];
        _accessoryIcon.tintColor = UIColor.tertiaryLabelColor;
        _accessoryIcon.contentMode = UIViewContentModeScaleAspectFit;
        _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
        _spinner.hidesWhenStopped = YES;
    }
    return self;
}

- (void)configureWithTitle:(NSString *)title subtitle:(NSString *)subtitle icon:(NSString *)icon showsPlay:(BOOL)showsPlay {
    self.titleLabel.text = title;
    self.subtitleLabel.text = subtitle;
    UIImageSymbolConfiguration *configuration = [UIImageSymbolConfiguration configurationWithPointSize:17 weight:UIImageSymbolWeightSemibold];
    self.iconView.image = [UIImage systemImageNamed:icon withConfiguration:configuration];
    self.accessoryIcon.image = [UIImage systemImageNamed:showsPlay ? @"play.fill" : @"chevron.right"];
    self.accessoryIcon.tintColor = showsPlay ? UIColor.systemIndigoColor : UIColor.tertiaryLabelColor;
    self.accessoryView = self.accessoryIcon;
    [self.spinner stopAnimating];
    self.userInteractionEnabled = YES;
    self.titleLabel.alpha = 1;
    self.subtitleLabel.alpha = 1;
    self.iconContainer.alpha = 1;
}

- (void)setRunning:(BOOL)running {
    if (running) {
        self.accessoryView = self.spinner;
        [self.spinner startAnimating];
    } else {
        [self.spinner stopAnimating];
        self.accessoryView = self.accessoryIcon;
    }
}

- (void)setModuleEnabled:(BOOL)enabled {
    self.userInteractionEnabled = enabled;
    self.titleLabel.alpha = enabled ? 1 : 0.45;
    self.subtitleLabel.alpha = enabled ? 1 : 0.45;
    self.iconContainer.alpha = enabled ? 1 : 0.45;
    self.accessoryIcon.alpha = enabled ? 1 : 0.45;
}

@end
