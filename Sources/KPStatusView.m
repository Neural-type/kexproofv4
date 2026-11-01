#import "KPStatusView.h"

@interface KPStatusView ()
@property (nonatomic, strong) UIView *indicator;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *detailLabel;
@end

@implementation KPStatusView

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
        self.layer.cornerRadius = 14;
        self.layer.cornerCurve = kCACornerCurveContinuous;
        self.accessibilityIdentifier = @"status-card";

        _indicator = [[UIView alloc] init];
        _indicator.translatesAutoresizingMaskIntoConstraints = NO;
        _indicator.layer.cornerRadius = 5;
        _indicator.backgroundColor = UIColor.systemGrayColor;

        _titleLabel = [[UILabel alloc] init];
        _titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
        _titleLabel.textColor = UIColor.labelColor;
        _titleLabel.numberOfLines = 0;

        _detailLabel = [[UILabel alloc] init];
        _detailLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
        _detailLabel.textColor = UIColor.secondaryLabelColor;
        _detailLabel.numberOfLines = 0;

        UIStackView *titleRow = [[UIStackView alloc] initWithArrangedSubviews:@[_indicator, _titleLabel]];
        titleRow.axis = UILayoutConstraintAxisHorizontal;
        titleRow.alignment = UIStackViewAlignmentCenter;
        titleRow.spacing = 9;

        UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[titleRow, _detailLabel]];
        stack.translatesAutoresizingMaskIntoConstraints = NO;
        stack.axis = UILayoutConstraintAxisVertical;
        stack.spacing = 6;
        [self addSubview:stack];

        [NSLayoutConstraint activateConstraints:@[
            [_indicator.widthAnchor constraintEqualToConstant:10],
            [_indicator.heightAnchor constraintEqualToConstant:10],
            [stack.topAnchor constraintEqualToAnchor:self.topAnchor constant:14],
            [stack.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:16],
            [stack.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-16],
            [stack.bottomAnchor constraintEqualToAnchor:self.bottomAnchor constant:-14]
        ]];
    }
    return self;
}

- (void)updateWithState:(KPStatusState)state title:(NSString *)title detail:(NSString *)detail {
    UIColor *color;
    switch (state) {
        case KPStatusStateRunning:
            color = UIColor.systemBlueColor;
            break;
        case KPStatusStateSuccess:
            color = UIColor.systemGreenColor;
            break;
        case KPStatusStateError:
            color = UIColor.systemRedColor;
            break;
        case KPStatusStateIdle:
            color = UIColor.systemGrayColor;
            break;
    }
    self.indicator.backgroundColor = color;
    self.titleLabel.text = title;
    self.detailLabel.text = detail;
    self.accessibilityLabel = [NSString stringWithFormat:@"%@. %@", title, detail];
}

@end
