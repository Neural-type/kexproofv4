#import "KPTestModule.h"
#import <mach/mach.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct {
    uint64_t kptr;
    vm_address_t userVA;
    vm_address_t regionBase;
    vm_size_t regionSize;
    uint32_t userTag;
    uint32_t shareMode;
    uint32_t objectId;
    int steeredNTL;
    uint64_t steeredX0;
    uint64_t ctxWords[8];
} Stage5KPtrRecord;

#ifdef __cplusplus
extern "C" {
#endif
const Stage5KPtrRecord * _Nullable KPH9GetStage5Candidate(int idx);
int KPH9GetStage5CandidateCount(void);
#ifdef __cplusplus
}
#endif

/// KRW via H9 video encoder OOB write (CVE-2026-112705-adjacent).
/// AVE_HEVC_ST_RPS_Retrieve: unbounded copy in UserRPSForFaceTime.
/// Overwrites FPS* pointer in encoder session -> controlled write.
/// Used by Calif in iOS 27.0.1 jailbreak (Hexacon demo).
@interface KPH9EncoderModule : NSObject <KPTestModule>
- (instancetype)initWithNameSweep;
@end

NS_ASSUME_NONNULL_END
