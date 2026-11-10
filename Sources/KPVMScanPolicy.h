#ifndef KPVMScanPolicy_h
#define KPVMScanPolicy_h

#import <mach/mach.h>
#import <mach/vm_statistics.h>
#import <stdint.h>

#ifndef VM_MEMORY_MALLOC_PROB_GUARD
#define VM_MEMORY_MALLOC_PROB_GUARD 13
#endif
#ifndef VM_MEMORY_COREGRAPHICS_BACKINGSTORES
#define VM_MEMORY_COREGRAPHICS_BACKINGSTORES 50
#endif
#ifndef VM_MEMORY_LAYERKIT
#define VM_MEMORY_LAYERKIT 51
#endif

static BOOL KPVMRangeOverlaps(vm_address_t address, vm_size_t size,
                              vm_address_t excludedAddress, vm_size_t excludedSize) {
    if (!excludedAddress || !excludedSize) return NO;
    if (address > UINT64_MAX - size || excludedAddress > UINT64_MAX - excludedSize) return YES;
    return address < excludedAddress + excludedSize && excludedAddress < address + size;
}

static BOOL KPVMShouldSkipRegion(const vm_region_submap_info_data_64_t *info,
                                 vm_address_t address, vm_size_t size,
                                 const void *stackMarker,
                                 const vm_address_t *excludedAddresses,
                                 const vm_size_t *excludedSizes,
                                 size_t excludedCount) {
    unsigned int tag = info->user_tag;
    if (tag == VM_MEMORY_STACK ||
        tag == VM_MEMORY_MALLOC_PROB_GUARD ||
        tag == VM_MEMORY_COREGRAPHICS_BACKINGSTORES ||
        tag == VM_MEMORY_LAYERKIT) {
        return YES;
    }
    uintptr_t marker = (uintptr_t)stackMarker;
    if (marker && marker >= address && marker < address + size) return YES;
    for (size_t i = 0; i < excludedCount; i++) {
        if (KPVMRangeOverlaps(address, size, excludedAddresses[i], excludedSizes[i])) return YES;
    }
    return NO;
}

// Per ollie: arm64e kernel pointers MUST have bit 55 = 1, byte6 = 0xff, and valid kernel VA prefix
static inline uint64_t KPStripPACKernel(uint64_t raw) {
    if ((raw & (1ULL << 55)) == 0) return 0; // not a kernel pointer
    uint8_t top8 = (uint8_t)((raw >> 56) & 0xff);
    uint8_t byte6 = (uint8_t)((raw >> 48) & 0xff);
    uint8_t byte5 = (uint8_t)((raw >> 40) & 0xff);
    // Require canonical untagged (0xffff) or plausible TBI/PAC tag (top8 != 0, byte6 == 0xff)
    // and valid kernel VA byte5 (0xf0, 0xfe, 0xff, 0xe0..0xef)
    if (top8 == 0x00 || byte6 != 0xff) return 0;
    if (byte5 != 0xf0 && byte5 != 0xfe && byte5 != 0xff && (byte5 < 0xe0 || byte5 > 0xef)) {
        return 0;
    }
    return (raw & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
}

static inline BOOL KPIsPlausibleKernelText(uint64_t raw, uint64_t *untagged) {
    if ((raw & 0x3ULL) != 0 || (raw & (1ULL << 55)) == 0) return NO;
    if ((raw & 0xffffULL) == 0) return NO;
    uint8_t top8 = (uint8_t)((raw >> 56) & 0xff);
    uint8_t byte6 = (uint8_t)((raw >> 48) & 0xff);
    uint8_t byte5 = (uint8_t)((raw >> 40) & 0xff);
    uint8_t byte4 = (uint8_t)((raw >> 32) & 0xff);
    if (top8 == 0x00 || byte6 != 0xff) return NO;
    // Match 0xfffffff0... or 0xfffffe00... kernelcache text/data ranges (bounded below 0xfffffff018000000).
    if (byte5 == 0xf0 || (byte5 == 0xff && byte4 == 0xf0) || (byte5 == 0xfe && byte4 < 0x10)) {
        uint64_t norm = 0xfffffff000000000ULL | (raw & 0x0000000fffffffffULL);
        if (norm >= 0xfffffff007004000ULL && norm < 0xfffffff018000000ULL) {
            if (untagged) *untagged = norm;
            return YES;
        }
    }
    return NO;
}

static inline BOOL KPIsPlausibleKernelHeap(uint64_t raw, uint64_t *untagged) {
    if ((raw & 0x7ULL) != 0 || (raw & (1ULL << 55)) == 0) return NO;
    uint8_t top8 = (uint8_t)((raw >> 56) & 0xff);
    uint8_t byte6 = (uint8_t)((raw >> 48) & 0xff);
    uint8_t byte5 = (uint8_t)((raw >> 40) & 0xff);
    uint8_t byte4 = (uint8_t)((raw >> 32) & 0xff);
    if (top8 == 0x00 || byte6 != 0xff) return NO;
    // T8122/T8130 kalloc / zone / kernel_map:
    //   - 0xfffffe10..0xfffffe3f (zone map)
    //   - 0xffffffe0..0xffffffef (.GEN0..3, .DATA, KMA, kernel_map 0xffffffec..0xffffffef)
    if (byte5 == 0xfe && byte4 >= 0x10 && byte4 < 0x40) {
        uint64_t norm = 0xfffffe0000000000ULL | (raw & 0x000000ffffffffffULL);
        if (untagged) *untagged = norm;
        return YES;
    }
    if (byte5 == 0xff && byte4 >= 0xe0 && byte4 <= 0xef) {
        uint64_t norm = 0xffffff0000000000ULL | (raw & 0x000000ffffffffffULL);
        if (untagged) *untagged = norm;
        return YES;
    }
    return NO;
}

typedef enum {
    KPTR_REJECT_PACKED_INT32 = 0,
    KPTR_REJECT_BAD_TBI,
    KPTR_REJECT_UNALIGNED,
    KPTR_CANDIDATE_ZONE_HEAP,
    KPTR_CANDIDATE_KERNEL_TEXT_DATA
} kptr_class_t;

static inline kptr_class_t KPClassifyKPtr(uint64_t raw) {
    if ((raw >> 56) != 0xFF) return KPTR_REJECT_BAD_TBI;
    uint32_t lo32 = (uint32_t)(raw & 0xFFFFFFFFULL);
    // Reject obvious small negative int32 in low half (0xffffxxxx) while allowing
    // valid kernel VAs like 0xffffffedfd6347b0 / 0xffffffefff31b3f0
    if ((lo32 & 0xFFFF0000U) == 0xFFFF0000U || lo32 < 0x00001000U) return KPTR_REJECT_PACKED_INT32;
    if ((raw & 0x3ULL) != 0) return KPTR_REJECT_UNALIGNED;
    uint32_t hi32 = (uint32_t)(raw >> 32);
    if (hi32 == 0xFFFFFFF0U) return KPTR_CANDIDATE_KERNEL_TEXT_DATA;
    if (hi32 >= 0xFFFFFE00U && hi32 <= 0xFFFFFE0FU) return KPTR_CANDIDATE_KERNEL_TEXT_DATA;
    if ((hi32 >= 0xFFFFFE10U && hi32 <= 0xFFFFFE3FU) ||
        (hi32 >= 0xFFFFFFE0U && hi32 <= 0xFFFFFFEFU)) {
        return ((raw & 0x7ULL) == 0) ? KPTR_CANDIDATE_ZONE_HEAP : KPTR_REJECT_UNALIGNED;
    }
    return KPTR_REJECT_UNALIGNED;
}

static BOOL KPIsKernelPointerCandidate(uint64_t value) {
    if ((value & 0x3) != 0 || value == UINT64_MAX) return NO;

    // Bit 55 MUST be 1 for arm64e kernel pointers (also excludes all user-space VAs)
    if ((value & (1ULL << 55)) == 0) return NO;

    // Reject 64KB-aligned SIMD/float/raster noise (e.g. 0xffffffe4720c0000, 0xfffffff072050000)
    // while explicitly preserving the confirmed kernel_map outer-object base prefix 0xffffffedfd620000
    BOOL isKnownOuterObjBase = ((value & 0xffffffffffff0000ULL) == 0xffffffedfd620000ULL);
    if (!isKnownOuterObjBase && ((value & 0xffffULL) == 0 || (value & 0xFFFFFULL) == 0)) return NO;

    // Reject 3-byte repeated fill/pixel runs in lo32 (e.g. 0xffffffdfd8d8d888, 0x40404040)
    uint8_t b0 = (uint8_t)(value & 0xff);
    uint8_t b1 = (uint8_t)((value >> 8) & 0xff);
    uint8_t b2 = (uint8_t)((value >> 16) & 0xff);
    uint8_t b3 = (uint8_t)((value >> 24) & 0xff);
    if ((b0 == b1 && b1 == b2) || (b1 == b2 && b2 == b3)) return NO;

    kptr_class_t cls = KPClassifyKPtr(value);
    if (cls != KPTR_CANDIDATE_ZONE_HEAP && cls != KPTR_CANDIDATE_KERNEL_TEXT_DATA) return NO;
    uint64_t va = KPStripPACKernel(value);
    if (va == 0) return NO;
    return (KPIsPlausibleKernelText(value, NULL) || KPIsPlausibleKernelHeap(value, NULL));
}

static BOOL KPIsKnownDiagnosticConstant(uint64_t value) {
    // Filter userspace malloc_small packed [uint32_t xx806580, int32_t neg] entries
    // confirmed by Stage 5 context dump (ctx[+1] == 0xbeef).
    if ((value & 0x00ffffffULL) == 0x00806580ULL) return YES;

    static const uint64_t constants[] = {
        0xfffffff000000000ULL,
        0xfffffff007004000ULL,
        0xfffffff00700c000ULL,
        0xfffffff007804000ULL,
        0xfffffff007ce0000ULL,
        0xfffffff007e00000ULL,
        0xfffffff0082b0000ULL,
        0xfffffff0082fc000ULL,
        0xfffffff00b02c000ULL,
        0xfffffff00b034000ULL,
        0xfffffff00b284000ULL,
        0xfffffff00b4e8000ULL,
        0xffffffe000000000ULL,
    };
    for (size_t i = 0; i < sizeof(constants) / sizeof(constants[0]); i++) {
        if (value == constants[i]) return YES;
    }
    static const int ntlValues[] = {
        -1, 0, 1, 2, 3, 100, 1000, 8000, 16000,
        16431, 16447, 16455, 16462, 16463, 16464,
    };
    for (size_t i = 0; i < sizeof(ntlValues) / sizeof(ntlValues[0]); i++) {
        int64_t index = (int64_t)ntlValues[i] - 16463;
        if (value == (((uint64_t)index << 32) | 0x59)) return YES;
    }
    return NO;
}

static inline BOOL KPIsRepeatedByteWord(uint64_t w) {
    uint8_t hi0 = (uint8_t)((w >> 56) & 0xff);
    uint8_t hi1 = (uint8_t)((w >> 48) & 0xff);
    uint8_t hi2 = (uint8_t)((w >> 40) & 0xff);
    uint8_t hi3 = (uint8_t)((w >> 32) & 0xff);
    if (hi0 != 0 && hi0 != 0xff && hi0 == hi1 && hi1 == hi2 && hi2 == hi3) return YES;
    uint8_t lo0 = (uint8_t)((w >> 24) & 0xff);
    uint8_t lo1 = (uint8_t)((w >> 16) & 0xff);
    uint8_t lo2 = (uint8_t)((w >> 8) & 0xff);
    uint8_t lo3 = (uint8_t)(w & 0xff);
    if (lo0 != 0 && lo0 != 0xff && lo0 == lo1 && lo1 == lo2 && lo2 == lo3) return YES;
    return NO;
}

static inline BOOL KPIsContextFalsePositive(const uint64_t *words, size_t wordCount, size_t index) {
    if (!words || index >= wordCount) return NO;
    if (index + 1 < wordCount && words[index + 1] == 0x000000000000beefULL) return YES;
    if (index > 0 && (words[index - 1] & 0xffffffffULL) == 0xeabb9729ULL) return YES;
    // Reject packed RGBA / negative int32 table entries where adjacent words have 0xffffffff
    // in either 32-bit half (e.g. ctx[+1] = 0x00000037ffffffff) or 4-byte pixel fill runs
    // (e.g. ctx[-1] = 0x101010101042ffff, ctx[+1] = 0x38d8d8d8d8d8deff).
    if (index > 0) {
        uint64_t prev = words[index - 1];
        if (prev != UINT64_MAX &&
            (((prev & 0xffffffffULL) == 0xffffffffULL) || ((prev >> 32) == 0xffffffffULL))) {
            return YES;
        }
        if (KPIsRepeatedByteWord(prev)) return YES;
    }
    if (index + 1 < wordCount) {
        uint64_t next = words[index + 1];
        if (next != UINT64_MAX &&
            (((next & 0xffffffffULL) == 0xffffffffULL) || ((next >> 32) == 0xffffffffULL))) {
            return YES;
        }
        if (KPIsRepeatedByteWord(next)) return YES;
    }
    return NO;
}

#endif
