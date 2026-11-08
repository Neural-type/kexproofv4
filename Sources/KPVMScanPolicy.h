#ifndef KPVMScanPolicy_h
#define KPVMScanPolicy_h

#import <mach/mach.h>
#import <mach/vm_statistics.h>
#import <stdint.h>

#ifndef VM_MEMORY_MALLOC_PROB_GUARD
#define VM_MEMORY_MALLOC_PROB_GUARD 13
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
    if (tag == VM_MEMORY_STACK || tag == VM_MEMORY_DYLD_MALLOC) return YES;
    if (tag >= VM_MEMORY_MALLOC && tag <= VM_MEMORY_MALLOC_PROB_GUARD) return YES;
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
    return (raw & 0x000000ffffffffffULL) | 0xfffffe0000000000ULL;
}

static inline BOOL KPIsPlausibleKernelText(uint64_t raw, uint64_t *untagged) {
    if ((raw & 0x3ULL) != 0 || (raw & (1ULL << 55)) == 0) return NO;
    uint8_t top8 = (uint8_t)((raw >> 56) & 0xff);
    uint8_t byte6 = (uint8_t)((raw >> 48) & 0xff);
    uint8_t byte5 = (uint8_t)((raw >> 40) & 0xff);
    uint8_t byte4 = (uint8_t)((raw >> 32) & 0xff);
    if (top8 == 0x00 || byte6 != 0xff) return NO;
    // Match 0xfffffff0... or 0xfffffe00... kernelcache text/data ranges.
    // Canonical untagged ktext (kernelcache link base 0xfffffff007004000) has
    // byte5=0xff byte4=0xf0 — the T8130 runtime family 0xfffffe00 has byte5=0xfe.
    if (byte5 == 0xf0 || (byte5 == 0xff && byte4 == 0xf0) || (byte5 == 0xfe && byte4 < 0x10)) {
        uint64_t norm = 0xfffffff000000000ULL | (raw & 0x0000000fffffffffULL);
        if (norm >= 0xfffffff007004000ULL && norm < 0xfffffff090000000ULL) {
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
    // kalloc / zone map on arm64e: 0xfffffe10..0xfffffe3f or 0xffffffe0..0xffffffe9
    if (byte5 == 0xfe && byte4 >= 0x10 && byte4 < 0x40) {
        uint64_t norm = 0xfffffe0000000000ULL | (raw & 0x000000ffffffffffULL);
        if (untagged) *untagged = norm;
        return YES;
    }
    if (byte5 == 0xff && byte4 >= 0xe0 && byte4 < 0xf0) {
        uint64_t norm = 0xffffff0000000000ULL | (raw & 0x000000ffffffffffULL);
        if (untagged) *untagged = norm;
        return YES;
    }
    return NO;
}

static BOOL KPIsKernelPointerCandidate(uint64_t value) {
    if ((value & 0x3) != 0 || value == UINT64_MAX) return NO;

    // Per ollie: bit 55 MUST be 1 for arm64e kernel pointers
    if ((value & (1ULL << 55)) == 0) return NO;

    // Reject PAC user-space pointers (untagged 36-bit user VA)
    uint64_t untagged = value & 0x0000000fffffffffULL;
    if (untagged >= 0x100000000ULL && untagged < 0x300000000ULL) return NO;

    // Reject SIMD/float/NaN noise
    if ((value & 0xffffULL) == 0) {
        uint8_t byte5 = (value >> 40) & 0xff;
        if (byte5 >= 0xf0) return NO;
    }
    if ((value & 0xFFFFFULL) == 0) return NO;

    // Check canonical kernel VA ranges
    uint64_t va = KPStripPACKernel(value);
    if (va == 0) return NO;
    return (KPIsPlausibleKernelText(value, NULL) || KPIsPlausibleKernelHeap(value, NULL));
}

static BOOL KPIsKnownDiagnosticConstant(uint64_t value) {
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

#endif
