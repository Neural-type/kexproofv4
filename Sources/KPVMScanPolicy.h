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

static BOOL KPIsKernelPointerCandidate(uint64_t value) {
    if ((value & 0x3) != 0 || value == UINT64_MAX) return NO;
    // Reject values with low 24 bits = 0 (packed int32+float pairs, not real kernel pointers)
    if ((value & 0xFFFFFULL) == 0) return NO;
    uint32_t high = (uint32_t)(value >> 32);
    return (high >= 0xffffffe0U && high <= 0xffffffe1U) ||
           (high >= 0xfffffff0U && high <= 0xfffffffdU);
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
