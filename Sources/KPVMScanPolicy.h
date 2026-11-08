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

    // Reject PAC user-space pointers (untagged 36-bit user VA 0x100000000-0x300000000)
    uint64_t untagged = value & 0x0000000fffffffffULL;
    if (untagged >= 0x100000000ULL && untagged < 0x300000000ULL) return NO;

    // Reject SIMD/float/NaN noise: low 16 bits = 0 with 0xfffffff0..ff prefix
    if ((value & 0xffffULL) == 0) {
        uint8_t byte5 = (value >> 40) & 0xff;
        if (byte5 >= 0xf0) return NO;
    }
    // Reject packed int32+float pairs (low 24 bits = 0)
    if ((value & 0xFFFFFULL) == 0) return NO;

    uint8_t byte5 = (value >> 40) & 0xff;
    // ARM64e A17 Pro (T8130) kernel layout:
    //   0xfffffe00... = kernel text/data
    //   0xfffffe10..3f... = kernel heap (zone map)
    if (byte5 == 0xfe) {
        uint8_t byte4 = (value >> 32) & 0xff;
        if (byte4 >= 0x00 && byte4 <= 0x3f) return YES;
    }
    if (byte5 >= 0xf0 && byte5 <= 0xfd) return YES;
    return NO;
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
