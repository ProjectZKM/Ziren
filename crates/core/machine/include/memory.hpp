#pragma once

#include <cstdlib>

#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::memory {

template<class F>
__ZKM_HOSTDEV__ void populate_access(
    MemoryAccessCols<F>& self,
    const MemoryRecord& current_record,
    const MemoryRecord& prev_record
) {
    write_word_from_u32_v2<F>(self.value, current_record.value);

    self.prev_shard = F::from_canonical_u32(prev_record.shard);
    self.prev_clk = F::from_canonical_u32(prev_record.timestamp);

    // Fill columns used for verifying current memory access time value is greater than
    // previous's.
    const bool use_clk_comparison = prev_record.shard == current_record.shard;
    self.compare_clk = F::from_bool(use_clk_comparison);
    const uint32_t prev_time_value = use_clk_comparison ? prev_record.timestamp : prev_record.shard;
    const uint32_t current_time_value =
        use_clk_comparison ? current_record.timestamp : current_record.shard;

    const uint32_t diff_minus_one = current_time_value - prev_time_value - 1;
    const uint16_t diff_16bit_limb = (uint16_t)(diff_minus_one & 0xffff);
    self.diff_16bit_limb = F::from_canonical_u16(diff_16bit_limb).val;
    const uint8_t diff_8bit_limb = (uint8_t)((diff_minus_one >> 16) & 0xff);
    self.diff_8bit_limb = F::from_canonical_u32(diff_8bit_limb);
}

template<class F>
__ZKM_HOSTDEV__ void
populate_read(MemoryReadCols<F>& self, const MemoryReadRecord& record) {
    const MemoryRecord current_record = {
        .shard = record.shard,
        .timestamp = record.timestamp,
        .value = record.value,
    };
    const MemoryRecord prev_record = {
        .shard = record.prev_shard,
        .timestamp = record.prev_timestamp,
        .value = record.value,
    };
    populate_access<F>(self.access, current_record, prev_record);
}

template<class F>
__ZKM_HOSTDEV__ void populate_read_write(
    MemoryReadWriteCols<F>& self,
    const OptionMemoryRecordEnum& record
) {
    if (record.tag == OptionMemoryRecordEnumTag::None) {
        return;
    }
    MemoryRecord current_record;
    MemoryRecord prev_record;
    switch (record.tag) {
        case OptionMemoryRecordEnumTag::Read:
            current_record = {
                .shard = record.read.shard,
                .timestamp = record.read.timestamp,
                .value = record.read.value,
            };
            prev_record = {
                .shard = record.read.prev_shard,
                .timestamp = record.read.prev_timestamp,
                .value = record.read.value,
            };
            break;
        case OptionMemoryRecordEnumTag::Write:
            current_record = {
                .shard = record.write.shard,
                .timestamp = record.write.timestamp,
                .value = record.write.value,
            };
            prev_record = {
                .shard = record.write.prev_shard,
                .timestamp = record.write.prev_timestamp,
                .value = record.write.prev_value,
            };
            break;
        default:
            // Unreachable. `None` case guarded above.
            assert(false);
            break;
    }
    write_word_from_u32_v2<F>(self.prev_value, prev_record.value);
    populate_access<F>(self.access, current_record, prev_record);
}
}  // namespace zkm_core_machine_sys::memory
