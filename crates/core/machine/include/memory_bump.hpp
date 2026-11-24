#pragma once

#include <cstdlib>

#include "memory.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::memory_bump {

/// One shadow read of a register at `(shard, event.timestamp)`, which advances the register's
/// memory-argument timestamp out of an earlier shard or a long gap.  See the `MemoryBumpChip` doc
/// comment.
template<class F>
__ZKM_HOSTDEV__ void event_to_row(const MemoryBumpEvent& event, MemoryBumpCols<F>& cols) {
    const MemoryReadRecord record = {
        .value = event.value,
        .shard = event.shard,
        .timestamp = event.timestamp,
        .prev_shard = event.prev_shard,
        .prev_timestamp = event.prev_timestamp,
    };
    memory::populate_read<F>(cols.access, record);

    cols.shard = F::from_canonical_u32(event.shard);
    cols.clk_16bit_limb = F::from_canonical_u32(event.timestamp & 0xffff);
    cols.clk_high_limb = F::from_canonical_u32(event.timestamp >> 16);
    cols.addr = F::from_canonical_u32(event.addr);
    cols.is_real = F::one();
}
}  // namespace zkm_core_machine_sys::memory_bump
