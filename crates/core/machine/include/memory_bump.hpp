#pragma once

#include <cstdlib>

#include "memory.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::memory_bump {

/// One shadow read of a register at `(shard, 0)`, which advances the register's memory-argument
/// timestamp out of whatever earlier shard it was left in.  See the `MemoryBumpChip` doc comment.
template<class F>
__ZKM_HOSTDEV__ void event_to_row(const MemoryBumpEvent& event, MemoryBumpCols<F>& cols) {
    const MemoryReadRecord record = {
        .value = event.value,
        .shard = event.shard,
        .timestamp = 0,
        .prev_shard = event.prev_shard,
        .prev_timestamp = event.prev_timestamp,
    };
    memory::populate_read<F>(cols.access, record);

    cols.shard = F::from_canonical_u32(event.shard);
    cols.addr = F::from_canonical_u32(event.addr);
    cols.is_real = F::one();
}
}  // namespace zkm_core_machine_sys::memory_bump
