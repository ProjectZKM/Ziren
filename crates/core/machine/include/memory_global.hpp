#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "memory_local.hpp"

namespace zkm_core_machine_sys::memory_global {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const MemoryInitializeFinalizeEvent* event, const bool is_receive, MemoryInitCols<F>* cols) {
        [[maybe_unused]]MemoryRecord record;
        if (is_receive) {
            record.shard = event->shard;
            record.timestamp = event->timestamp;
            record.value = event->value;
        } else {
            record.shard = 0;
            record.timestamp = 0;
            record.value = event->value;
        }
        cols->shard = F::from_canonical_u32(event->shard);
        cols->timestamp = F::from_canonical_u32(event->timestamp);
        cols->addr[0] = F::from_canonical_u32(event->addr & 0xffff);
        cols->addr[1] = F::from_canonical_u32(event->addr >> 16);
        F top_distance = F::from_canonical_u32(0x7F00) - cols->addr[1];
        cols->top_inv = top_distance == F::zero() ? F::zero() : top_distance.reciprocal();
        for(uintptr_t i = 0 ; i < 4 ; i++) {
            cols->value[i] = F::from_canonical_u32(((event->value) >> (8 * i)) & 0xff);
        }
        cols->is_real = F::one();
    }
}  // namespace zkm::memory_local
