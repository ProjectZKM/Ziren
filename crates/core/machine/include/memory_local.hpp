#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::memory_local {
    template<class F, class EF7>
    __ZKM_HOSTDEV__ void event_to_row(const MemoryLocalEvent* event, SingleMemoryLocal<F>* cols) {
        cols->addr = F::from_canonical_u32(event->addr);
        
        cols->initial_shard = F::from_canonical_u32(event->initial_mem_access.shard);
        cols->initial_clk = F::from_canonical_u32(event->initial_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols->initial_value, event->initial_mem_access.value);
        
        cols->final_shard = F::from_canonical_u32(event->final_mem_access.shard);
        cols->final_clk = F::from_canonical_u32(event->final_mem_access.timestamp);
        write_word_from_u32_v2<F>(cols->final_value, event->final_mem_access.value);

        cols->is_real = F::one();
    }
}  // namespace zkm::memory_local
