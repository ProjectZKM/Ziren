#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::syscall {
    template<class F, class EF7>
    __ZKM_HOSTDEV__ void event_to_row(const SyscallEvent* event, const bool is_receive, SyscallCols<F>* cols) {
        cols->shard = F::from_canonical_u32(event->shard);
        cols->clk = F::from_canonical_u32(event->clk);
        cols->syscall_id = F::from_canonical_u32(event->syscall_id);
        // Pack arguments into range-checked half-words for collision-resistant global lookup.
        uint32_t a1 = event->arg1;
        cols->arg1_lo = F::from_canonical_u32((a1 & 0xFF) | ((a1 >> 8 & 0xFF) << 8));
        cols->arg1_hi = F::from_canonical_u32(((a1 >> 16) & 0xFF) | ((a1 >> 24 & 0xFF) << 8));
        uint32_t a2 = event->arg2;
        cols->arg2_lo = F::from_canonical_u32((a2 & 0xFF) | ((a2 >> 8 & 0xFF) << 8));
        cols->arg2_hi = F::from_canonical_u32(((a2 >> 16) & 0xFF) | ((a2 >> 24 & 0xFF) << 8));
        cols->is_real = F::one();
    }
}  // namespace zkm::memory_local
