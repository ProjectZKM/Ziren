#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::syscall {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const SyscallEvent& event, SyscallCols<F>& cols) {
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.syscall_id = F::from_canonical_u32(event.syscall_id);

        // Pack arguments into range-checked half-words for collision-resistant global lookup.
        auto a1b = u32_to_le_bytes(event.arg1);
        cols.arg1_lo = F::from_canonical_u32(a1b[0] + (a1b[1] << 8));
        cols.arg1_hi = F::from_canonical_u32(a1b[2] + (a1b[3] << 8));

        auto a2b = u32_to_le_bytes(event.arg2);
        cols.arg2_lo = F::from_canonical_u32(a2b[0] + (a2b[1] << 8));
        cols.arg2_hi = F::from_canonical_u32(a2b[2] + (a2b[3] << 8));
        cols.is_real = F::one();
    }

    template<class F>
    __ZKM_HOSTDEV__ void event_to_row_result(bool is_linux, uint32_t value, SyscallCols<F>& cols) {
        if (is_linux) {
            auto valueb = u32_to_le_bytes(value);
            cols.result_lo = F::from_canonical_u32(valueb[0] + (valueb[1] << 8));
            cols.result_hi = F::from_canonical_u32(valueb[2] + (valueb[3] << 8));
        } else {
            cols.result_lo = F::zero();
            cols.result_hi = F::zero();
        }
    }

    template<class F>
    __ZKM_HOSTDEV__ void core_event_to_row(const SyscallEvent& event, SyscallCols<F>& cols) {
        event_to_row<F>(event, cols);

        // For Core shard, a_record has real prev_value with linux_sys byte.
        bool is_linux = (event.a_record.prev_value >> 8 & 0xFFu) != 0;

        cols.is_linux = F::from_bool(is_linux);

        event_to_row_result<F>(is_linux, event.a_record.value, cols);
    }

    template<class F>
    __ZKM_HOSTDEV__ void precompile_event_to_row(const SyscallEvent& event, SyscallCols<F>& cols) {
        event_to_row<F>(event, cols);

        bool is_linux = event.a_record.prev_value == 1;

        cols.is_linux = F::from_bool(is_linux);

        event_to_row_result<F>(is_linux, event.a_record.value, cols);
    }
}  // namespace zkm::syscall
