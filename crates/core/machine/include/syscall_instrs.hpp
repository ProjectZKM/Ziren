#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::syscall_instrs {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const SyscallEvent& event, SyscallInstrColumns<F>& cols) {
        cols.is_real = F::one();
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);

        write_word_from_u32_v2<F>(cols.op_a_value, event.a_record.value);
        write_word_from_u32_v2<F>(cols.op_b_value, event.arg1);
        write_word_from_u32_v2<F>(cols.op_c_value, event.arg2);
        write_word_from_u32_v2<F>(cols.prev_a_value, event.a_record.prev_value);
        cols.syscall_id = F::from_canonical_u32(event.syscall_id);
        F syscall_id = F::from_canonical_u32(event.a_record.prev_value & 0xffff);
        F num_cycles = cols.prev_a_value._0[3];

        cols.num_extra_cycles = num_cycles;
        cols.is_halt = F::from_bool(
            syscall_id == F::from_canonical_u32(to_syscall_id(SyscallCode::HALT))
                || syscall_id == F::from_canonical_u32(to_syscall_id(SyscallCode::SYS_EXT_GROUP))
        );

        cols.is_sys_linux = F::from_bool((event.a_record.prev_value & 0x0ff00u) != 0);

        // Populate `is_enter_unconstrained`.
        populate_is_zero_operation(
            cols.is_enter_unconstrained,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::ENTER_UNCONSTRAINED))
        );

        // Populate `is_hint_len`.
        populate_is_zero_operation(
            cols.is_hint_len,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::SYSHINTLEN))
        );

        // Populate `is_halt`.
        populate_is_zero_operation(
            cols.is_halt_check,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::HALT))
        );

        // Populate `is_exit_group`.
        populate_is_zero_operation(
            cols.is_exit_group_check,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::SYS_EXT_GROUP))
        );

        // Populate `is_commit`.
        populate_is_zero_operation(
            cols.is_commit,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::COMMIT))
        );

        // Populate `is_commit_deferred_proofs`.
        populate_is_zero_operation(
            cols.is_commit_deferred_proofs,
            syscall_id - F::from_canonical_u32(to_syscall_id(SyscallCode::COMMIT_DEFERRED_PROOFS))
        );

        // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
        // digest word.
        if (syscall_id == F::from_canonical_u32(to_syscall_id(SyscallCode::COMMIT))
            || syscall_id == F::from_canonical_u32(to_syscall_id(SyscallCode::COMMIT_DEFERRED_PROOFS)))
        {
            cols.index_bitmap[event.arg1] = F::one();
        }

        // For halt and commit deferred proofs syscalls, we need to koala bear range check one of
        // it's operands.
        if (cols.is_halt == F::one()) {
            write_word_from_u32_v2<F>(cols.operand_to_check, event.arg1);
            populate_range_checker(cols.operand_range_check_cols, event.arg1);
            cols.syscall_range_check_operand = F::one();
        }

        if (syscall_id == F::from_canonical_u32(to_syscall_id(SyscallCode::COMMIT_DEFERRED_PROOFS))) {
            write_word_from_u32_v2<F>(cols.operand_to_check, event.arg2);
            populate_range_checker(cols.operand_range_check_cols, event.arg2);
            cols.syscall_range_check_operand = F::one();
        }
    }
}  // namespace zkm::syscall_instrs
