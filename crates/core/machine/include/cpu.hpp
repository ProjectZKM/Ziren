#pragma once

#include <cassert>
#include <cstdlib>

#include "memory.hpp"
#include "prelude.hpp"
#include "utils.hpp"
#include "instruction.hpp"

namespace zkm_core_machine_sys::cpu {

template<class F>
__ZKM_HOSTDEV__ void populate_shard_clk(const CpuEventFfi& event, const uint32_t shard, CpuCols<F>& cols) {
    cols.shard = F::from_canonical_u32(shard);

    const uint16_t clk_16bit_limb = (uint16_t)(event.clk & 0xffff);
    const uint8_t clk_8bit_limb = (uint8_t)(event.clk >> 16 & 0xff);
    cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
    cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);
}

template<class F>
__ZKM_HOSTDEV__ void
populate_instruction(InstructionCols<F>& self, const InstructionFfi& instruction) {
    self.opcode = F::from_canonical_u32((uint32_t)instruction.opcode);
    self.op_a = F::from_canonical_u32((uint32_t)instruction.op_a);
    write_word_from_u32_v2<F>(self.op_b, instruction.op_b);
    write_word_from_u32_v2<F>(self.op_c, instruction.op_c);

    self.op_a_0 = F::from_bool(instruction.op_a == 0);  // 0 = Register::X0
    self.imm_b = F::from_bool(instruction.imm_b);
    self.imm_c = F::from_bool(instruction.imm_c);
}

template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const CpuEventFfi& event,
    const uint32_t shard,
    const InstructionFfi& instruction,
    CpuCols<F>& cols
) {
    // Populate shard and clk columns.
    populate_shard_clk<F>(event, shard, cols);

    // Populate basic fields.
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);
    cols.next_next_pc = F::from_canonical_u32(event.next_next_pc);

    populate_instruction<F>(cols.instruction, instruction);

    cols.op_a_immutable = F::from_bool(
        is_memory_store_instruction_except_sc(instruction)
            || is_branch_instruction(instruction)
    );

    cols.is_rw_a = F::from_bool(is_rw_a_instruction(instruction));
    cols.is_check_memory = F::from_bool(
        is_mult_div_instruction(instruction) || is_check_memory_instruction(instruction)
    );

    write_word_from_u32_v2<F>(cols.op_a_value, event.a);
    if (event.hi.tag == OptionValTag::Some) {
        write_word_from_u32_v2<F>(cols.hi_or_prev_a, event.hi.value);
    }

    write_word_from_u32_v2<F>(cols.op_a_access.access.value, event.a);
    write_word_from_u32_v2<F>(cols.op_b_access.access.value, event.b);
    write_word_from_u32_v2<F>(cols.op_c_access.access.value, event.c);

    if (is_check_memory_instruction(instruction) || is_mult_div_instruction(instruction)) {
        cols.shard_to_send = cols.shard;
        cols.clk_to_send = F::from_canonical_u32(event.clk);
    }

    // Populate memory accesses for a, b, and c.
    memory::populate_read_write<F>(cols.op_a_access, event.a_record);
    if (event.b_record.tag == OptionMemoryRecordEnumTag::Read) {
        memory::populate_read<F>(cols.op_b_access, event.b_record.read);
    }
    if (event.c_record.tag == OptionMemoryRecordEnumTag::Read) {
        memory::populate_read<F>(cols.op_c_access, event.c_record.read);
    }

    bool is_halt = false;
    if (is_syscall_instruction(instruction)) {
        F syscall_id0 = cols.op_a_access.prev_value._0[0];
        F syscall_id1 = cols.op_a_access.prev_value._0[1];
        F num_extra_cycles = cols.op_a_access.prev_value._0[3];
        uint32_t sys_exit_group = (uint32_t)SyscallCode::SYS_EXT_GROUP & 0x0FFFF;
        is_halt = (syscall_id0 == F::from_canonical_u32((uint32_t)SyscallCode::HALT & 0x0FFFF)
            && syscall_id1 == F::zero())
            || (syscall_id0 == F::from_canonical_u8((uint8_t)sys_exit_group)
                && syscall_id1 == F::from_canonical_u8((uint8_t)(sys_exit_group >> 8)));
        cols.is_halt = F::from_bool(is_halt);
        cols.num_extra_cycles = num_extra_cycles;
    }

    cols.is_sequential = F::from_bool(
        !is_halt
            && !is_branch_instruction(instruction)
            && !is_jump_instruction(instruction)
    );

    // Assert that the instruction is not a no-op.
    cols.is_real = F::one();
}
}  // namespace zkm_core_machine_sys::cpu
