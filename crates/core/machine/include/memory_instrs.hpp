#pragma once

#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"
#include "memory.hpp"
#include "add_sub.hpp"
#include "kb31_septic_extension_t.hpp"

// Device mirror of `crates/core/machine/src/memory/instructions/`.
//
// The former 79-column `MemoryInstructionsColumns` union is split into five
// per-width chips, each embedding `MemoryInstrCommonCols`.  Every function here
// must produce byte-identical columns to the corresponding Rust `event_to_row`;
// the byte-lookup events are still emitted by the Rust side (the GPU path runs
// the host `generate_dependencies` pass for them), so only column values matter.
namespace zkm_core_machine_sys::memory_instrs {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint32_t
mem_value_of(const MemInstrEvent& event) {
    return event.mem_access.tag == MemoryRecordEnum::Tag::Read
               ? event.mem_access.read._0.value
               : event.mem_access.write._0.value;
}

/// Mirrors `MemoryInstrCommonCols::populate`.  Returns `addr & 0b11`.
template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ uint8_t
populate_common(
    MemoryInstrCommonCols<F>& cols,
    const MemInstrEvent& event,
    const InstructionFfi& instruction
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_mem<F>(cols.frame, event, instruction);

    cols.shard = F::from_canonical_u32(event.shard);
    assert(cols.shard != F::zero());
    cols.clk = F::from_canonical_u32(event.clk);
    cols.pc = F::from_canonical_u32(event.pc);
    cols.next_pc = F::from_canonical_u32(event.next_pc);
    write_word_from_u32_v2<F>(cols.op_a_value, event.a);
    write_word_from_u32_v2<F>(cols.op_b_value, event.b);
    write_word_from_u32_v2<F>(cols.op_c_value, event.c);
    write_word_from_u32_v2<F>(cols.prev_a_val, event.prev_a_val);

    // Memory consistency columns for the memory access.
    memory::populate_read_write_v2<F>(cols.memory_access, event.mem_access);

    // Inline effective-address addition: `addr_add.value = op_b + op_c`.
    const uint32_t memory_addr = add_sub::populate<F>(cols.addr_add, event.b, event.c);
    populate_range_checker(cols.addr_word_range_checker, memory_addr);

    const uint8_t addr_ls_two_bits = (uint8_t)(memory_addr % WORD_SIZE);
    cols.addr_ls_two_bits = F::from_canonical_u8(addr_ls_two_bits);

    populate_is_zero_operation(
        cols.most_sig_bytes_zero,
        cols.addr_add.value._0[1] + cols.addr_add.value._0[2] + cols.addr_add.value._0[3]
    );

    return addr_ls_two_bits;
}

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
populate_offset_flags(F& one, F& two, F& three, const uint8_t addr_ls_two_bits) {
    one = F::from_bool(addr_ls_two_bits == 1);
    two = F::from_bool(addr_ls_two_bits == 2);
    three = F::from_bool(addr_ls_two_bits == 3);
}

/// `LB`, `LBU`, `LH`, `LHU`.
template<class F>
__ZKM_HOSTDEV__ void
load_narrow_event_to_row(
    const MemInstrEvent& event,
    LoadNarrowColumns<F>& cols,
    const InstructionFfi& instruction
) {
    const uint8_t addr_ls_two_bits = populate_common<F>(cols.common, event, instruction);
    populate_offset_flags<F>(
        cols.ls_bits_is_one, cols.ls_bits_is_two, cols.ls_bits_is_three, addr_ls_two_bits);

    const uint32_t mem_value = mem_value_of<F>(event);

    uint8_t val_lo = 0;
    uint8_t val_hi = 0;
    if (event.opcode == Opcode::LB || event.opcode == Opcode::LBU) {
        const auto le_bytes = u32_to_le_bytes(mem_value);
        val_lo = le_bytes[addr_ls_two_bits];
        val_hi = 0;
    } else {
        // LH / LHU: the offset is 0 or 2.
        uint32_t half = ((addr_ls_two_bits >> 1) % 2) == 0
                            ? (mem_value & 0x0000FFFFu)
                            : ((mem_value & 0xFFFF0000u) >> 16);
        const auto le_bytes = u32_to_le_bytes(half);
        val_lo = le_bytes[0];
        val_hi = le_bytes[1];
    }
    cols.val_lo = F::from_canonical_u8(val_lo);
    cols.val_hi = F::from_canonical_u8(val_hi);

    if (event.opcode == Opcode::LB || event.opcode == Opcode::LH) {
        const uint8_t most_sig_byte = (event.opcode == Opcode::LB) ? val_lo : val_hi;
        cols.most_sig_byte = F::from_canonical_u8(most_sig_byte);
        cols.most_sig_bit = F::from_canonical_u8((uint8_t)(most_sig_byte >> 7));
    } else {
        cols.most_sig_byte = F::zero();
        cols.most_sig_bit = F::zero();
    }

    cols.is_lb = F::from_bool(event.opcode == Opcode::LB);
    cols.is_lbu = F::from_bool(event.opcode == Opcode::LBU);
    cols.is_lh = F::from_bool(event.opcode == Opcode::LH);
    cols.is_lhu = F::from_bool(event.opcode == Opcode::LHU);
}

/// `LW`, `LL`.
template<class F>
__ZKM_HOSTDEV__ void
load_word_event_to_row(
    const MemInstrEvent& event,
    LoadWordColumns<F>& cols,
    const InstructionFfi& instruction
) {
    populate_common<F>(cols.common, event, instruction);
    cols.is_lw = F::from_bool(event.opcode == Opcode::LW);
    cols.is_ll = F::from_bool(event.opcode == Opcode::LL);
}

/// `SB`, `SH`.
template<class F>
__ZKM_HOSTDEV__ void
store_narrow_event_to_row(
    const MemInstrEvent& event,
    StoreNarrowColumns<F>& cols,
    const InstructionFfi& instruction
) {
    const uint8_t addr_ls_two_bits = populate_common<F>(cols.common, event, instruction);
    populate_offset_flags<F>(
        cols.ls_bits_is_one, cols.ls_bits_is_two, cols.ls_bits_is_three, addr_ls_two_bits);
    cols.is_sb = F::from_bool(event.opcode == Opcode::SB);
    cols.is_sh = F::from_bool(event.opcode == Opcode::SH);
}

/// `SW`, `SC`.
template<class F>
__ZKM_HOSTDEV__ void
store_word_event_to_row(
    const MemInstrEvent& event,
    StoreWordColumns<F>& cols,
    const InstructionFfi& instruction
) {
    populate_common<F>(cols.common, event, instruction);
    cols.is_sw = F::from_bool(event.opcode == Opcode::SW);
    cols.is_sc = F::from_bool(event.opcode == Opcode::SC);
}

/// `LWL`, `LWR`, `SWL`, `SWR`.
template<class F>
__ZKM_HOSTDEV__ void
unaligned_event_to_row(
    const MemInstrEvent& event,
    MemoryUnalignedColumns<F>& cols,
    const InstructionFfi& instruction
) {
    const uint8_t addr_ls_two_bits = populate_common<F>(cols.common, event, instruction);
    populate_offset_flags<F>(
        cols.ls_bits_is_one, cols.ls_bits_is_two, cols.ls_bits_is_three, addr_ls_two_bits);
    cols.is_lwl = F::from_bool(event.opcode == Opcode::LWL);
    cols.is_lwr = F::from_bool(event.opcode == Opcode::LWR);
    cols.is_swl = F::from_bool(event.opcode == Opcode::SWL);
    cols.is_swr = F::from_bool(event.opcode == Opcode::SWR);
}

}  // namespace zkm_core_machine_sys::memory_instrs
