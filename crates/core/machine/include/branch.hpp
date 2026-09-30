#pragma once

#include <cassert>
#include "add_sub.hpp"
#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::branch {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(
    const BranchEvent& event,
    BranchColumns<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_alu_imm<BranchEvent, F>(cols.frame, event, instruction, shard);

    cols.pc = F::from_canonical_u32(event.pc);

    cols.is_beq = F::from_bool(event.opcode == Opcode::BEQ);
    cols.is_bne = F::from_bool(event.opcode == Opcode::BNE);
    cols.is_bltz = F::from_bool(event.opcode == Opcode::BLTZ);
    cols.is_bgtz = F::from_bool(event.opcode == Opcode::BGTZ);
    cols.is_blez = F::from_bool(event.opcode == Opcode::BLEZ);
    cols.is_bgez = F::from_bool(event.opcode == Opcode::BGEZ);


    bool a_eq_b = false;
    if (event.a == event.b) {
        a_eq_b = true;
    }
    bool a_lt_b = false;
    if ((int32_t)event.a < (int32_t)event.b) {
        a_lt_b = true;
    }
    bool a_gt_b = false;
    if ((int32_t)event.a > (int32_t)event.b) {
        a_gt_b = true;
    }

    // Equality gadget: IsZero of the two 16-bit limb differences.
    {
        const auto ab = u32_to_le_bytes(event.a);
        const auto bb = u32_to_le_bytes(event.b);
        const F two_pow_8 = F::from_canonical_u32(1 << 8);
        const F d_lo = F::from_canonical_u8(ab[0]) - F::from_canonical_u8(bb[0])
            + (F::from_canonical_u8(ab[1]) - F::from_canonical_u8(bb[1])) * two_pow_8;
        const F d_hi = F::from_canonical_u8(ab[2]) - F::from_canonical_u8(bb[2])
            + (F::from_canonical_u8(ab[3]) - F::from_canonical_u8(bb[3])) * two_pow_8;
        if (d_lo == F::zero()) {
            cols.eq_lo = F::one();
        } else {
            cols.eq_lo_inv = d_lo.reciprocal();
        }
        if (d_hi == F::zero()) {
            cols.eq_hi = F::one();
        } else {
            cols.eq_hi_inv = d_hi.reciprocal();
        }
        cols.a_eq_b = cols.eq_lo * cols.eq_hi;

        // Sign bit + a>0, only on the zero-compare rows (the byte events are
        // emitted by the Rust dependency pass).
        if (event.opcode == Opcode::BLTZ || event.opcode == Opcode::BLEZ
            || event.opcode == Opcode::BGTZ || event.opcode == Opcode::BGEZ) {
            const uint32_t msb = (event.a >> 31) & 1;
            cols.msb_a = F::from_canonical_u32(msb);
            cols.a_gt_0 = F::from_bool(msb == 0 && !a_eq_b);
        }
    }

    bool branching = false;
    if (event.opcode == Opcode::BEQ) {
        branching = a_eq_b;
    } else if (event.opcode == Opcode::BNE) {
        branching = !a_eq_b;
    } else if (event.opcode == Opcode::BLTZ) {
        branching = a_lt_b;
    } else if (event.opcode == Opcode::BLEZ) {
        branching = a_lt_b || a_eq_b;
    } else if (event.opcode == Opcode::BGTZ) {
        branching = a_gt_b;
    } else if (event.opcode == Opcode::BGEZ) {
        branching = a_eq_b || a_gt_b;
    }
    cols.is_branching = F::from_bool(branching);

    write_word_from_u32_v2<F>(cols.next_pc, event.next_pc);
    write_word_from_u32_v2<F>(cols.next_next_pc, event.next_next_pc);
    populate_range_checker(cols.next_pc_range_checker, event.next_pc);
    populate_range_checker(cols.next_next_pc_range_checker, event.next_next_pc);

    // The (when taken) target addition — mirrors control_flow/branch/trace.rs.
    if (branching) {
        add_sub::populate<F>(cols.target_add, event.next_pc, event.c);
    }
}
}  // namespace zkm::branch
