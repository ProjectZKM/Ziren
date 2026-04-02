#pragma once

#include <cassert>
#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::branch {
template<class F>
__ZKM_HOSTDEV__ void event_to_row(const BranchEvent& event, BranchColumns<F>& cols) {
    cols.pc = F::from_canonical_u32(event.pc);

    cols.is_beq = F::from_bool(event.opcode == Opcode::BEQ);
    cols.is_bne = F::from_bool(event.opcode == Opcode::BNE);
    cols.is_bltz = F::from_bool(event.opcode == Opcode::BLTZ);
    cols.is_bgtz = F::from_bool(event.opcode == Opcode::BGTZ);
    cols.is_blez = F::from_bool(event.opcode == Opcode::BLEZ);
    cols.is_bgez = F::from_bool(event.opcode == Opcode::BGEZ);

    write_word_from_u32_v2<F>(cols.op_a_value, event.a);
    write_word_from_u32_v2<F>(cols.op_b_value, event.b);
    write_word_from_u32_v2<F>(cols.op_c_value, event.c);

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

    cols.a_lt_b = F::from_bool(a_lt_b);
    cols.a_gt_b = F::from_bool(a_gt_b);

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

    uint32_t target_pc = event.next_pc + event.c;
    write_word_from_u32_v2<F>(cols.next_pc, event.next_pc);
    write_word_from_u32_v2<F>(cols.target_pc, target_pc);
    write_word_from_u32_v2<F>(cols.next_next_pc, event.next_next_pc);
    populate_range_checker(cols.next_pc_range_checker, event.next_pc);
    populate_range_checker(cols.next_next_pc_range_checker, event.next_next_pc);
}
}  // namespace zkm::branch
