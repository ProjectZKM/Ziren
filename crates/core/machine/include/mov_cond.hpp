#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::mov_cond {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const MovCondEvent& event, MovCondCols<F>& cols) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        write_word_from_u32_v2<F>(cols.op_a_value, event.a);
        write_word_from_u32_v2<F>(cols.op_b_value, event.b);
        write_word_from_u32_v2<F>(cols.op_c_value, event.c);
        write_word_from_u32_v2<F>(cols.prev_a_value, event.prev_a);

        populate_is_zero_word_operaion(cols.c_eq_0, u32_to_word<F>(event.c));

        cols.is_meq = F::from_bool(event.opcode == Opcode::MEQ);
        cols.is_mne = F::from_bool(event.opcode == Opcode::MNE);
        cols.is_wsbh = F::from_bool(event.opcode == Opcode::WSBH);
    }
}  // namespace zkm::mov_cond
