#pragma once

#include "frame.hpp"
#include "prelude.hpp"
#include "utils.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::mov_cond {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(
    const MovCondEvent& event,
    MovCondCols<F>& cols,
    const InstructionFfi& instruction,
    const uint32_t shard
) {
    // Every row is a real instruction owning its frame.
    frame::populate_from_movcond<F>(cols.frame, event, instruction, shard);

        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        cols.is_meq = F::from_bool(event.opcode == Opcode::MEQ);
        cols.is_mne = F::from_bool(event.opcode == Opcode::MNE);
        cols.is_wsbh = F::from_bool(event.opcode == Opcode::WSBH);

        // Mirrors misc/mov_cond/mod.rs: the c == 0 limb IsZeros and the
        // fired-move selector, on the conditional-move rows only.
        if (event.opcode != Opcode::WSBH) {
            const auto cb = u32_to_le_bytes(event.c);
            const F c_lo = F::from_canonical_u32((uint32_t)cb[0] + ((uint32_t)cb[1] << 8));
            const F c_hi = F::from_canonical_u32((uint32_t)cb[2] + ((uint32_t)cb[3] << 8));
            if (c_lo == F::zero()) {
                cols.c_eq_lo = F::one();
            } else {
                cols.c_eq_lo_inv = c_lo.reciprocal();
            }
            if (c_hi == F::zero()) {
                cols.c_eq_hi = F::one();
            } else {
                cols.c_eq_hi_inv = c_hi.reciprocal();
            }
            cols.c_eq_0 = cols.c_eq_lo * cols.c_eq_hi;
            const bool fired =
                (event.opcode == Opcode::MEQ) ? (event.c == 0) : (event.c != 0);
            cols.sel_moved = F::from_bool(fired);
        }
    }
}  // namespace zkm::mov_cond
