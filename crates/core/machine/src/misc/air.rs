use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm2_core_executor::{
    Opcode, DEFAULT_PC_INC,
};
use zkm2_stark::{
    air::{
        BaseAirBuilder, LookupScope, PublicValues, ZKMAirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS, ZKM_PROOF_NUM_PV_ELTS,
    },
    Word,
};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{KoalaBearWordRangeChecker, IsZeroOperation},
};

use super::{columns::MiscInstrColumns, MiscInstrsChip};

impl<AB> Air<AB> for MiscInstrsChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MiscInstrColumns<AB::Var> = (*local).borrow();

        let cpu_opcode = local.is_wsbh * Opcode::WSBH.as_field::<AB::F>()
            + local.is_seb * Opcode::SEXT.as_field::<AB::F>()
            + local.is_ins * Opcode::INS.as_field::<AB::F>()
            + local.is_ext * Opcode::EXT.as_field::<AB::F>()
            + local.is_maddu * Opcode::MADDU.as_field::<AB::F>()
            + local.is_msubu * Opcode::MSUBU.as_field::<AB::F>()
            + local.is_meq * Opcode::MEQ.as_field::<AB::F>()
            + local.is_mne * Opcode::MNE.as_field::<AB::F>()
            + local.is_nop * Opcode::NOP.as_field::<AB::F>()
            + local.is_teq * Opcode::TEQ.as_field::<AB::F>();
            
        // SAFETY: This checks the following.
        // - `shard`, `clk` are correctly received from the CpuChip
        // - `op_a_0 = 0` enforced, as `op_a = X5` for all SYSCALL
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // `next_pc`, `num_extra_cycles`, `op_a_val`, `is_halt` need to be constrained. We outline the checks below.
        // `next_pc` is constrained for the case where `is_halt` is true to be `0` in `eval_is_halt_unimpl`.
        // `next_pc` is constrained for the case where `is_halt` is false to be `pc + 4` in `eval`.
        // `num_extra_cycles` is checked to be equal to the return value of `get_num_extra_ecall_cycles`, in `eval`.
        // `op_a_val` is constrained in `eval_syscall`.
        // `is_halt` is checked to be correct in `eval_is_halt_syscall`.
        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.pc + AB::Expr::from_canonical_u32(DEFAULT_PC_INC),
            AB::Expr::ZERO,
            cpu_opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.op_hi_value,
            local.op_a_0,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.is_real,
        );

        self.eval_wsbh(builder, local);
    }

}

impl MiscInstrsChip {
    pub(crate) fn eval_wsbh<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[0], local.op_b_value[1]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[1], local.op_b_value[0]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[2], local.op_b_value[3]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[3], local.op_b_value[2]);
    }
}
