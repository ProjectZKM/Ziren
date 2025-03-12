use p3_air::AirBuilder;
use p3_field::FieldAlgebra;
use zkm2_core_executor::syscalls::SyscallCode;
use zkm2_stark::{
    air::{
        BaseAirBuilder, LookupScope, PublicValues, ZKMAirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS,
    },
    Word,
};

use crate::{
    air::WordAirBuilder,
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    memory::MemoryCols,
    operations::{IsZeroOperation, KoalaBearWordRangeChecker},
};

impl CpuChip {

    pub(crate) fn is_wsbh_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_wsbh.into()
    }
    /// Constraints related to the syscall opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_wsbh<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let is_wsbh_instruction = self.is_wsbh_instruction::<AB>(&local.selectors);

        builder
            .when(is_wsbh_instruction.clone())
            .assert_eq(local.op_a_val()[0], local.op_b_val()[1]);

        builder
            .when(is_wsbh_instruction.clone())
            .assert_eq(local.op_a_val()[1], local.op_b_val()[0]);

        builder
            .when(is_wsbh_instruction.clone())
            .assert_eq(local.op_a_val()[2], local.op_b_val()[3]);

        builder
            .when(is_wsbh_instruction.clone())
            .assert_eq(local.op_a_val()[3], local.op_b_val()[2]);
        
    }   
}
