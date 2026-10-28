use columns::NUM_SYSCALL_INSTR_COLS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct SyscallInstrsChip;

impl<F> BaseAir<F> for SyscallInstrsChip {
    fn width(&self) -> usize {
        NUM_SYSCALL_INSTR_COLS
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::{Borrow, BorrowMut};

    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use zkm_core_executor::{
        syscalls::SyscallCode, ByteOpcode, ExecutionRecord, Executor, Instruction, Opcode, Program,
    };
    use zkm_pcs::{
        air::{MachineAir, ZKM_PROOF_NUM_PV_ELTS},
        constraints_hold_on_row, Chip, LookupKind, ZKMCoreOpts,
    };

    use super::{columns::SyscallInstrColumns, SyscallInstrsChip};

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    /// The `SYSCALL` row of one call of `code` with arguments `a0`, `a1`.
    fn syscall_row(code: SyscallCode, a0: u32, a1: u32) -> Vec<F> {
        let program = Program::new(
            vec![
                Instruction::new(Opcode::ADD, 2, 0, code as u32, false, true),
                Instruction::new(Opcode::ADD, 4, 0, a0, false, true),
                Instruction::new(Opcode::ADD, 5, 0, a1, false, true),
                Instruction::new(Opcode::SYSCALL, 2, 4, 5, false, false),
            ],
            0,
            0,
        );
        let mut runtime = Executor::new(program, ZKMCoreOpts::default());
        runtime.run().unwrap();
        let record = runtime.records.iter().find(|r| !r.syscall_events.is_empty()).unwrap();
        let trace: RowMajorMatrix<F> =
            SyscallInstrsChip.generate_trace(record, &mut ExecutionRecord::default()).unwrap();
        (0..trace.height())
            .map(|i| trace.row_slice(i).unwrap().to_vec())
            .find(|row| {
                let cols: &SyscallInstrColumns<F> = row.as_slice().borrow();
                cols.is_real == F::ONE && cols.syscall_id == F::from_u32(code.syscall_id())
            })
            .unwrap()
    }

    fn holds(row: &[F]) -> bool {
        constraints_hold_on_row::<F, EF, _>(
            &SyscallInstrsChip,
            row,
            row,
            &[F::ZERO; ZKM_PROOF_NUM_PV_ELTS],
        )
    }

    /// The `(b, c)` operands of the U8Range lookups the row sends.
    fn u8_range_sends(row: &[F]) -> Vec<(F, F)> {
        let chip = Chip::<F, _>::new(SyscallInstrsChip);
        chip.sends()
            .iter()
            .filter(|lookup| {
                lookup.kind == LookupKind::Byte
                    && lookup.multiplicity.apply::<F, F>(&[], row) != F::ZERO
            })
            .map(|lookup| lookup.values.iter().map(|v| v.apply::<F, F>(&[], row)).collect())
            .filter(|values: &Vec<F>| values[0] == F::from_u8(ByteOpcode::U8Range as u8))
            .map(|values| (values[3], values[4]))
            .collect()
    }

    #[test]
    fn extra_cycles_are_byte_checked_on_an_honest_row() {
        let row = syscall_row(SyscallCode::SHA_EXTEND, 100, 0);
        let cols: &SyscallInstrColumns<F> = row.as_slice().borrow();
        assert_eq!(cols.num_extra_cycles, F::from_u32(48));
        assert!(holds(&row));
        assert!(u8_range_sends(&row).contains(&(F::ONE, F::from_u32(48))));
    }

    /// A Linux syscall writes a result to op_a, so nothing but the byte check
    /// ties byte 3 of the incoming code.  A non-byte value there, including
    /// `p - 5`, which makes the State step `clk -> clk`, satisfies the row's
    /// local equations and is sent to the byte table, which cannot match it.
    #[test]
    fn non_byte_extra_cycles_are_rejected_by_the_byte_lookup() {
        for forged in [-F::from_u32(5), F::from_u32(256), F::from_u32(1 << 20)] {
            let mut row = syscall_row(SyscallCode::SYS_FCNTL, 1, 1);
            let cols: &mut SyscallInstrColumns<F> = row.as_mut_slice().borrow_mut();
            assert_eq!(cols.is_sys_linux, F::ONE);
            cols.frame.op_a_access.prev_value[3] = forged;
            cols.num_extra_cycles = forged;
            assert!(holds(&row), "local equations, extra = {forged}");
            assert!(
                u8_range_sends(&row).contains(&(F::ZERO, forged)),
                "extra = {forged} is not sent to the byte table"
            );
            assert!(forged.as_canonical_u32() > 255);
        }
    }
}
