use std::borrow::BorrowMut;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, MiscEvent},
    ByteOpcode, ExecutionRecord, Opcode, Program,
};
use zkm_stark::{air::MachineAir, Word};

use crate::utils::{next_power_of_two, zeroed_f_vec};

use super::{
    columns::{MiscInstrColumns, NUM_MISC_INSTR_COLS},
    MiscInstrsChip,
};

impl<F: PrimeField32> MachineAir<F> for MiscInstrsChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MiscInstrs".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let chunk_size = std::cmp::max((input.misc_events.len()) / num_cpus::get(), 1);
        let nb_rows = input.misc_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_power_of_two(nb_rows, size_log2);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MISC_INSTR_COLS);

        let blu_events = values
            .chunks_mut(chunk_size * NUM_MISC_INSTR_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_MISC_INSTR_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut MiscInstrColumns<F> = row.borrow_mut();

                    if idx < input.misc_events.len() {
                        let event = &input.misc_events[idx];
                        self.event_to_row(event, cols, &mut blu);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MISC_INSTR_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.misc_events.is_empty()
        }
    }
}

impl MiscInstrsChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MiscEvent,
        cols: &mut MiscInstrColumns<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);

        cols.op_a_value = event.a.into();
        cols.op_b_value = event.b.into();
        cols.op_c_value = event.c.into();
        cols.prev_a_value = event.prev_a.into();
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);

        cols.is_sext = F::from_bool(matches!(event.opcode, Opcode::SEXT));
        cols.is_ext = F::from_bool(matches!(event.opcode, Opcode::EXT));
        cols.is_ins = F::from_bool(matches!(event.opcode, Opcode::INS));
        cols.is_maddu = F::from_bool(matches!(event.opcode, Opcode::MADDU));
        cols.is_msubu = F::from_bool(matches!(event.opcode, Opcode::MSUBU));
        cols.is_madd = F::from_bool(matches!(event.opcode, Opcode::MADD));
        cols.is_msub = F::from_bool(matches!(event.opcode, Opcode::MSUB));
        cols.is_teq = F::from_bool(matches!(event.opcode, Opcode::TEQ));

        self.populate_sext(cols, event, blu);
        self.populate_maddsub(cols, event, blu);
        self.populate_ext(cols, event, blu);
        self.populate_ins(cols, event, blu);
    }

    fn populate_sext<F: PrimeField32>(
        &self,
        cols: &mut MiscInstrColumns<F>,
        event: &MiscEvent,
        blu: &mut impl ByteRecord,
    ) {
        if !matches!(event.opcode, Opcode::SEXT | Opcode::TEQ) {
            return;
        }
        let sext_cols = cols.misc_specific_columns.sext_mut();

        let (sig_bit, sig_byte) = if event.c > 0 {
            sext_cols.is_seh = F::ONE;
            ((event.b as u16) >> 15, (event.b >> 8 & 0xff) as u8)
        } else {
            sext_cols.is_seb = F::ONE;
            (((event.b as u8) >> 7) as u16, event.b as u8)
        };
        sext_cols.most_sig_bit = F::from_canonical_u16(sig_bit);
        sext_cols.sig_byte = F::from_canonical_u8(sig_byte);

        sext_cols.a_eq_b = F::from_bool(event.b == event.a);

        if matches!(event.opcode, Opcode::SEXT) {
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::MSB,
                a1: sig_bit,
                a2: 0,
                b: sig_byte,
                c: 0,
            });
        }
    }

    fn populate_maddsub<F: PrimeField32>(
        &self,
        cols: &mut MiscInstrColumns<F>,
        event: &MiscEvent,
        blu: &mut impl ByteRecord,
    ) {
        if !matches!(event.opcode, Opcode::MADDU | Opcode::MSUBU | Opcode::MADD | Opcode::MSUB) {
            return;
        }

        let is_sign = event.opcode == Opcode::MADD || event.opcode == Opcode::MSUB;
        let maddsub_cols = cols.misc_specific_columns.maddsub_mut();
        let multiply = if is_sign {
            ((event.b as i32 as i64) * (event.c as i32 as i64)) as u64
        } else {
            event.b as u64 * event.c as u64
        };
        let mul_hi = (multiply >> 32) as u32;
        let mul_lo = multiply as u32;
        maddsub_cols.mul_hi = Word::from(mul_hi);
        maddsub_cols.mul_lo = Word::from(mul_lo);

        let is_add = event.opcode == Opcode::MADDU || event.opcode == Opcode::MADD;
        let src2_lo = if is_add { event.prev_a } else { event.a };
        let src2_hi = if is_add { event.hi_record.prev_value } else { event.hi_record.value };
        let _ = maddsub_cols.add_operation.populate(
            blu,
            multiply,
            ((src2_hi as u64) << 32) + (src2_lo as u64),
        );
        maddsub_cols.src2_lo = Word::from(src2_lo);
        maddsub_cols.src2_hi = Word::from(src2_hi);

        // For maddu/msubu instructions, pass in a dummy byte lookup vector.
        // This maddu/msubu instruction chip also has a op_hi_access field that will be
        // populated and that will contribute to the byte lookup dependencies.
        maddsub_cols.op_hi_access.populate(MemoryRecordEnum::Write(event.hi_record), blu);
    }

    fn populate_ext<F: PrimeField32>(
        &self,
        cols: &mut MiscInstrColumns<F>,
        event: &MiscEvent,
        blu: &mut impl ByteRecord,
    ) {
        if !matches!(event.opcode, Opcode::EXT) {
            return;
        }
        let ext_cols = cols.misc_specific_columns.ext_mut();
        let lsb = event.c & 0x1f;
        let msbd = event.c >> 5;
        let shift_left = event.b << (31 - lsb - msbd);
        ext_cols.lsb = F::from_canonical_u32(lsb);
        ext_cols.msbd = F::from_canonical_u32(msbd);
        ext_cols.sll_val = Word::from(shift_left);
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: lsb as u8,
            c: msbd as u8,
        });
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: 1,
            a2: 0,
            b: (lsb + msbd) as u8,
            c: 32,
        });
    }

    fn populate_ins<F: PrimeField32>(
        &self,
        cols: &mut MiscInstrColumns<F>,
        event: &MiscEvent,
        blu: &mut impl ByteRecord,
    ) {
        if !matches!(event.opcode, Opcode::INS) {
            return;
        }
        let ins_cols = cols.misc_specific_columns.ins_mut();
        let lsb = event.c & 0x1f;
        let msb = event.c >> 5;
        let ror_val = event.prev_a.rotate_right(lsb);
        let srl_val = ror_val >> (msb - lsb + 1);
        let sll_val = event.b << (31 - msb + lsb);
        let add_val = srl_val + sll_val;
        ins_cols.lsb = F::from_canonical_u32(lsb);
        ins_cols.msb = F::from_canonical_u32(msb);
        ins_cols.ror_val = Word::from(ror_val);
        ins_cols.srl_val = Word::from(srl_val);
        ins_cols.sll_val = Word::from(sll_val);
        ins_cols.add_val = Word::from(add_val);
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::U8Range,
            a1: 0,
            a2: 0,
            b: lsb as u8,
            c: msb as u8,
        });

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: 1,
            a2: 0,
            b: lsb as u8,
            c: (msb + 1) as u8,
        });

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: 1,
            a2: 0,
            b: msb as u8,
            c: 32,
        });
    }
}
