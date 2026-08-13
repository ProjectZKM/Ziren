use crate::{
    events::{
        AluEvent, BranchEvent, CompAluEvent, JumpEvent, MemoryWriteRecord, MiscEvent,
    },
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode, DEFAULT_PC_INC, UNUSED_PC,
};

/// Emits the dependencies for division and remainder operations.
#[allow(clippy::too_many_lines)]
pub fn emit_divrem_dependencies(executor: &mut Executor, event: AluEvent) {
    let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
    let c_msb = get_msb(event.c);
    let rem_msb = get_msb(remainder);
    let mut c_neg = 0;
    let mut rem_neg = 0;
    let is_signed_operation = is_signed_operation(event.opcode);
    if is_signed_operation {
        c_neg = c_msb; // same as abs_c_alu_event
        rem_neg = rem_msb; // same as abs_rem_alu_event
    }

    if c_neg == 1 {
        executor.record.add_sub_events.push(AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            ..Default::default()
        });
    }
    if rem_neg == 1 {
        executor.record.add_sub_events.push(AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            ..Default::default()
        });
    }

    let c_times_quotient = {
        if is_signed_operation {
            (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
        } else {
            ((quotient as u64) * (event.c as u64)).to_le_bytes()
        }
    };
    let lower_word = u32::from_le_bytes(c_times_quotient[0..4].try_into().unwrap());
    let upper_word = u32::from_le_bytes(c_times_quotient[4..8].try_into().unwrap());

    let multiplication = CompAluEvent {
        clk: 0,
        shard: 0,
        pc: UNUSED_PC,
        next_pc: UNUSED_PC + DEFAULT_PC_INC,
        opcode: {
            if is_signed_operation {
                Opcode::MULT
            } else {
                Opcode::MULTU
            }
        },
        a: lower_word,
        c: event.c,
        b: quotient,
        hi: upper_word,
        hi_record_is_real: false,
        hi_record: MemoryWriteRecord::default(),
        // Synthetic dependency event: no frame.
        is_instruction: 0,
        next_next_pc: 0,
        recv_next_pc: 0,
        a_record: None.into(),
        b_record: None.into(),
        c_record: None.into(),
    };
    executor.record.mul_events.push(multiplication);

    let lt_event = if is_signed_operation {
        AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SLTU,
            hi: 0,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            ..Default::default()
        }
    } else {
        AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SLTU,
            hi: 0,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            ..Default::default()
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Emits the dependencies for clo and clz operations.
#[allow(clippy::too_many_lines)]
pub fn emit_cloclz_dependencies(executor: &mut Executor, event: AluEvent) {
    let b = if event.opcode == Opcode::CLZ { event.b } else { !event.b };
    if b != 0 {
        let srl_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SRL,
            hi: 0,
            a: b >> (31 - event.a),
            b,
            c: 31 - event.a,
            ..Default::default()
        };

        executor.record.shift_right_events.push(srl_event);
    }
}



/// Emit the dependencies for misc instructions.
pub fn emit_misc_dependencies(executor: &mut Executor, event: MiscEvent) {
    if matches!(event.opcode, Opcode::MADDU | Opcode::MSUBU) {
        let multiply = event.b as u64 * event.c as u64;
        let mul_hi = (multiply >> 32) as u32;
        let mul_lo = multiply as u32;
        let mul_event = CompAluEvent {
            clk: 0,
            shard: 0,
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::MULTU,
            hi: mul_hi,
            a: mul_lo,
            b: event.b,
            c: event.c,
            hi_record_is_real: false,
            hi_record: MemoryWriteRecord::default(),
        // Synthetic dependency event: no frame.
        is_instruction: 0,
        next_next_pc: 0,
        recv_next_pc: 0,
        a_record: None.into(),
        b_record: None.into(),
        c_record: None.into(),
    };
        executor.record.add_mul_event(mul_event);
    } else if matches!(event.opcode, Opcode::MADD | Opcode::MSUB) {
        let multiply = ((event.b as i32 as i64) * (event.c as i32 as i64)) as u64;
        let mul_hi = (multiply >> 32) as u32;
        let mul_lo = multiply as u32;
        let mul_event = CompAluEvent {
            clk: 0,
            shard: 0,
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::MULT,
            hi: mul_hi,
            a: mul_lo,
            b: event.b,
            c: event.c,
            hi_record_is_real: false,
            hi_record: MemoryWriteRecord::default(),
        // Synthetic dependency event: no frame.
        is_instruction: 0,
        next_next_pc: 0,
        recv_next_pc: 0,
        a_record: None.into(),
        b_record: None.into(),
        c_record: None.into(),
    };
        executor.record.add_mul_event(mul_event);
    } else if matches!(event.opcode, Opcode::EXT) {
        let lsb = event.c & 0x1f;
        let msbd = event.c >> 5;
        // `execute_ext` rejects encodings with `lsb + msbd >= 32`, so the `31 - lsb - msbd`
        // shift amounts below cannot underflow.
        debug_assert!(
            lsb + msbd < 32,
            "EXT with lsb + msbd >= 32 must be rejected during execution"
        );
        let sll_val = event.b << (31 - lsb - msbd);
        let sll_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SLL,
            hi: 0,
            a: sll_val,
            b: event.b,
            c: 31 - lsb - msbd,
            ..Default::default()
        };
        executor.record.shift_left_events.push(sll_event);
        let srl_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SRL,
            hi: 0,
            a: event.a,
            b: sll_val,
            c: 31 - msbd,
            ..Default::default()
        };
        assert_eq!(event.a, sll_val >> (31 - msbd));
        executor.record.shift_right_events.push(srl_event);
    } else if matches!(event.opcode, Opcode::INS) {
        let lsb = event.c & 0x1f;
        let msb = event.c >> 5;
        let ror_val = event.prev_a.rotate_right(lsb);
        let ror_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ROR,
            hi: 0,
            a: ror_val,
            b: event.prev_a,
            c: lsb,
            ..Default::default()
        };
        executor.record.shift_right_events.push(ror_event);

        let srl1_val = ror_val >> 1;
        let srl1_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SRL,
            hi: 0,
            a: srl1_val,
            b: ror_val,
            c: 1,
            ..Default::default()
        };
        executor.record.shift_right_events.push(srl1_event);

        let srl_val = srl1_val >> (msb - lsb);
        let srl_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SRL,
            hi: 0,
            a: srl_val,
            b: srl1_val,
            c: msb - lsb,
            ..Default::default()
        };
        executor.record.shift_right_events.push(srl_event);

        let sll_val = event.b << (31 - msb + lsb);
        let sll_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SLL,
            hi: 0,
            a: sll_val,
            b: event.b,
            c: 31 - msb + lsb,
            ..Default::default()
        };
        executor.record.shift_left_events.push(sll_event);

        let extra_shift = srl_val + sll_val;
        let add_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: extra_shift,
            b: srl_val,
            c: sll_val,
            ..Default::default()
        };
        executor.record.add_sub_events.push(add_event);

        let ror_event2 = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ROR,
            hi: 0,
            a: event.a,
            b: extra_shift,
            c: 31 - msb,
            ..Default::default()
        };
        assert_eq!(event.a, extra_shift.rotate_right(31 - msb));
        executor.record.shift_right_events.push(ror_event2);
    }
}
