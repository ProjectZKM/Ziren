use crate::{
    events::{
        AluEvent, BranchEvent, CompAluEvent, JumpEvent, MemInstrEvent, MemoryRecord,
        MemoryWriteRecord, MiscEvent,
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
        executor.record.add_events.push(AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
        });
    }
    if rem_neg == 1 {
        executor.record.add_events.push(AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
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
        };

        executor.record.shift_right_events.push(srl_event);
    }
}

/// Emit the dependencies for memory instructions.
pub fn emit_memory_dependencies(
    executor: &mut Executor,
    event: MemInstrEvent,
    memory_record: MemoryRecord,
) {
    let memory_addr = event.b.wrapping_add(event.c);
    // Add event to ALU check to check that addr == b + c
    let add_event = AluEvent {
        pc: UNUSED_PC,
        next_pc: UNUSED_PC + DEFAULT_PC_INC,
        opcode: Opcode::ADD,
        hi: 0,
        a: memory_addr,
        b: event.b,
        c: event.c,
    };
    executor.record.add_events.push(add_event);
    let addr_offset = (memory_addr % 4_u32) as u8;
    let mem_value = memory_record.value;

    if matches!(event.opcode, Opcode::LB | Opcode::LH) {
        let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match event.opcode {
            Opcode::LB => {
                let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
                let sign_value = 256;
                (most_sig_mem_value_byte as u32, most_sig_mem_value_byte, sign_value)
            }
            Opcode::LH => {
                let sign_value = 65536;
                let unsigned_mem_val = match (addr_offset >> 1) % 2 {
                    0 => mem_value & 0x0000FFFF,
                    1 => (mem_value & 0xFFFF0000) >> 16,
                    _ => unreachable!(),
                };
                let most_sig_mem_value_byte = unsigned_mem_val.to_le_bytes()[1];
                (unsigned_mem_val, most_sig_mem_value_byte, sign_value)
            }
            _ => unreachable!(),
        };

        if most_sig_mem_value_byte >> 7 & 0x01 == 1 {
            let sub_event = AluEvent {
                pc: UNUSED_PC,
                next_pc: UNUSED_PC + DEFAULT_PC_INC,
                opcode: Opcode::SUB,
                hi: 0,
                a: event.a,
                b: unsigned_mem_val,
                c: sign_value,
            };
            executor.record.add_events.push(sub_event);
        }
    }
}

/// Emit the dependencies for branch instructions.
pub fn emit_branch_dependencies(executor: &mut Executor, event: BranchEvent) {
    let a_eq_b = event.a == event.b;
    let a_lt_b = (event.a as i32) < (event.b as i32);
    let a_gt_b = (event.a as i32) > (event.b as i32);

    let lt_comp_event = AluEvent {
        pc: UNUSED_PC,
        next_pc: UNUSED_PC + DEFAULT_PC_INC,
        opcode: Opcode::SLT,
        hi: 0,
        a: a_lt_b as u32,
        b: event.a,
        c: event.b,
    };
    let gt_comp_event = AluEvent {
        pc: UNUSED_PC,
        next_pc: UNUSED_PC + DEFAULT_PC_INC,
        opcode: Opcode::SLT,
        hi: 0,
        a: a_gt_b as u32,
        b: event.b,
        c: event.a,
    };
    executor.record.lt_events.push(lt_comp_event);
    executor.record.lt_events.push(gt_comp_event);
    let branching = match event.opcode {
        Opcode::BEQ => a_eq_b,
        Opcode::BNE => !a_eq_b,
        Opcode::BLTZ => a_lt_b,
        Opcode::BLEZ => a_lt_b || a_eq_b,
        Opcode::BGTZ => a_gt_b,
        Opcode::BGEZ => a_eq_b || a_gt_b,
        _ => unreachable!(),
    };
    if branching {
        let add_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ADD,
            hi: 0,
            a: event.next_next_pc,
            b: event.next_pc,
            c: event.c,
        };
        executor.record.add_events.push(add_event);
    }
}

/// Emit the dependencies for jump instructions.
pub fn emit_jump_dependencies(executor: &mut Executor, event: JumpEvent) {
    match event.opcode {
        Opcode::JumpDirect => {
            let target_pc = event.next_pc.wrapping_add(event.b);
            let add_event = AluEvent {
                pc: UNUSED_PC,
                next_pc: UNUSED_PC + DEFAULT_PC_INC,
                opcode: Opcode::ADD,
                hi: 0,
                a: target_pc,
                b: event.next_pc,
                c: event.b,
            };
            executor.record.add_events.push(add_event);
        }
        Opcode::Jump | Opcode::Jumpi => {}
        _ => unreachable!(),
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
        };
        executor.record.add_mul_event(mul_event);
    } else if matches!(event.opcode, Opcode::EXT) {
        let lsb = event.c & 0x1f;
        let msbd = event.c >> 5;
        let sll_val = event.b << (31 - lsb - msbd);
        let sll_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SLL,
            hi: 0,
            a: sll_val,
            b: event.b,
            c: 31 - lsb - msbd,
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
        };
        executor.record.shift_right_events.push(ror_event);

        let srl_val = ror_val >> (msb - lsb + 1);
        let srl_event = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::SRL,
            hi: 0,
            a: srl_val,
            b: ror_val,
            c: msb - lsb + 1,
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
        };
        executor.record.add_events.push(add_event);

        let ror_event2 = AluEvent {
            pc: UNUSED_PC,
            next_pc: UNUSED_PC + DEFAULT_PC_INC,
            opcode: Opcode::ROR,
            hi: 0,
            a: event.a,
            b: extra_shift,
            c: 31 - msb,
        };
        assert_eq!(event.a, extra_shift.rotate_right(31 - msb));
        executor.record.shift_right_events.push(ror_event2);
    }
}
