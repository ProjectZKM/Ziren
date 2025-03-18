use crate::{
    events::{AluEvent, BranchEvent, JumpEvent, MemInstrEvent, MiscEvent, MemoryRecord},
    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
    Executor, Opcode, UNUSED_PC, DEFAULT_PC_INC,
};
/// Emits the dependencies for division and remainder operations.
#[allow(clippy::too_many_lines)]
pub fn emit_divrem_dependencies(executor: &mut Executor, event: AluEvent) {
    let shard = executor.shard();
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
            op_a_0: false,
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
            op_a_0: false,
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

    let multiplication = AluEvent {
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
        op_a_0: false,
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
            op_a_0: false,
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
            op_a_0: false,
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Emits the dependencies for clo and clz operations.
#[allow(clippy::too_many_lines)]
pub fn emit_cloclz_dependencies(executor: &mut Executor, event: AluEvent) {
    let shard = executor.shard();

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
            op_a_0: false,
        };

        executor.record.shift_right_events.push(srl_event);
    }
}

/// Emit the dependencies for memory instructions.
pub fn emit_memory_dependencies(
    executor: &mut Executor,
    event: MemInstrEvent,
    memory_record: MemoryRecord,
    index: usize
) {
    let cpu_event = executor.record.cpu_events[index];
    let shard = executor.shard();
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
        op_a_0: false,
    };
    executor.record.add_events.push(add_event);
    let addr_offset = (memory_addr % 4_u32) as u8;
    let mem_value = memory_record.value;

    if matches!(event.opcode, Opcode::LB | Opcode::LH) {
        let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match event.opcode {
            Opcode::LB => {
                let most_sig_mem_value_byte = mem_value.to_le_bytes()[addr_offset as usize];
                let sign_value = 256;
                (
                    most_sig_mem_value_byte as u32,
                    most_sig_mem_value_byte,
                    sign_value,
                )
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
                op_a_0: false,
            };
            executor.record.add_events.push(sub_event);
        }
    }
}

/// Emit the dependencies for branch instructions.
pub fn emit_branch_dependencies(executor: &mut Executor, event: BranchEvent, index: usize) {
    let cpu_event = executor.record.cpu_events[index];
    let shard = executor.shard();
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
        op_a_0: false,
    };
    let gt_comp_event = AluEvent {
        pc: UNUSED_PC,
        next_pc: UNUSED_PC + DEFAULT_PC_INC,
        opcode: Opcode::SLT,
        hi: 0,
        a: a_gt_b as u32,
        b: event.b,
        c: event.a,
        op_a_0: false,
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
            op_a_0: false,
        };
        executor.record.add_events.push(add_event);
    }
}

/// Emit the dependencies for jump instructions.
pub fn emit_jump_dependencies(executor: &mut Executor, event: JumpEvent, index: usize) {
    let cpu_event = executor.record.cpu_events[index];
    let shard = executor.shard();
    match event.opcode {
        Opcode::JumpDirect => {
            let target_pc = event.next_pc.wrapping_add(event.b);
            let add_event = AluEvent {
                pc: UNUSED_PC,
                next_pc: UNUSED_PC,
                opcode: Opcode::ADD,
                hi: 0,
                a: target_pc,
                b: event.next_pc,
                c: event.b,
                op_a_0: false,
            };
            executor.record.add_events.push(add_event);
        }
        Opcode::Jump | Opcode::Jumpi => {
        }
        _ => unreachable!(),
    }
}

/// Emit the dependencies for misc instructions.
pub fn emit_misc_dependencies(executor: &mut Executor, event: MiscEvent, index: usize) {
    // TODO
}
