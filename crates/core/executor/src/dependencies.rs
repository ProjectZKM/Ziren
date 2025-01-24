use crate::{events::AluEvent, utils::{get_msb, get_quotient_and_remainder, is_signed_operation}, Executor, Opcode, WORD_SIZE};

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
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[3],
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: event.c,
            c: (event.c as i32).unsigned_abs(),
            sub_lookups: ids,
        });
    }
    if rem_neg == 1 {
        let ids = executor.record.create_lookup_ids();
        executor.record.add_events.push(AluEvent {
            lookup_id: event.sub_lookups[4],
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            hi: 0,
            a: 0,
            b: remainder,
            c: (remainder as i32).unsigned_abs(),
            sub_lookups: ids,
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
        lookup_id: event.sub_lookups[0],
        shard,
        clk: event.clk,
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
        sub_lookups: executor.record.create_lookup_ids(),
        hi: upper_word,
    };
    executor.record.mul_events.push(multiplication);

    let lt_event = if is_signed_operation {
        AluEvent {
            lookup_id: event.sub_lookups[1],
            shard,
            opcode: Opcode::SLTU,
            hi: 0,
            a: 1,
            b: (remainder as i32).unsigned_abs(),
            c: u32::max(1, (event.c as i32).unsigned_abs()),
            clk: event.clk,
            sub_lookups: executor.record.create_lookup_ids(),
        }
    } else {
        AluEvent {
            lookup_id: event.sub_lookups[2],
            shard,
            opcode: Opcode::SLTU,
            hi: 0,
            a: 1,
            b: remainder,
            c: u32::max(1, event.c),
            clk: event.clk,
            sub_lookups: executor.record.create_lookup_ids(),
        }
    };

    if event.c != 0 {
        executor.record.lt_events.push(lt_event);
    }
}

/// Emit the dependencies for CPU events.
#[allow(clippy::too_many_lines)]
pub fn emit_cpu_dependencies(executor: &mut Executor, index: usize) {
    let event = executor.record.cpu_events[index];
    let shard = executor.shard();
    let instruction = &executor.program.fetch(event.pc);
    if matches!(
        instruction.opcode,
        Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LWR
            | Opcode::LWL
            | Opcode::LL
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::SB
            | Opcode::SH
            | Opcode::SW
            | Opcode::SWR
            | Opcode::SWL
            | Opcode::SC
            | Opcode::SDC1
    ) {
        let memory_addr = event.b.wrapping_add(event.c);
        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            lookup_id: event.memory_add_lookup_id,
            shard,
            clk: event.clk,
            opcode: Opcode::ADD,
            hi: 0,
            a: memory_addr,
            b: event.b,
            c: event.c,
            sub_lookups: executor.record.create_lookup_ids(),
        };
        executor.record.add_events.push(add_event);
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        let mem_value = event.memory_record.unwrap().value();

        if matches!(instruction.opcode, Opcode::LB | Opcode::LH) {
            let (unsigned_mem_val, most_sig_mem_value_byte, sign_value) = match instruction.opcode {
                Opcode::LB => {
                    // TODO: stephen, MIPS is using big-endian for memory values, we may use 3 -
                    // addr_offset when we calculate add_offset.
                    let offset = 3 - addr_offset;
                    let most_sig_mem_value_byte = mem_value.to_le_bytes()[offset as usize];
                    let sign_value = 256;
                    (
                        most_sig_mem_value_byte as u32,
                        most_sig_mem_value_byte,
                        sign_value,
                    )
                }
                Opcode::LH => {
                    let sign_value = 65536;
                    let offset = 1 - (addr_offset >> 1);
                    let unsigned_mem_val = match offset % 2 {
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
                    lookup_id: event.memory_sub_lookup_id,
                    shard,
                    clk: event.clk,
                    opcode: Opcode::SUB,
                    hi: 0,
                    a: event.a,
                    b: unsigned_mem_val,
                    c: sign_value,
                    sub_lookups: executor.record.create_lookup_ids(),
                };
                executor.record.add_events.push(sub_event);
            }
        }
    }

    if instruction.is_branch_instruction() {
        let a_eq_b = event.a == event.b;
        let a_eq_0 = (event.a as i32) == 0;
        let a_lt_0 = (event.a as i32) < 0;
        let a_gt_0 = (event.a as i32) > 0;

        if instruction.opcode.signed_compare() {
            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                lookup_id: event.branch_lt_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::SLT,
                hi: 0,
                a: a_lt_0 as u32,
                b: event.a,
                c: 0,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            let gt_comp_event = AluEvent {
                lookup_id: event.branch_gt_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::SLT,
                hi: 0,
                a: a_gt_0 as u32,
                b: 0,
                c: event.a,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            executor.record.lt_events.push(lt_comp_event);
            executor.record.lt_events.push(gt_comp_event);
        }

        let branching = match instruction.opcode {
            Opcode::BEQ => a_eq_b,
            Opcode::BNE => !a_eq_b,
            Opcode::BLTZ => a_lt_0,
            Opcode::BLEZ => a_lt_0 || a_eq_0,
            Opcode::BGTZ => a_gt_0,
            Opcode::BGEZ => a_eq_0 || a_gt_0,
            _ => unreachable!(),
        };
        if branching {
            let add_event = AluEvent {
                lookup_id: event.branch_add_lookup_id,
                shard,
                clk: event.clk,
                opcode: Opcode::ADD,
                hi: 0,
                a: event.next_next_pc,
                b: event.next_pc,
                c: event.c,
                sub_lookups: executor.record.create_lookup_ids(),
            };
            executor.record.add_events.push(add_event);
        }
    }

    // todo: process jump instructions
    // if instruction.is_jump_instruction() {
    //     match instruction.opcode {
    //         Opcode::JAL => {
    //             let next_pc = event.pc.wrapping_add(event.b);
    //             let add_event = AluEvent {
    //                 lookup_id: event.jump_jal_lookup_id,
    //                 shard,
    //                 clk: event.clk,
    //                 opcode: Opcode::ADD,
    //                 a: next_pc,
    //                 b: event.pc,
    //                 c: event.b,
    //                 sub_lookups: executor.record.create_lookup_ids(),
    //             };
    //             executor.record.add_events.push(add_event);
    //         }
    //         Opcode::JALR => {
    //             let next_pc = event.b.wrapping_add(event.c);
    //             let add_event = AluEvent {
    //                 lookup_id: event.jump_jalr_lookup_id,
    //                 shard,
    //                 clk: event.clk,
    //                 opcode: Opcode::ADD,
    //                 a: next_pc,
    //                 b: event.b,
    //                 c: event.c,
    //                 sub_lookups: executor.record.create_lookup_ids(),
    //             };
    //             executor.record.add_events.push(add_event);
    //         }
    //         _ => unreachable!(),
    //     }
    // }
}
