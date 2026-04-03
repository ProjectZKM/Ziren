#pragma once

#include "prelude.hpp"
#include "utils.hpp"
#include "memory.hpp"
#include "kb31_septic_extension_t.hpp"

namespace zkm_core_machine_sys::memory_instrs {
    template<class F>
    __ZKM_HOSTDEV__ void event_to_row(const MemInstrEvent& event, MemoryInstructionsColumns<F>& cols) {
        cols.shard = F::from_canonical_u32(event.shard);
        assert(cols.shard != F::zero());
        cols.clk = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        write_word_from_u32_v2<F>(cols.op_a_value, event.a);
        write_word_from_u32_v2<F>(cols.op_b_value, event.b);
        write_word_from_u32_v2<F>(cols.op_c_value, event.c);

        // Populate memory accesses for reading from memory.
        memory::populate_read_write_v2<F>(cols.memory_access, event.mem_access);
        write_word_from_u32_v2<F>(cols.prev_a_val, event.prev_a_val);

        // Populate addr_word and addr_aligned columns.
        uint32_t memory_addr = event.b + event.c;
        uint32_t aligned_addr = memory_addr - (memory_addr % WORD_SIZE);
        write_word_from_u32_v2<F>(cols.addr_word, memory_addr);
        populate_range_checker(cols.addr_word_range_checker, memory_addr);
        cols.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert(aligned_addr % 4 == 0);
        // Populate memory offsets.
        uint8_t addr_ls_two_bits = (uint8_t)(memory_addr % WORD_SIZE);
        cols.addr_ls_two_bits = F::from_canonical_u8(addr_ls_two_bits);
        cols.ls_bits_is_one = F::from_bool(addr_ls_two_bits == 1);
        cols.ls_bits_is_two = F::from_bool(addr_ls_two_bits == 2);
        cols.ls_bits_is_three = F::from_bool(addr_ls_two_bits == 3);

        const uint32_t mem_value =
            event.mem_access.tag == MemoryRecordEnum::Tag::Read ?
                event.mem_access.read._0.value
                : event.mem_access.write._0.value;

        // If it is a load instruction, set the unsigned_mem_val column.
        if (event.opcode == Opcode::LB ||
            event.opcode == Opcode::LBU ||
            event.opcode == Opcode::LH ||
            event.opcode == Opcode::LHU ||
            event.opcode == Opcode::LW ||
            event.opcode == Opcode::LWL ||
            event.opcode == Opcode::LWR ||
            event.opcode == Opcode::LL)
        {
            uint32_t unsigned_mem_val_u32 = 0;
            switch (event.opcode) {
                case Opcode::LB:
                case Opcode::LBU: {
                    // LB: mem_value = sign_extend::<8>((mem >> (24 - (rs & 3) * 8)) & 0xff)
                    const auto le_bytes = u32_to_le_bytes(mem_value);
                    unsigned_mem_val_u32 = le_bytes[addr_ls_two_bits] & 0xFFu;
                    break;
                }
                case Opcode::LH:
                case Opcode::LHU: {
                    // LH: sign_extend::<16>((mem >> (16 - (rs & 2) * 8)) & 0xffff)
                    // LH: sign_extend::<16>((mem >> (8 * (2 - (rs & 2))) & 0xffff)
                    switch ((addr_ls_two_bits >> 1) % 2) {
                        case 0:
                            unsigned_mem_val_u32 = mem_value & 0x0000FFFFu;
                            break;
                        case 1:
                            unsigned_mem_val_u32 = (mem_value & 0xFFFF0000u) >> 16;
                            break;
                        default:
                            __builtin_unreachable();  // GCC/Clang
                            break;
                    }
                    break;
                }
                case Opcode::LW: {
                    unsigned_mem_val_u32 = mem_value;
                    break;
                }
                case Opcode::LWL: {
                    // LWL:
                    //    let val = mem << (24 - (rs & 3) * 8);
                    //    let mask = 0xFFFFFFFF_u32 << (24 - (rs & 3) * 8);
                    //    (rt & (!mask)) | val
                    uint32_t val = mem_value << (24 - addr_ls_two_bits * 8);
                    uint32_t mask = 0xFFFFFFFFu << (24 - addr_ls_two_bits * 8);
                    unsigned_mem_val_u32 = (event.prev_a_val & (~mask)) | val;
                    break;
                }
                case Opcode::LWR: {
                    // LWR:
                    //     let val = mem >> ((rs & 3) * 8);
                    //     let mask = 0xFFFFFFFF_u322 >> ((rs & 3) * 8);
                    //     (rt & (!mask)) | val
                    uint32_t val = mem_value >> (addr_ls_two_bits * 8);
                    uint32_t mask = 0xFFFFFFFFu >> (addr_ls_two_bits * 8);
                    unsigned_mem_val_u32 = (event.prev_a_val & (~mask)) | val;
                    break;
                }
                case Opcode::LL: {
                    unsigned_mem_val_u32 = mem_value;
                    break;
                }
                default:
                    __builtin_unreachable();  // GCC/Clang
                    break;
            }
            write_word_from_u32_v2<F>(cols.unsigned_mem_val, unsigned_mem_val_u32);

            // For the signed load instructions, we need to check if the loaded value is negative.
            if (event.opcode == Opcode::LB || event.opcode == Opcode::LH) {
                const auto le_bytes = u32_to_le_bytes(unsigned_mem_val_u32);
                const uint8_t most_sig_mem_value_byte =
                    (event.opcode == Opcode::LB) ? le_bytes[0] : le_bytes[1];

                uint8_t most_sig_mem_value_bit = most_sig_mem_value_byte >> 7;
                if (most_sig_mem_value_bit == 1) {
                    cols.mem_value_is_neg = F::one();
                } else {
                    cols.mem_value_is_neg = F::zero();
                }

                cols.most_sig_byte = F::from_canonical_u8(most_sig_mem_value_byte);
                cols.most_sig_bit = F::from_canonical_u8(most_sig_mem_value_bit);
            } else {
                cols.most_sig_byte = F::zero();
                cols.most_sig_bit = F::zero();
                cols.mem_value_is_neg = F::zero();
            }
        } else {
            cols.most_sig_byte = F::zero();
            cols.most_sig_bit = F::zero();
            cols.mem_value_is_neg = F::zero();
            write_word_from_u32_v2<F>(cols.unsigned_mem_val, 0);
        }

        cols.is_lb = F::from_bool(event.opcode == Opcode::LB);
        cols.is_lbu = F::from_bool(event.opcode == Opcode::LBU);
        cols.is_lh = F::from_bool(event.opcode == Opcode::LH);
        cols.is_lhu = F::from_bool(event.opcode == Opcode::LHU);
        cols.is_lw = F::from_bool(event.opcode == Opcode::LW);
        cols.is_lwl = F::from_bool(event.opcode == Opcode::LWL);
        cols.is_lwr = F::from_bool(event.opcode == Opcode::LWR);
        cols.is_ll = F::from_bool(event.opcode == Opcode::LL);
        cols.is_sb = F::from_bool(event.opcode == Opcode::SB);
        cols.is_sh = F::from_bool(event.opcode == Opcode::SH);
        cols.is_sw = F::from_bool(event.opcode == Opcode::SW);
        cols.is_swl = F::from_bool(event.opcode == Opcode::SWL);
        cols.is_swr = F::from_bool(event.opcode == Opcode::SWR);
        cols.is_sc = F::from_bool(event.opcode == Opcode::SC);

        populate_from_field_element(
            cols.most_sig_bytes_zero,
            cols.addr_word._0[1] + cols.addr_word._0[2] + cols.addr_word._0[3]
        );
    }
}  // namespace zkm::memory_instrs
