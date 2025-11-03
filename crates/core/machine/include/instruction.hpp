#pragma once

#include "prelude.hpp"

namespace zkm_core_machine_sys::cpu {

__ZKM_HOSTDEV__ bool is_syscall_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SYSCALL:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_branch_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::BEQ:
        case Opcode::BNE:
        case Opcode::BLTZ:
        case Opcode::BGEZ:
        case Opcode::BLEZ:
        case Opcode::BGTZ:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_jump_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::Jump:
        case Opcode::Jumpi:
        case Opcode::JumpDirect:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_memory_store_instruction_except_sc(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SB:
        case Opcode::SH:
        case Opcode::SW:
        case Opcode::SWL:
        case Opcode::SWR:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_memory_load_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::LB:
        case Opcode::LH:
        case Opcode::LW:
        case Opcode::LWL:
        case Opcode::LWR:
        case Opcode::LBU:
        case Opcode::LHU:
        case Opcode::LL:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_memory_store_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SB:
        case Opcode::SH:
        case Opcode::SW:
        case Opcode::SWL:
        case Opcode::SWR:
        case Opcode::SC:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_rw_a_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SYSCALL:
        case Opcode::INS:
        case Opcode::MADDU:
        case Opcode::MSUBU:
        case Opcode::MADD:
        case Opcode::MSUB:
        case Opcode::MEQ:
        case Opcode::MNE:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ bool is_mult_div_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::MULT:
        case Opcode::MULTU:
        case Opcode::DIV:
        case Opcode::DIVU:
            return true;
        default:
            return false;
    }
}

} // namespace zkm_core_machine_sys::cpu
