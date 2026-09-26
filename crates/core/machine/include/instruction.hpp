#pragma once

#include "prelude.hpp"
#include "utils.hpp"

namespace zkm_core_machine_sys::cpu {

template<class F>
__ZKM_HOSTDEV__ __ZKM_INLINE__ void
populate_instruction(InstructionCols<F>& self, const InstructionFfi& instruction) {
    self.opcode = F::from_canonical_u32((uint32_t)instruction.opcode);
    self.op_a = F::from_canonical_u32((uint32_t)instruction.op_a);
    write_word_from_u32_v2<F>(self.op_b, instruction.op_b);
    write_word_from_u32_v2<F>(self.op_c, instruction.op_c);

    self.op_a_0 = F::from_bool(instruction.op_a == 0);  // 0 = Register::X0
    self.imm_b = F::from_bool(instruction.imm_b);
    self.imm_c = F::from_bool(instruction.imm_c);
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_syscall_instruction(const InstructionFfi& instruction) {
    return instruction.opcode == Opcode::SYSCALL;
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_branch_instruction(const InstructionFfi& instruction) {
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

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_jump_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::Jump:
        case Opcode::Jumpi:
        case Opcode::JumpDirect:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_check_memory_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SYSCALL:
        case Opcode::MADDU:
        case Opcode::MSUBU:
        case Opcode::MADD:
        case Opcode::MSUB:
        case Opcode::LH:
        case Opcode::LWL:
        case Opcode::LW:
        case Opcode::LBU:
        case Opcode::LHU:
        case Opcode::LWR:
        case Opcode::SB:
        case Opcode::SH:
        case Opcode::SWL:
        case Opcode::SW:
        case Opcode::SWR:
        case Opcode::LL:
        case Opcode::SC:
        case Opcode::LB:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_memory_store_instruction_except_sc(const InstructionFfi& instruction) {
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

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_memory_load_instruction(const InstructionFfi& instruction) {
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

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_memory_store_instruction(const InstructionFfi& instruction) {
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

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_rw_a_instruction(const InstructionFfi& instruction) {
    switch (instruction.opcode) {
        case Opcode::SYSCALL:
        case Opcode::INS:
        case Opcode::MADDU:
        case Opcode::MSUBU:
        case Opcode::MADD:
        case Opcode::MSUB:
        case Opcode::MEQ:
        case Opcode::MNE:
        case Opcode::LH:
        case Opcode::LWL:
        case Opcode::LW:
        case Opcode::LBU:
        case Opcode::LHU:
        case Opcode::LWR:
        case Opcode::SB:
        case Opcode::SH:
        case Opcode::SWL:
        case Opcode::SW:
        case Opcode::SWR:
        case Opcode::LL:
        case Opcode::SC:
        case Opcode::LB:
            return true;
        default:
            return false;
    }
}

__ZKM_HOSTDEV__ __ZKM_INLINE__ bool is_mult_div_instruction(const InstructionFfi& instruction) {
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
