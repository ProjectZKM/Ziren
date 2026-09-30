#include "kb31_t.hpp"
#include "sys.hpp"

namespace zkm_core_machine_sys {

extern void add_sub_event_to_row_koalabear(
    const AluEvent* event,
    AddSubCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    AddSubCols<kb31_t>* cols_kb31 = reinterpret_cast<AddSubCols<kb31_t>*>(cols);
    add_sub::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void add_sub_imm_event_to_row_koalabear(
    const AluEvent* event,
    AddSubImmCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    AddSubImmCols<kb31_t>* cols_kb31 = reinterpret_cast<AddSubImmCols<kb31_t>*>(cols);
    add_sub_imm::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void memory_local_event_to_row_koalabear(const MemoryLocalEvent* event, SingleMemoryLocal<KoalaBearP3>* cols) {
    SingleMemoryLocal<kb31_t>* cols_kb31 = reinterpret_cast<SingleMemoryLocal<kb31_t>*>(cols);
    memory_local::event_to_row<kb31_t, kb31_septic_extension_t>(event, cols_kb31);
}

extern void memory_bump_event_to_row_koalabear(const MemoryBumpEvent* event, MemoryBumpCols<KoalaBearP3>* cols) {
    MemoryBumpCols<kb31_t>* cols_kb31 = reinterpret_cast<MemoryBumpCols<kb31_t>*>(cols);
    memory_bump::event_to_row<kb31_t>(*event, *cols_kb31);
}

extern void memory_global_event_to_row_koalabear(const MemoryInitializeFinalizeEvent* event, const bool is_receive, MemoryInitCols<KoalaBearP3>* cols) {
    MemoryInitCols<kb31_t>* cols_kb31 = reinterpret_cast<MemoryInitCols<kb31_t>*>(cols);
    memory_global::event_to_row<kb31_t, kb31_septic_extension_t>(event, is_receive, cols_kb31);
}

extern void syscall_core_event_to_row_koalabear(const SyscallEvent* event, SyscallCols<KoalaBearP3>* cols) {
    SyscallCols<kb31_t>* cols_kb31 = reinterpret_cast<SyscallCols<kb31_t>*>(cols);
    syscall::core_event_to_row<kb31_t>(*event, *cols_kb31);
}

extern void syscall_precompile_event_to_row_koalabear(const SyscallEvent* event, SyscallCols<KoalaBearP3>* cols) {
    SyscallCols<kb31_t>* cols_kb31 = reinterpret_cast<SyscallCols<kb31_t>*>(cols);
    syscall::precompile_event_to_row<kb31_t>(*event, *cols_kb31);
}

extern void lt_event_to_row_koalabear(
    const AluEvent* event,
    LtCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    LtCols<kb31_t>* cols_kb31 = reinterpret_cast<LtCols<kb31_t>*>(cols);
    lt::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void lt_imm_event_to_row_koalabear(
    const AluEvent* event,
    LtImmCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    LtImmCols<kb31_t>* cols_kb31 = reinterpret_cast<LtImmCols<kb31_t>*>(cols);
    lt_imm::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void bitwise_event_to_row_koalabear(
    const AluEvent* event,
    BitwiseCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    BitwiseCols<kb31_t>* cols_kb31 = reinterpret_cast<BitwiseCols<kb31_t>*>(cols);
    bitwise::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void bitwise_imm_event_to_row_koalabear(
    const AluEvent* event,
    BitwiseImmCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    BitwiseImmCols<kb31_t>* cols_kb31 = reinterpret_cast<BitwiseImmCols<kb31_t>*>(cols);
    bitwise_imm::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void clo_clz_event_to_row_koalabear(
    const AluEvent* event,
    CloClzCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    CloClzCols<kb31_t>* cols_kb31 = reinterpret_cast<CloClzCols<kb31_t>*>(cols);
    clo_clz::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void branch_event_to_row_koalabear(
    const BranchEvent* event,
    BranchColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    BranchColumns<kb31_t>* cols_kb31 = reinterpret_cast<BranchColumns<kb31_t>*>(cols);
    branch::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void jump_event_to_row_koalabear(
    const JumpEvent* event,
    JumpColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    JumpColumns<kb31_t>* cols_kb31 = reinterpret_cast<JumpColumns<kb31_t>*>(cols);
    jump::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void misc_instrs_event_to_row_koalabear(
    const MiscEvent* event,
    MiscInstrColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    MiscInstrColumns<kb31_t>* cols_kb31 = reinterpret_cast<MiscInstrColumns<kb31_t>*>(cols);
    misc_instrs::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void mov_cond_event_to_row_koalabear(
    const MovCondEvent* event,
    MovCondCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    MovCondCols<kb31_t>* cols_kb31 = reinterpret_cast<MovCondCols<kb31_t>*>(cols);
    mov_cond::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void shift_left_event_to_row_koalabear(
    const AluEvent* event,
    ShiftLeftCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    ShiftLeftCols<kb31_t>* cols_kb31 = reinterpret_cast<ShiftLeftCols<kb31_t>*>(cols);
    shift_left::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void shift_left_imm_event_to_row_koalabear(
    const AluEvent* event,
    ShiftLeftImmCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    ShiftLeftImmCols<kb31_t>* cols_kb31 = reinterpret_cast<ShiftLeftImmCols<kb31_t>*>(cols);
    shift_left_imm::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void shift_right_event_to_row_koalabear(
    const AluEvent* event,
    ShiftRightCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    ShiftRightCols<kb31_t>* cols_kb31 = reinterpret_cast<ShiftRightCols<kb31_t>*>(cols);
    shift_right::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void shift_right_imm_event_to_row_koalabear(
    const AluEvent* event,
    ShiftRightImmCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    ShiftRightImmCols<kb31_t>* cols_kb31 = reinterpret_cast<ShiftRightImmCols<kb31_t>*>(cols);
    shift_right_imm::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void mul_event_to_row_koalabear(
    const CompAluEvent* event,
    MulCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    MulCols<kb31_t>* cols_kb31 = reinterpret_cast<MulCols<kb31_t>*>(cols);
    mul::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void div_rem_event_to_row_koalabear(
    const CompAluEvent* event,
    DivRemCols<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    DivRemCols<kb31_t>* cols_kb31 = reinterpret_cast<DivRemCols<kb31_t>*>(cols);
    div_rem::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

extern void memory_load_narrow_event_to_row_koalabear(
    const MemInstrEvent* event,
    LoadNarrowColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction
) {
    LoadNarrowColumns<kb31_t>* cols_kb31 = reinterpret_cast<LoadNarrowColumns<kb31_t>*>(cols);
    memory_instrs::load_narrow_event_to_row<kb31_t>(*event, *cols_kb31, instruction);
}

extern void memory_load_word_event_to_row_koalabear(
    const MemInstrEvent* event,
    LoadWordColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction
) {
    LoadWordColumns<kb31_t>* cols_kb31 = reinterpret_cast<LoadWordColumns<kb31_t>*>(cols);
    memory_instrs::load_word_event_to_row<kb31_t>(*event, *cols_kb31, instruction);
}

extern void memory_store_narrow_event_to_row_koalabear(
    const MemInstrEvent* event,
    StoreNarrowColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction
) {
    StoreNarrowColumns<kb31_t>* cols_kb31 = reinterpret_cast<StoreNarrowColumns<kb31_t>*>(cols);
    memory_instrs::store_narrow_event_to_row<kb31_t>(*event, *cols_kb31, instruction);
}

extern void memory_store_word_event_to_row_koalabear(
    const MemInstrEvent* event,
    StoreWordColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction
) {
    StoreWordColumns<kb31_t>* cols_kb31 = reinterpret_cast<StoreWordColumns<kb31_t>*>(cols);
    memory_instrs::store_word_event_to_row<kb31_t>(*event, *cols_kb31, instruction);
}

extern void memory_unaligned_event_to_row_koalabear(
    const MemInstrEvent* event,
    MemoryUnalignedColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction
) {
    MemoryUnalignedColumns<kb31_t>* cols_kb31 = reinterpret_cast<MemoryUnalignedColumns<kb31_t>*>(cols);
    memory_instrs::unaligned_event_to_row<kb31_t>(*event, *cols_kb31, instruction);
}

extern void syscall_instrs_event_to_row_koalabear(
    const SyscallEvent* event,
    SyscallInstrColumns<KoalaBearP3>* cols,
    const InstructionFfi instruction,
    const uint32_t shard
) {
    SyscallInstrColumns<kb31_t>* cols_kb31 = reinterpret_cast<SyscallInstrColumns<kb31_t>*>(cols);
    syscall_instrs::event_to_row<kb31_t>(*event, *cols_kb31, instruction, shard);
}

} // namespace zkm_core_machine_sys
