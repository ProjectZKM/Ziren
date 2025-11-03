#include "kb31_t.hpp"
#include "sys.hpp"

namespace zkm_core_machine_sys {

extern void cpu_event_to_row_koalabear(
    const CpuEventFfi event,
    const uint32_t shard,
    const InstructionFfi instruction,
    CpuCols<KoalaBearP3>* cols
) {
    CpuCols<kb31_t>* cols_kb31 = reinterpret_cast<CpuCols<kb31_t>*>(cols);
    cpu::event_to_row<kb31_t>(event, shard, instruction, *cols_kb31);
}

extern void add_sub_event_to_row_koalabear(
    const AluEvent* event,
    AddSubCols<KoalaBearP3>* cols
) {
    AddSubCols<kb31_t>* cols_kb31 = reinterpret_cast<AddSubCols<kb31_t>*>(cols);
    add_sub::event_to_row<kb31_t>(*event, *cols_kb31);
}

extern void memory_local_event_to_row_koalabear(const MemoryLocalEvent* event, SingleMemoryLocal<KoalaBearP3>* cols) {
    SingleMemoryLocal<kb31_t>* cols_kb31 = reinterpret_cast<SingleMemoryLocal<kb31_t>*>(cols);
    memory_local::event_to_row<kb31_t, kb31_septic_extension_t>(event, cols_kb31);
}

extern void memory_global_event_to_row_koalabear(const MemoryInitializeFinalizeEvent* event, const bool is_receive, MemoryInitCols<KoalaBearP3>* cols) {
    MemoryInitCols<kb31_t>* cols_kb31 = reinterpret_cast<MemoryInitCols<kb31_t>*>(cols);
    memory_global::event_to_row<kb31_t, kb31_septic_extension_t>(event, is_receive, cols_kb31);
}

extern void syscall_event_to_row_koalabear(const SyscallEvent* event, const bool is_receive, SyscallCols<KoalaBearP3>* cols) {
    SyscallCols<kb31_t>* cols_kb31 = reinterpret_cast<SyscallCols<kb31_t>*>(cols);
    syscall::event_to_row<kb31_t, kb31_septic_extension_t>(event, is_receive, cols_kb31);
}

} // namespace zkm_core_machine_sys
