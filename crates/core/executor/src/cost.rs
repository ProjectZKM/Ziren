use enum_map::EnumMap;

use crate::{events::NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC, Opcode, MipsAirId};

/// Estimate
/// Maps the opcode counts to the number of events in each air.
#[must_use]
pub fn estimate_mips_event_counts(
    cpu_cycles: u64,
    touched_addresses: u64,
    syscalls_sent: u64,
    opcode_counts: EnumMap<Opcode, u64>,
) -> EnumMap<MipsAirId, u64> {
    let mut events_counts: EnumMap<MipsAirId, u64> = EnumMap::default();
    // Compute the number of events in the cpu chip.
    events_counts[MipsAirId::Cpu] = cpu_cycles;

    // Compute the number of events in the add sub chip.
    events_counts[MipsAirId::AddSub] = opcode_counts[Opcode::ADD] + opcode_counts[Opcode::SUB];

    // Compute the number of events in the mul chip.
    events_counts[MipsAirId::Mul] = opcode_counts[Opcode::MUL]
        + opcode_counts[Opcode::MULT]
        + opcode_counts[Opcode::MULTU];

    // Compute the number of events in the bitwise chip.
    events_counts[MipsAirId::Bitwise] = opcode_counts[Opcode::XOR]
        + opcode_counts[Opcode::OR]
        + opcode_counts[Opcode::AND]
        + opcode_counts[Opcode::NOR];

    // Compute the number of events in the shift left chip.
    events_counts[MipsAirId::ShiftLeft] = opcode_counts[Opcode::SLL];

    // Compute the number of events in the shift right chip.
    events_counts[MipsAirId::ShiftRight] = opcode_counts[Opcode::SRL] + opcode_counts[Opcode::SRA];

    // Compute the number of events in the divrem chip.
    events_counts[MipsAirId::DivRem] = opcode_counts[Opcode::DIV]
        + opcode_counts[Opcode::DIVU];

    // Compute the number of events in the lt chip.
    events_counts[MipsAirId::Lt] = opcode_counts[Opcode::SLT] + opcode_counts[Opcode::SLTU];

    // Compute the number of events in the memory local chip.
    events_counts[MipsAirId::MemoryLocal] =
        touched_addresses.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC as u64);

    // // Compute the number of events in the branch chip.
    // events_counts[MipsAirId::Branch] = opcode_counts[Opcode::BEQ]
    //     + opcode_counts[Opcode::BNE]
    //     + opcode_counts[Opcode::BGTZ]
    //     + opcode_counts[Opcode::BGEZ]
    //     + opcode_counts[Opcode::BLTZ]
    //     + opcode_counts[Opcode::BLEZ];

    // // Compute the number of events in the jump chip.
    // events_counts[MipsAirId::Jump] = opcode_counts[Opcode::Jump]
    //     + opcode_counts[Opcode::Jumpi]
    //     + opcode_counts[Opcode::JumpDirect];

    // Compute the number of events in the auipc chip.
    events_counts[MipsAirId::CloClz] = opcode_counts[Opcode::CLO] + opcode_counts[Opcode::CLZ];

    // Compute the number of events in the syscall core chip.
    events_counts[MipsAirId::SyscallCore] = syscalls_sent;

    // Compute the number of events in the global chip.
    events_counts[MipsAirId::Global] = 2 * touched_addresses + syscalls_sent;

    events_counts
}

/// Pads the event counts to account for the worst case jump in events across N cycles.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn pad_mips_event_counts(
    mut event_counts: EnumMap<MipsAirId, u64>,
    num_cycles: u64,
) -> EnumMap<MipsAirId, u64> {
    event_counts.iter_mut().for_each(|(k, v)| match k {
        MipsAirId::Cpu => *v += num_cycles,
        MipsAirId::AddSub => *v += 5 * num_cycles,
        MipsAirId::Mul => *v += 4 * num_cycles,
        MipsAirId::Bitwise => *v += 3 * num_cycles,
        MipsAirId::ShiftLeft => *v += num_cycles,
        MipsAirId::ShiftRight => *v += num_cycles,
        MipsAirId::DivRem => *v += 4 * num_cycles,
        MipsAirId::Lt => *v += 2 * num_cycles,
        MipsAirId::MemoryLocal => *v += 64 * num_cycles,
        // MipsAirId::Branch => *v += 8 * num_cycles,
        // MipsAirId::Jump => *v += 2 * num_cycles,
        MipsAirId::CloClz => *v += 3 * num_cycles, // TODO: Check this value.
        MipsAirId::SyscallCore => *v += 2 * num_cycles,
        MipsAirId::Global => *v += 64 * num_cycles,
        _ => (),
    });
    event_counts
}
