use zkm_core_machine::mips::MipsAir;
use zkm_pcs::{CpuProver, MachineProver, StarkGenericConfig};

use crate::{CoreSC, OuterSC, WrapAir};

pub trait ZKMProverComponents: Send + Sync {
    /// The prover for making Ziren core proofs.
    type CoreProver: MachineProver<CoreSC, MipsAir<<CoreSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;

    /// The prover for wrapping compressed proofs into SNARK-friendly field elements.
    type WrapProver: MachineProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>
        + Send
        + Sync;
}

pub struct DefaultProverComponents;

impl ZKMProverComponents for DefaultProverComponents {
    type CoreProver = CpuProver<CoreSC, MipsAir<<CoreSC as StarkGenericConfig>::Val>>;
    type WrapProver = CpuProver<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>;
}
