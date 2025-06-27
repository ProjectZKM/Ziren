use zkm_core_executor::{ExecutionReport, HookEnv, ZKMContextBuilder};
use zkm_core_machine::io::ZKMStdin;
use zkm_primitives::io::ZKMPublicValues;
use zkm_prover::{components::DefaultProverComponents, ZKMProvingKey};

use anyhow::{Ok, Result};
use std::time::Duration;
use zkm_stark::{ZKMCoreOpts, ZKMProverOpts};

use crate::{provers::ProofOpts, Prover, ZKMProofKind, ZKMProofWithPublicValues};

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
pub struct Execute<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    context_builder: ZKMContextBuilder<'a>,
    elf: &'a [u8],
    stdin: ZKMStdin,
}

impl<'a> Execute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        elf: &'a [u8],
        stdin: ZKMStdin,
    ) -> Self {
        Self { prover, elf, stdin, context_builder: Default::default() }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(ZKMPublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, mut context_builder } = self;
        let context = context_builder.build();
        Ok(prover.zkm_prover().execute(elf, &stdin, context)?)
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within zkMIPS by writing to the specified file descriptor `fd`
    /// with [`zkm_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`zkm_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`zkm_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn max_cycles(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Skip deferred proof verification.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct Prove<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: ZKMProofKind,
    context_builder: ZKMContextBuilder<'a>,
    pk: &'a ZKMProvingKey,
    stdin: ZKMStdin,
    core_opts: ZKMCoreOpts,
    recursion_opts: ZKMCoreOpts,
    timeout: Option<Duration>,
}

impl<'a> Prove<'a> {
    /// Prepare to prove the execution of the given program with the given input.
    ///
    /// Prefer using [ProverClient::prove](super::ProverClient::prove).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        pk: &'a ZKMProvingKey,
        stdin: ZKMStdin,
    ) -> Self {
        Self {
            prover,
            kind: Default::default(),
            pk,
            stdin,
            context_builder: Default::default(),
            core_opts: ZKMCoreOpts::default(),
            recursion_opts: ZKMCoreOpts::recursion(),
            timeout: None,
        }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<ZKMProofWithPublicValues> {
        let Self {
            prover,
            kind,
            pk,
            stdin,
            mut context_builder,
            core_opts,
            recursion_opts,
            timeout,
        } = self;
        let opts = ZKMProverOpts { core_opts, recursion_opts };
        let proof_opts = ProofOpts { zkm_prover_opts: opts, timeout };
        let context = context_builder.build();

        // Dump the program and stdin to files for debugging if `ZKM_DUMP` is set.
        crate::utils::zkm_dump(&pk.elf, &stdin);

        prover.prove_impl(pk, stdin, proof_opts, context, kind)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = ZKMProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = ZKMProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = ZKMProofKind::Plonk;
        self
    }

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = ZKMProofKind::Groth16;
        self
    }

    /// Set the proof mode to the compressed-proof-to-groth16 mode.
    pub fn compress_to_groth16(mut self) -> Self {
        self.kind = ZKMProofKind::CompressToGroth16;
        self
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within zkMIPS by writing to the specified file descriptor `fd`
    /// with [`zkm_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`zkm_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the shard size for proving.
    pub fn shard_size(mut self, value: usize) -> Self {
        self.core_opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.core_opts.shard_batch_size = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.core_opts.reconstruct_commitments = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`zkm_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.context_builder.max_cycles(cycle_limit);
        self
    }

    /// Set the timeout for the proof's generation.
    ///
    /// This parameter is only used when the prover is run in network mode.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the skip deferred proof verification flag.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}
