use std::borrow::Borrow;

use p3_challenger::DuplexChallenger;
use p3_koala_bear::KoalaBear;
use p3_symmetric::{Hash, MerkleCap};

use p3_field::PrimeCharacteristicRing;
use zkm_pcs::{
    koala_bear_poseidon2::KoalaBearPoseidon2, Com, InnerChallenge, InnerPerm, InnerVal,
    OpeningProof, StarkVerifyingKey, Word,
};
use zkm_recursion_compiler::ir::Builder;

use zkm_recursion_compiler::ir::Felt;

use crate::{
    challenger::DuplexChallengerVariable,
    hash::{FieldHasher, FieldHasherVariable},
    merkle_tree::MerkleProof,
    stark::MerkleProofVariable,
    witness::{WitnessWriter, Witnessable},
    CircuitConfig, FriProofVariable, KoalaBearFriParametersVariable, VerifyingKeyVariable,
};

use super::{ZKMMerkleProofWitnessValues, ZKMMerkleProofWitnessVariable};

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Word<T> {
    type WitnessVariable = Word<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        Word(self.0.read(builder))
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.write(witness);
    }
}

impl<C> Witnessable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
{
    type WitnessVariable = DuplexChallengerVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable { sponge_state, input_buffer, output_buffer }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.sponge_state.write(witness);
        self.input_buffer.write(witness);
        self.output_buffer.write(witness);
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for Hash<F, W, DIGEST_ELEMENTS>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    W: Witnessable<C>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.write(witness);
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for MerkleCap<F, [W; DIGEST_ELEMENTS]>
where
    C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
    W: Witnessable<C> + Copy,
    [W; DIGEST_ELEMENTS]: Borrow<[W; DIGEST_ELEMENTS]>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        // MerkleCap with cap_height=0 has exactly one digest entry.
        let cap: &[[W; DIGEST_ELEMENTS]] = self.borrow();
        assert!(!cap.is_empty(), "MerkleCap must have at least one digest");
        cap[0].read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let cap: &[[W; DIGEST_ELEMENTS]] = self.borrow();
        assert!(!cap.is_empty(), "MerkleCap must have at least one digest");
        cap[0].write(witness);
    }
}

impl<
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge>,
        SC: KoalaBearFriParametersVariable<C>,
    > Witnessable<C> for StarkVerifyingKey<SC>
where
    Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
    OpeningProof<SC>: Witnessable<C, WitnessVariable = FriProofVariable<C, SC>>,
{
    type WitnessVariable = VerifyingKeyVariable<C, SC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let commitment = self.commit.read(builder);
        let pc_start = self.pc_start.read(builder);
        let initial_global_cumulative_sum = self.initial_global_cumulative_sum.read(builder);
        let chip_information = self
            .chip_information
            .iter()
            .map(|(name, ser_domain, dims)| {
                (
                    name.clone(),
                    ser_domain.to_coset(),
                    p3_matrix::Dimensions { width: dims.0, height: dims.1 },
                )
            })
            .collect();
        // WITNESS the per-prep-chip [name_digest, prep_width] vk.hash
        // inputs so the in-circuit hash is VALUE-INDEPENDENT — a FIXED
        // 2 reads per prep chip regardless of the core vk's heights /
        // name lengths / sort order.  Read order MUST mirror `write` below.
        let prep_name_width_hash_inputs: Vec<[Felt<C::F>; 2]> = self
            .chip_information
            .iter()
            .map(|(name, _ser_domain, dims)| {
                let name_digest = zkm_primitives::prep_chip_name_digest(name);
                let width = InnerVal::from_usize(dims.0);
                [name_digest.read(builder), width.read(builder)]
            })
            .collect();
        let chip_ordering = self.chip_ordering.clone();
        VerifyingKeyVariable {
            commitment,
            pc_start,
            initial_global_cumulative_sum,
            chip_information,
            chip_ordering,
            prep_name_width_hash_inputs,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.commit.write(witness);
        self.pc_start.write(witness);
        self.initial_global_cumulative_sum.write(witness);
        // Write the per-prep-chip [name_digest, prep_width] vk.hash
        // inputs in the same order `read` consumes them.
        for (name, _ser_domain, dims) in self.chip_information.iter() {
            zkm_primitives::prep_chip_name_digest(name).write(witness);
            InnerVal::from_usize(dims.0).write(witness);
        }
    }
}

impl<C: CircuitConfig, HV: FieldHasherVariable<C>> Witnessable<C> for MerkleProof<C::F, HV>
where
    HV::Digest: Witnessable<C, WitnessVariable = HV::DigestVariable>,
{
    type WitnessVariable = MerkleProofVariable<C, HV>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let mut bits = vec![];
        let mut index = self.index;
        for _ in 0..self.path.len() {
            bits.push(index % 2 == 1);
            index >>= 1;
        }
        let index_bits = bits.read(builder);
        let path = self.path.read(builder);

        MerkleProofVariable { index: index_bits, path }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let mut index = self.index;
        for _ in 0..self.path.len() {
            (index % 2 == 1).write(witness);
            index >>= 1;
        }
        self.path.write(witness);
    }
}

impl<C: CircuitConfig<F = KoalaBear>, SC: KoalaBearFriParametersVariable<C>> Witnessable<C>
    for ZKMMerkleProofWitnessValues<SC>
where
    // This trait bound is redundant, but Rust-Analyzer is not able to infer it.
    SC: FieldHasher<KoalaBear>,
    <SC as FieldHasher<KoalaBear>>::Digest: Witnessable<C, WitnessVariable = SC::DigestVariable>,
{
    type WitnessVariable = ZKMMerkleProofWitnessVariable<C, SC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        ZKMMerkleProofWitnessVariable {
            vk_merkle_proofs: self.vk_merkle_proofs.read(builder),
            values: self.values.read(builder),
            root: self.root.read(builder),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vk_merkle_proofs.write(witness);
        self.values.write(witness);
        self.root.write(witness);
    }
}

// ---------------------------------------------------------------------------
// Witnessable impls for SP1-style shard-level basefold recursion stages.
// Each one follows the pattern of the legacy equivalent
// above, with `ShardProof<SC>::read` replaced by `BasefoldShardProof::read`
// (which produces a 5-tuple variable, see shard_level_witness.rs:198-241).
// ---------------------------------------------------------------------------

mod basefold_witness {
    use super::*;
    use crate::machine::{
        compress_basefold::{ZKMCompressBasefoldWitnessValues, ZKMCompressBasefoldWitnessVariable},
        core_basefold::{ZKMCoreBasefoldWitnessValues, ZKMCoreBasefoldWitnessVariable},
        deferred_basefold::{ZKMDeferredBasefoldWitnessValues, ZKMDeferredBasefoldWitnessVariable},
        wrap_basefold::{ZKMWrapBasefoldWitnessValues, ZKMWrapBasefoldWitnessVariable},
    };

    impl<C> Witnessable<C> for ZKMCoreBasefoldWitnessValues<KoalaBearPoseidon2>
    where
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
    {
        type WitnessVariable = ZKMCoreBasefoldWitnessVariable<C, KoalaBearPoseidon2>;

        fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
            let vk = self.vk.read(builder);
            let shard_proof_tuples = self.shard_proofs.read(builder);
            // Read per-shard chip_cumulative_sums.
            // Order: outer = shard_proofs iteration (Vec); inner = BTreeMap iter (sorted by key).
            let chip_cumulative_sums_per_shard: Vec<_> = self
                .shard_proofs
                .iter()
                .map(|sp| {
                    sp.chip_cumulative_sums
                        .iter()
                        .map(|(name, sums)| (name.clone(), sums.read(builder)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .collect();
            let is_complete = InnerVal::from_bool(self.is_complete).read(builder);
            let is_first_shard = InnerVal::from_bool(self.is_first_shard).read(builder);
            let vk_root = self.vk_root.read(builder);
            ZKMCoreBasefoldWitnessVariable {
                vk,
                shard_proof_tuples,
                chip_cumulative_sums_per_shard,
                is_complete,
                is_first_shard,
                vk_root,
            }
        }

        fn write(&self, witness: &mut impl WitnessWriter<C>) {
            self.vk.write(witness);
            self.shard_proofs.write(witness);
            // Write per-shard chip_cumulative_sums in matching order.
            for sp in self.shard_proofs.iter() {
                for (_name, sums) in sp.chip_cumulative_sums.iter() {
                    sums.write(witness);
                }
            }
            InnerVal::from_bool(self.is_complete).write(witness);
            InnerVal::from_bool(self.is_first_shard).write(witness);
            self.vk_root.write(witness);
        }
    }

    impl<C, SC> Witnessable<C> for ZKMCompressBasefoldWitnessValues<SC>
    where
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
        SC: zkm_pcs::StarkGenericConfig
            + KoalaBearFriParametersVariable<C>
            + crate::hash::FieldHasher<p3_koala_bear::KoalaBear>,
        Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
        StarkVerifyingKey<SC>: Witnessable<C, WitnessVariable = VerifyingKeyVariable<C, SC>>,
        crate::machine::ZKMMerkleProofWitnessValues<SC>:
            Witnessable<C, WitnessVariable = crate::machine::ZKMMerkleProofWitnessVariable<C, SC>>,
    {
        type WitnessVariable = ZKMCompressBasefoldWitnessVariable<C, SC>;

        fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
            let vks_and_proofs = self.vks_and_proofs.read(builder);
            // witness chip_cumulative_sums per input.
            let chip_cumulative_sums_per_input: Vec<_> = self
                .vks_and_proofs
                .iter()
                .map(|(_, sp)| {
                    sp.chip_cumulative_sums
                        .iter()
                        .map(|(name, sums)| (name.clone(), sums.read(builder)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .collect();
            // Mirror chip_heights per input (plain RAW-height map, no
            // witness-stream consumption — host-side metadata threaded
            // into chip_height_bits_from_heights at the lift site).
            let chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>> =
                self.vks_and_proofs.iter().map(|(_, sp)| sp.chip_heights.clone()).collect();
            // Read vk-merkle witness so verify_compress_basefold can
            // bind each child VK hash to vk_merkle_data.root.
            let vk_merkle_data = self.vk_merkle_data.read(builder);
            let is_complete = InnerVal::from_bool(self.is_complete).read(builder);
            ZKMCompressBasefoldWitnessVariable {
                vks_and_proofs,
                chip_cumulative_sums_per_input,
                chip_heights_per_input,
                vk_merkle_data,
                is_complete,
            }
        }

        fn write(&self, witness: &mut impl WitnessWriter<C>) {
            self.vks_and_proofs.write(witness);
            // Write chip_cumulative_sums per input.
            for (_, sp) in self.vks_and_proofs.iter() {
                for (_name, sums) in sp.chip_cumulative_sums.iter() {
                    sums.write(witness);
                }
            }
            // chip_heights is host-side metadata; no witness-stream
            // write (the recursion circuit consumes it via constants
            // emitted at compile-time inside chip_height_bits_from_heights).
            // Write vk-merkle witness in matching read order.
            self.vk_merkle_data.write(witness);
            InnerVal::from_bool(self.is_complete).write(witness);
        }
    }

    impl<C> Witnessable<C> for ZKMDeferredBasefoldWitnessValues<KoalaBearPoseidon2>
    where
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
    {
        type WitnessVariable = ZKMDeferredBasefoldWitnessVariable<C, KoalaBearPoseidon2>;

        fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
            let vks_and_proofs = self.vks_and_proofs.read(builder);
            // witness chip_cumulative_sums per input.
            let chip_cumulative_sums_per_input: Vec<_> = self
                .vks_and_proofs
                .iter()
                .map(|(_, sp)| {
                    sp.chip_cumulative_sums
                        .iter()
                        .map(|(name, sums)| (name.clone(), sums.read(builder)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .collect();
            // Mirror chip_heights per input (host-side metadata).
            let chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>> =
                self.vks_and_proofs.iter().map(|(_, sp)| sp.chip_heights.clone()).collect();
            ZKMDeferredBasefoldWitnessVariable {
                vks_and_proofs,
                chip_cumulative_sums_per_input,
                chip_heights_per_input,
                vk_merkle_data: self.vk_merkle_data.read(builder),
                start_reconstruct_deferred_digest: self
                    .start_reconstruct_deferred_digest
                    .read(builder),
                zkm_vk_digest: self.zkm_vk_digest.read(builder),
                committed_value_digest: self.committed_value_digest.read(builder),
                deferred_proofs_digest: self.deferred_proofs_digest.read(builder),
                end_pc: self.end_pc.read(builder),
                end_shard: self.end_shard.read(builder),
                end_execution_shard: self.end_execution_shard.read(builder),
                init_addr_bits: self.init_addr_bits.read(builder),
                finalize_addr_bits: self.finalize_addr_bits.read(builder),
                is_complete: InnerVal::from_bool(self.is_complete).read(builder),
            }
        }

        fn write(&self, witness: &mut impl WitnessWriter<C>) {
            self.vks_and_proofs.write(witness);
            // Write chip_cumulative_sums per input.
            for (_, sp) in self.vks_and_proofs.iter() {
                for (_name, sums) in sp.chip_cumulative_sums.iter() {
                    sums.write(witness);
                }
            }
            self.vk_merkle_data.write(witness);
            self.start_reconstruct_deferred_digest.write(witness);
            self.zkm_vk_digest.write(witness);
            self.committed_value_digest.write(witness);
            self.deferred_proofs_digest.write(witness);
            self.end_pc.write(witness);
            self.end_shard.write(witness);
            self.end_execution_shard.write(witness);
            self.init_addr_bits.write(witness);
            self.finalize_addr_bits.write(witness);
            InnerVal::from_bool(self.is_complete).write(witness);
        }
    }

    impl<C> Witnessable<C> for ZKMWrapBasefoldWitnessValues<KoalaBearPoseidon2>
    where
        C: CircuitConfig<F = InnerVal, EF = InnerChallenge, Bit = Felt<InnerVal>>,
    {
        type WitnessVariable = ZKMWrapBasefoldWitnessVariable<C, KoalaBearPoseidon2>;

        fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
            let vks_and_proofs = self.vks_and_proofs.read(builder);
            // witness chip_cumulative_sums per input.
            let chip_cumulative_sums_per_input: Vec<_> = self
                .vks_and_proofs
                .iter()
                .map(|(_, sp)| {
                    sp.chip_cumulative_sums
                        .iter()
                        .map(|(name, sums)| (name.clone(), sums.read(builder)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .collect();
            // Mirror chip_heights per input (host-side metadata).
            let chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>> =
                self.vks_and_proofs.iter().map(|(_, sp)| sp.chip_heights.clone()).collect();
            // Read vk-merkle witness so verify_wrap_basefold can bind
            // the input VK hash against vk_merkle_data.root.
            let vk_merkle_data = self.vk_merkle_data.read(builder);
            ZKMWrapBasefoldWitnessVariable {
                vks_and_proofs,
                chip_cumulative_sums_per_input,
                chip_heights_per_input,
                vk_merkle_data,
            }
        }

        fn write(&self, witness: &mut impl WitnessWriter<C>) {
            self.vks_and_proofs.write(witness);
            // Write chip_cumulative_sums per input.
            for (_, sp) in self.vks_and_proofs.iter() {
                for (_name, sums) in sp.chip_cumulative_sums.iter() {
                    sums.write(witness);
                }
            }
            // Write vk-merkle witness in matching order.
            self.vk_merkle_data.write(witness);
        }
    }

    // Witnessable for the OUTER wrap witness (gnark layer). Mirrors the
    // inner impl above but for KoalaBearPoseidon2Outer over an
    // outer-config builder (Bit = Var<N>). vk_merkle_data is read for
    // witness-shape symmetry; the gnark wrap verifier skips verifying it
    // (skip_vk_merkle=true) — binding is the build_outer_circuit commit/pc_start
    // constraint + the public vkey_hash, mirroring SP1WrapVerifier (no merkle).
    type OuterCfg = zkm_recursion_compiler::config::OuterConfig;
    impl Witnessable<OuterCfg>
        for ZKMWrapBasefoldWitnessValues<zkm_recursion_core::stark::KoalaBearPoseidon2Outer>
    {
        type WitnessVariable = ZKMWrapBasefoldWitnessVariable<
            OuterCfg,
            zkm_recursion_core::stark::KoalaBearPoseidon2Outer,
        >;

        fn read(&self, builder: &mut Builder<OuterCfg>) -> Self::WitnessVariable {
            let vks_and_proofs = self.vks_and_proofs.read(builder);
            let chip_cumulative_sums_per_input: Vec<_> = self
                .vks_and_proofs
                .iter()
                .map(|(_, sp)| {
                    sp.chip_cumulative_sums
                        .iter()
                        .map(|(name, sums)| (name.clone(), sums.read(builder)))
                        .collect::<std::collections::BTreeMap<_, _>>()
                })
                .collect();
            let chip_heights_per_input: Vec<std::collections::BTreeMap<String, usize>> =
                self.vks_and_proofs.iter().map(|(_, sp)| sp.chip_heights.clone()).collect();
            let vk_merkle_data = self.vk_merkle_data.read(builder);
            ZKMWrapBasefoldWitnessVariable {
                vks_and_proofs,
                chip_cumulative_sums_per_input,
                chip_heights_per_input,
                vk_merkle_data,
            }
        }

        fn write(&self, witness: &mut impl WitnessWriter<OuterCfg>) {
            self.vks_and_proofs.write(witness);
            for (_, sp) in self.vks_and_proofs.iter() {
                for (_name, sums) in sp.chip_cumulative_sums.iter() {
                    sums.write(witness);
                }
            }
            self.vk_merkle_data.write(witness);
        }
    }
}
