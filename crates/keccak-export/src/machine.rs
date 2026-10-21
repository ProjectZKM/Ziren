//! Trusted profile/AIR export for an EVM reference implementation. No proof
//! validity flag from this exporter is accepted by the EVM.
use crate::wire::{Mode, Profile};
use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_air::{Air, BaseAir, PairCol, VirtualPairCol};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear as F;
use p3_uni_stark::{AirLayout, SymbolicAirBuilder};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path};
use zkm_core_machine::reduce::ZKMReduceProof;
use zkm_pcs::{
    air::{LookupScope, MachineAir},
    shard_level::shard_proof::EvaluationProof,
    InnerChallenge as E, MachineProver,
};
use zkm_prover::{
    components::DefaultProverComponents, HashableKey, ShrinkKeccakSC, ZKMProver, ZKMVerifyingKey,
};

fn affine(c: &VirtualPairCol<F>) -> Value {
    json!({"constant":c.constant_term().as_canonical_u32(),"weights":c.column_weights().iter().map(|(col,w)|{
  let (kind,index)=match col{PairCol::Main(i)=>(0,i),PairCol::Preprocessed(i)=>(1,i)};
  json!([kind,index,w.as_canonical_u32()])
 }).collect::<Vec<_>>()})
}
struct Rpn {
    ops: Vec<(u8, u32, u32)>,
    memo: HashMap<usize, u32>,
    main: usize,
    prep: usize,
}
impl Rpn {
    fn emit(&mut self, e: &SymbolicExpression<F>) -> u32 {
        let ptr = e as *const _ as usize;
        if let Some(&id) = self.memo.get(&ptr) {
            return id;
        }
        let id = match e {
            SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => 0x80000000 | c.as_canonical_u32(),
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset } => {
                    assert_eq!(offset, 0, "next-row AIR requires an explicit mapping");
                    v.index as u32
                }
                BaseEntry::Preprocessed { offset } => {
                    assert_eq!(offset, 0, "next-row AIR requires an explicit mapping");
                    (self.main + v.index) as u32
                }
                BaseEntry::Public => (self.main + self.prep + v.index) as u32,
                _ => panic!("periodic columns need an explicit verifier mapping"),
            },
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let a = self.emit(x);
                let b = self.emit(y);
                let op = match e {
                    SymbolicExpr::Add { .. } => 0,
                    SymbolicExpr::Sub { .. } => 1,
                    _ => 2,
                };
                self.op(op, a, b)
            }
            SymbolicExpr::Neg { x, .. } => {
                let b = self.emit(x);
                self.op(1, 0x80000000, b)
            }
            _ => panic!("row selectors are unsupported by the native shard folder"),
        };
        self.memo.insert(ptr, id);
        id
    }
    fn op(&mut self, op: u8, a: u32, b: u32) -> u32 {
        let id = (self.main + self.prep + zkm_pcs::PROOF_MAX_NUM_PVS + self.ops.len()) as u32;
        self.ops.push((op, a, b));
        id
    }
    fn run(&self, inputs: &[E], roots: &[u32], alpha: E) -> E {
        let mut v = inputs.to_vec();
        let get = |v: &[E], id: u32| {
            if id & 0x80000000 != 0 {
                E::from_u32(id & 0x7fffffff)
            } else {
                v[id as usize]
            }
        };
        for &(op, a, b) in &self.ops {
            let a = get(&v, a);
            let b = get(&v, b);
            v.push(match op {
                0 => a + b,
                1 => a - b,
                2 => a * b,
                _ => unreachable!(),
            });
        }
        roots.iter().fold(E::ZERO, |a, &id| a * alpha + get(&v, id))
    }
}

pub fn export(
    directory: &Path,
    prover: &ZKMProver<DefaultProverComponents>,
    terminal: &ZKMReduceProof<ShrinkKeccakSC>,
    app: &ZKMVerifyingKey,
    expected_terminal_key: &[u8; 32],
    public_values: &zkm_primitives::io::ZKMPublicValues,
) -> anyhow::Result<()> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let parent = directory
        .parent()
        .ok_or_else(|| anyhow::anyhow!("export needs an external parent directory"))?;
    let repository = repository.canonicalize()?;
    let mut existing = directory;
    while !existing.exists() {
        existing = existing
            .parent()
            .ok_or_else(|| anyhow::anyhow!("export path has no existing ancestor"))?;
    }
    anyhow::ensure!(
        !existing.canonicalize()?.starts_with(&repository),
        "keep generated verifier data outside the repository"
    );
    prover.verify_shrink_keccak(terminal, app, expected_terminal_key, public_values)?;
    std::fs::create_dir_all(parent)?;
    std::fs::create_dir_all(directory)?;
    let profile = Profile::from_trusted_proof(&terminal.vk, &terminal.proof, Mode::Raw, false)?;
    for (name, shift) in [("marker", 0u32), ("marker_shift", 1_000_000u32)] {
        let mut packet = b"ZKET".to_vec();
        packet.extend([1, 0]);
        packet.extend(profile.id());
        for i in 0..profile.field_count {
            packet.extend((i as u32 + 1 + shift).to_le_bytes());
        }
        for i in 0..profile.digest_references {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(b"EVMDIGST");
            h[8..12].copy_from_slice(&(i as u32).to_le_bytes());
            packet.extend(h);
        }
        let mut marker = profile.decode(&packet)?;
        let bytes = match &marker.jagged_shard_proof.evaluation_proof {
            EvaluationProof::Bytes(b) => b,
            _ => unreachable!(),
        };
        let bundle = zkm_pcs::jagged_pcs::jagged::JaggedPcsProofGeneric::<
            zkm_pcs::kb31_keccak::KeccakMmcs,
        >::from_bytes_for_verification(bytes)
        .unwrap();
        marker.jagged_shard_proof.evaluation_proof = EvaluationProof::Empty;
        std::fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec(&json!({"proof":marker,"bundle":bundle}))?,
        )?;
    }
    let terminal_prover = zkm_prover::keccak_terminal_prover();
    let machine = terminal_prover.machine();
    let mut chips = Vec::new();
    for (index, chip) in
        machine.shard_chips_named(&terminal.proof.jagged_shard_proof.chip_heights).enumerate()
    {
        let main = chip.air.width();
        let prep = MachineAir::preprocessed_width(&chip.air);
        assert!(
            chip.sends.iter().chain(&chip.receives).any(|l| l.scope == LookupScope::Local),
            "native permutation early-return must apply"
        );
        let mut builder = SymbolicAirBuilder::<F>::new(AirLayout {
            main_width: main,
            preprocessed_width: prep,
            num_public_values: zkm_pcs::PROOF_MAX_NUM_PVS,
            ..Default::default()
        });
        chip.air.eval(&mut builder);
        let expressions = builder.base_constraints();
        assert!(builder.extension_constraints().is_empty());
        let mut rpn = Rpn { ops: Vec::new(), memo: HashMap::new(), main, prep };
        let roots = expressions.iter().map(|e| rpn.emit(e)).collect::<Vec<_>>();
        let opening = &terminal.proof.jagged_shard_proof.opened_values.chips[index];
        let alpha = E::from_basis_coefficients_fn(|i| F::from_usize(i + 7));
        let mut inputs = opening.main.local.clone();
        inputs.extend(&opening.preprocessed.local);
        inputs.extend(terminal.proof.public_values.iter().copied().map(E::from));
        let expected =
            zkm_pcs::shard_level::basefold_constraint_folder::eval_constraints_shard_host(
                chip,
                opening,
                alpha,
                &terminal.proof.public_values,
            );
        assert_eq!(
            rpn.run(&inputs, &roots, alpha),
            expected,
            "exported AIR/native constraint parity"
        );
        // Also compare on unrelated rows/public inputs, so the export cannot pass
        // merely because the reference proof happens to zero an omitted term.
        for trial in 1..=3usize {
            let mut changed = opening.clone();
            for (i, x) in changed
                .main
                .local
                .iter_mut()
                .chain(changed.preprocessed.local.iter_mut())
                .enumerate()
            {
                *x = E::from_basis_coefficients_fn(|j| {
                    F::from_usize((i + 11) * (j + 3) * (trial + 7) + trial)
                });
            }
            let pv = (0..terminal.proof.public_values.len())
                .map(|i| F::from_usize(i * 19 + trial * 31))
                .collect::<Vec<_>>();
            let alpha = E::from_basis_coefficients_fn(|j| F::from_usize(j * 3 + trial + 11));
            let mut inputs = changed.main.local.clone();
            inputs.extend(&changed.preprocessed.local);
            inputs.extend(pv.iter().copied().map(E::from));
            let expected =
                zkm_pcs::shard_level::basefold_constraint_folder::eval_constraints_shard_host(
                    chip, &changed, alpha, &pv,
                );
            assert_eq!(
                rpn.run(&inputs, &roots, alpha),
                expected,
                "independent-row AIR export parity"
            );
        }
        let lookups=chip.sends.iter().map(|l|(l,true)).chain(chip.receives.iter().map(|l|(l,false))).map(|(l,send)|{
   json!({"send":send,"kind":l.argument_index(),"multiplicity":affine(&l.multiplicity),"values":l.values.iter().map(affine).collect::<Vec<_>>()})
  }).collect::<Vec<_>>();
        chips.push(json!({"name":chip.name(),"main_width":main,"prep_width":prep,"air_ops":rpn.ops,"air_roots":roots,"lookups":lookups}));
    }
    let pv = zkm_recursion_core::air::RECURSION_PUBLIC_VALUES_COL_MAP;
    let hash = |h: &[u8]| format!("0x{}", hex::encode(h));
    let vk = &terminal.vk;
    let canonical = |xs: &[F]| xs.iter().map(|v| v.as_canonical_u32()).collect::<Vec<_>>();
    let app_digest = app.hash_koalabear();
    let metadata = json!({"profile_id":hash(&profile.id()),"field_count":profile.field_count,"hash_count":profile.digest_references,"chips":chips,
  "vk":{"root":hash(&vk.commit.roots()[0]),"pc_start":vk.pc_start.as_canonical_u32(),"global":canonical(&vk.initial_global_cumulative_sum.0.x.0).into_iter().chain(canonical(&vk.initial_global_cumulative_sum.0.y.0)).collect::<Vec<_>>(),"prep":vk.chip_information.iter().map(|(n,_,(w,h))|json!([n,w,h])).collect::<Vec<_>>()},
  "public_binding":{"application":canonical(&app_digest),"recursion_root":canonical(&prover.recursion_vk_root),"application_offset":pv.zkm_vk_digest[0],"root_offset":pv.vk_root[0],"complete_offset":pv.is_complete,"execution_offset":pv.contains_execution_shard,"exit_offset":pv.exit_code,"committed_offset":pv.committed_value_digest[0].0[0],"digest_offset":pv.digest[0],"hash_inputs":zkm_recursion_core::air::NUM_PV_ELMS_TO_HASH},
  "gkr_grinding_bits":zkm_pcs::logup_gkr::gkr_grinding_bits(),
  "whir_config":zkm_pcs::whir::jagged::whir_config_for_profile(zkm_pcs::whir::jagged::WhirProfile::Keccak,21),
  "poseidon_constants":zkm_primitives::RC_16_30.iter().map(|r|canonical(r)).collect::<Vec<_>>()});
    std::fs::write(directory.join("machine.json"), serde_json::to_vec(&metadata)?)?;
    Ok(())
}
