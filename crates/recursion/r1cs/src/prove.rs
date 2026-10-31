//! Proving lowered relations with the word backend, the committed bits
//! under the binary stage's Boolean WHIR and Blake3 transcript.

use p3_binary_pcs::{BooleanBackend, BooleanMultilinearPcs};
use p3_word::{ConstraintSystem, Word64};
use p3_word_backend::{PackedWitness, WordDevice, WordProof, WordProofKey};
use zkm_binary_stark::{
    challenger,
    config::{bit_commitment, BitPcs},
    BinarySchedule, Challenger, F,
};

use p3_maybe_rayon::prelude::*;

use crate::{builder::Built, lower::Lowered};

/// The commitment of a word proof.
pub type Commitment = <BitPcs as BooleanBackend<F>>::Commitment;
/// Where a key's commitment opens on a device.
pub type OpeningDevice = <BitPcs as BooleanMultilinearPcs<F, Challenger>>::OpeningDevice;

/// What the commitment to a composed key's routing words keeps for its openings.
pub type RoutingData = <BitPcs as BooleanBackend<F>>::ProverData;

/// A word proof.
pub type Proof = WordProof<F, F, <BitPcs as BooleanBackend<F>>::Proof>;

/// The deferred values as the prover knows them.
pub type Hints = p3_word_backend::ShiftHints<F>;

/// The schedule a word proof commits under.
///
/// Decoding to the proven Johnson radius halves the queries of unique
/// decoding, which keeps a leaf's opening under the proof-size ceiling, and
/// the queries every node verifies.  Its grinds grow with the witness: a
/// composed leaf of `2^34` bits grinds 31, so the ceiling is 32.
pub fn schedule() -> BinarySchedule {
    let mut schedule = BinarySchedule {
        regime: zkm_binary_stark::WhirRegime::Johnson,
        log_inv_rate: 2,
        folding: 3,
        ..BinarySchedule::default()
    };
    schedule.budget.max_grinding_bits = 32;
    schedule
}

/// A key, the commitment it is proven under, and its relations.
pub struct WordKey {
    /// The compiled relations.
    pub key: WordProofKey<Word64>,
    /// The commitment of the key's trace.
    pub pcs: BitPcs,
    /// The key's constants: its public words past the outputs.
    pub constants: Vec<Word64>,
    /// The number of outputs, the public words before the constants.
    pub outputs: usize,
    /// The Blake3 digest naming the key: of a tag, the commitment's
    /// variables, the outputs, the constants and the relations.
    pub digest: [u8; 32],
    /// How a composed key's statement takes its words from the lowering's, when the key is
    /// one.
    pub layout: Option<ComposedLayout>,
}

/// How the statement of a composed key takes its words from the lowering's.
pub struct ComposedLayout {
    /// For each committed word of the statement, the lowering's word it holds.
    pub witness_of: Vec<u32>,
    /// For each public word of the statement, the lowering's public word it is.
    pub public_of: Vec<u32>,
    /// The commitment to the statement's routing words.
    pub routing: Commitment,
    /// The routing commitment's prover data, opened by every proof of the key.
    pub routing_data: RoutingData,
    /// The lowering's public words past the outputs, which its tape reads.
    pub tape_constants: Vec<Word64>,
}

impl WordKey {
    /// The key of `built`'s relations under `schedule`, whose first
    /// `outputs` public words are outputs.
    pub fn new(built: &Built, schedule: &BinarySchedule) -> Result<Self, String> {
        Self::with_outputs(built, schedule, zkm_recursion_core::DIGEST_SIZE)
    }

    /// [`Self::new`] for `outputs` public words before the constants.
    pub fn with_outputs(
        built: &Built,
        schedule: &BinarySchedule,
        outputs: usize,
    ) -> Result<Self, String> {
        let outputs = outputs.min(built.public.len());
        let digest = relations_digest(built, outputs);
        let system = tracing::info_span!("copy relations").in_scope(|| built.system.clone());
        Self::compile(system, schedule, built.public[outputs..].to_vec(), outputs, digest)
    }

    /// [`Self::new`] with `built`'s relations moved into the key, an empty system left in
    /// their place; its words stay.
    pub fn taking(built: &mut Built, schedule: &BinarySchedule) -> Result<Self, String> {
        let outputs = zkm_recursion_core::DIGEST_SIZE.min(built.public.len());
        let digest = relations_digest(built, outputs);
        let empty = ConstraintSystem::new(0, 0, Vec::new(), Vec::new(), Vec::new())
            .map_err(|e| format!("an empty system: {e:?}"))?;
        let system = std::mem::replace(&mut built.system, empty);
        Self::compile(system, schedule, built.public[outputs..].to_vec(), outputs, digest)
    }

    fn compile(
        system: ConstraintSystem<Word64>,
        schedule: &BinarySchedule,
        constants: Vec<Word64>,
        outputs: usize,
        digest: [u8; 32],
    ) -> Result<Self, String> {
        let key = tracing::info_span!("compile key")
            .in_scope(|| WordProofKey::new(system))
            .map_err(|e| format!("key: {e:?}"))?;
        let pcs = tracing::info_span!("key commitment")
            .in_scope(|| bit_commitment(key.trace_variables(), schedule))
            .map_err(|e| e.to_string())?;
        Ok(Self { key, pcs, constants, outputs, digest, layout: None })
    }

    /// The key of the composition [`crate::lower_composed`] left in `lowered`, taken from it,
    /// under `schedule`: its digest is of a tag, the outputs, the constants and the key, the
    /// routing included.
    pub fn composed(lowered: &mut Lowered, schedule: &BinarySchedule) -> Result<Self, String> {
        let composed = lowered.composed.take().ok_or("the lowering was not composed")?;
        let outputs = zkm_recursion_core::DIGEST_SIZE.min(composed.public.len());
        let key = tracing::info_span!("compile composed key")
            .in_scope(|| WordProofKey::with_ports(composed.composition, composed.routing))
            .map_err(|e| format!("key: {e:?}"))?;
        let pcs = bit_commitment(key.trace_variables(), schedule).map_err(|e| e.to_string())?;
        let (routing, routing_data) = tracing::info_span!("commit routing")
            .in_scope(|| key.port_routing::<F, _, _>(&pcs, &mut challenger()))
            .map_err(|e| format!("routing: {e:?}"))?
            .ok_or("the composed key routes no ports")?;
        let constants = composed.public[outputs..].to_vec();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ziren composed word key");
        hasher.update(&(outputs as u64).to_le_bytes());
        for word in &constants {
            hasher.update(&word.get().to_le_bytes());
        }
        let bytes = postcard::to_allocvec(&key).map_err(|e| format!("encode the key: {e}"))?;
        hasher.update_rayon(&bytes);
        let digest = *hasher.finalize().as_bytes();
        let layout = ComposedLayout {
            witness_of: composed.witness_of,
            public_of: composed.public_of,
            routing,
            routing_data,
            tape_constants: lowered.built.public[outputs.min(lowered.built.public.len())..].to_vec(),
        };
        Ok(Self { key, pcs, constants, outputs, digest, layout: Some(layout) })
    }

    /// The public words past the outputs the lowering's tape reads: the statement's own
    /// unless the key is composed.
    pub fn tape_constants(&self) -> &[Word64] {
        self.layout.as_ref().map_or(&self.constants, |layout| &layout.tape_constants)
    }

    /// The statement's public words for the outputs `outputs`.
    pub fn public(&self, outputs: &[Word64]) -> Vec<Word64> {
        outputs.iter().chain(&self.constants).copied().collect()
    }

    /// The statement's public words, of the lowering's `public`.
    pub fn statement_public(&self, public: &[Word64]) -> Vec<Word64> {
        match &self.layout {
            Some(layout) => layout.public_of.iter().map(|&p| public[p as usize]).collect(),
            None => public.to_vec(),
        }
    }

    /// The commitment to the routing words of a composed key.
    pub fn routing(&self) -> Option<&Commitment> {
        self.layout.as_ref().map(|layout| &layout.routing)
    }

    /// Proves `built`'s words satisfy the key's relations, over the transcript `challenger`
    /// starts, on `devices` when given: the trees, relations and shifts on the first, the
    /// commitment's opening on the second.
    pub fn prove(
        &self,
        built: &Built,
        devices: Option<(&dyn WordDevice, &OpeningDevice)>,
        challenger: &mut Challenger,
    ) -> Result<(Commitment, Proof, Hints), String> {
        self.prove_words(&built.public, &built.witness, devices, challenger)
    }

    /// [`Self::prove`] for the public words `public` and the committed words `witness`.
    pub fn prove_words(
        &self,
        public: &[Word64],
        witness: &[Word64],
        devices: Option<(&dyn WordDevice, &OpeningDevice)>,
        challenger: &mut Challenger,
    ) -> Result<(Commitment, Proof, Hints), String> {
        if let Some(layout) = &self.layout {
            let (public, witness) = tracing::info_span!("gather composed words").in_scope(|| {
                let public: Vec<Word64> = layout.public_of.iter().map(|&p| public[p as usize]).collect();
                let witness: Vec<Word64> =
                    layout.witness_of.par_iter().map(|&w| witness[w as usize]).collect();
                (public, witness)
            });
            if let Some((device, _)) = devices {
                let gathered = tracing::info_span!("gather composed words on device")
                    .in_scope(|| device.gather_witness(&layout.witness_of));
                if !gathered {
                    return Err("the device holds no committed words to gather".into());
                }
            }
            return self.prove_statement(&public, &witness, devices, challenger);
        }
        self.prove_statement(public, witness, devices, challenger)
    }

    /// [`Self::prove_words`] for the statement's own public and committed words.
    fn prove_statement(
        &self,
        public: &[Word64],
        witness: &[Word64],
        devices: Option<(&dyn WordDevice, &OpeningDevice)>,
        challenger: &mut Challenger,
    ) -> Result<(Commitment, Proof, Hints), String> {
        let values = tracing::info_span!("pack witness")
            .in_scope(|| PackedWitness::new(self.key.statement(), public, witness))
            .map_err(|e| format!("witness: {e:?}"))?;
        match (&self.layout, devices) {
            (Some(layout), devices) => self.key.prove_routed::<F, F, _, _>(
                &self.pcs,
                &values,
                (&layout.routing, &layout.routing_data),
                devices,
                challenger,
            ),
            (None, Some((device, opening))) => self
                .key
                .prove_with_hints_on::<F, F, _, _>(&self.pcs, &values, device, opening, challenger),
            (None, None) => self.key.prove_with_hints::<F, F, _, _>(&self.pcs, &values, challenger),
        }
        .map_err(|e| format!("prove: {e:?}"))
    }

    /// The height of the caps the key's commitments are made with.
    #[must_use]
    pub fn cap_height(&self) -> usize {
        self.pcs.inner().mmcs().cap_height()
    }

    /// Verifies a proof against the public words.
    pub fn verify(
        &self,
        commitment: &Commitment,
        public: &[Word64],
        proof: &Proof,
    ) -> Result<(), String> {
        match &self.layout {
            Some(layout) => self.key.verify_routed::<F, F, _, _>(
                &self.pcs,
                commitment,
                &layout.routing,
                public,
                proof,
                &mut challenger(),
            ),
            None => self
                .key
                .verify::<F, F, _, _>(&self.pcs, commitment, public, proof, &mut challenger()),
        }
        .map_err(|e| format!("verify: {e:?}"))
    }
}

/// The tag a key file starts with; a change of the format changes it.
const KEY_FILE_TAG: &[u8; 16] = b"ziren word key 1";

impl WordKey {
    /// The key as a file: [`KEY_FILE_TAG`], the Blake3 digest of the body, then the body,
    /// the key's digest, outputs, constants and compiled relations.  The commitment is
    /// rebuilt from the schedule on reading.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        if self.layout.is_some() {
            return Err("a composed key is not written".into());
        }
        let constants: Vec<u64> = self.constants.iter().map(|w| w.get()).collect();
        let body = tracing::info_span!("encode key")
            .in_scope(|| postcard::to_allocvec(&(&self.digest, self.outputs as u64, &constants, &self.key)))
            .map_err(|e| format!("encode the key: {e}"))?;
        if std::env::var_os("ZIREN_WORD_KEY_SIZES").is_some() {
            let statement = postcard::to_allocvec(self.key.statement()).map_or(0, |b| b.len());
            tracing::info!("word key: {} bytes, the statement {statement} of them", body.len());
        }
        let mut out = Vec::with_capacity(KEY_FILE_TAG.len() + 32 + body.len());
        out.extend_from_slice(KEY_FILE_TAG);
        out.extend_from_slice(blake3::Hasher::new().update_rayon(&body).finalize().as_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The key [`Self::to_bytes`] wrote, its commitment made under `schedule`.
    pub fn from_bytes(bytes: &[u8], schedule: &BinarySchedule) -> Result<Self, String> {
        let header = KEY_FILE_TAG.len() + 32;
        if bytes.len() < header || &bytes[..KEY_FILE_TAG.len()] != KEY_FILE_TAG {
            return Err("not a word key file of this format".into());
        }
        let body = &bytes[header..];
        let sum = tracing::info_span!("check key file")
            .in_scope(|| blake3::Hasher::new().update_rayon(body).finalize());
        if sum.as_bytes() != &bytes[KEY_FILE_TAG.len()..header] {
            return Err("the key file is corrupt".into());
        }
        let (digest, outputs, constants, key): ([u8; 32], u64, Vec<u64>, WordProofKey<Word64>) =
            tracing::info_span!("decode key")
                .in_scope(|| postcard::from_bytes(body))
                .map_err(|e| format!("decode the key: {e}"))?;
        let pcs = bit_commitment(key.trace_variables(), schedule).map_err(|e| e.to_string())?;
        Ok(Self {
            key,
            pcs,
            constants: constants.into_iter().map(Word64::new).collect(),
            outputs: outputs as usize,
            digest,
            layout: None,
        })
    }
}

/// Keys by digest: those made or read so far, and a directory that keeps every key made
/// across runs, one `<digest>.wkey` file each; and, by the digest of the program lowered,
/// the key it is proved under and the tape that computes its witness.
pub struct WordKeys {
    keys: Vec<std::sync::Arc<WordKey>>,
    dir: Option<std::path::PathBuf>,
    programs: std::collections::HashMap<[u8; 32], (usize, std::sync::Arc<crate::tape::Tape>)>,
}

impl WordKeys {
    /// No keys yet, kept in `dir` when given.
    pub fn new(dir: Option<std::path::PathBuf>) -> Self {
        Self { keys: Vec::new(), dir, programs: std::collections::HashMap::new() }
    }

    /// The key position and tape of the program of digest `program`, if it was lowered.
    pub fn program(&self, program: &[u8; 32]) -> Option<(usize, std::sync::Arc<crate::tape::Tape>)> {
        self.programs.get(program).cloned()
    }

    /// Records that the program of digest `program` is proved under the key at `key` and
    /// its witness computed by `tape`.
    pub fn insert_program(&mut self, program: [u8; 32], key: usize, mut tape: crate::tape::Tape) {
        tracing::info_span!("schedule tape").in_scope(|| tape.schedule());
        self.insert_tape(program, key, std::sync::Arc::new(tape));
    }

    /// [`Self::insert_program`] for a `tape` already scheduled.
    pub fn insert_tape(
        &mut self,
        program: [u8; 32],
        key: usize,
        tape: std::sync::Arc<crate::tape::Tape>,
    ) {
        self.programs.insert(program, (key, tape));
    }

    /// What makes this set's keys on another thread.
    pub fn maker(&self) -> KeyMaker {
        KeyMaker { dir: self.dir.clone() }
    }

    /// The position of the key named `digest`, if it is known.
    pub fn known(&self, digest: &[u8; 32]) -> Option<usize> {
        self.keys.iter().position(|key| key.digest == *digest)
    }

    /// The position of the key of `key`'s digest: the one known, else `key`, added.
    pub fn insert(&mut self, key: WordKey) -> usize {
        if let Some(position) = self.known(&key.digest) {
            return position;
        }
        self.keys.push(std::sync::Arc::new(key));
        self.keys.len() - 1
    }

    /// [`Self::new`] in the directory `ZKM_WORD_KEY_DIR` names, if it does.
    pub fn from_env() -> Self {
        Self::new(std::env::var_os("ZKM_WORD_KEY_DIR").map(Into::into))
    }

    /// The keys known so far.
    pub fn as_slice(&self) -> &[std::sync::Arc<WordKey>] {
        &self.keys
    }

    /// The position of the key named `digest`: one known, else the one its file holds, else
    /// the key of `built` under `schedule`, made and written to its file.
    pub fn position(
        &mut self,
        built: &Built,
        digest: [u8; 32],
        schedule: &BinarySchedule,
    ) -> Result<usize, String> {
        if let Some(position) = self.known(&digest) {
            return Ok(position);
        }
        let key = self.maker().make(built, digest, schedule)?;
        Ok(self.insert(key))
    }
}

/// Makes the keys of a [`WordKeys`] apart from it, so several are made at once: each read from
/// the set's directory when its file is there, else built and written to it.
#[derive(Clone, Debug)]
pub struct KeyMaker {
    dir: Option<std::path::PathBuf>,
}

impl KeyMaker {
    fn path(&self, digest: &[u8; 32]) -> Option<std::path::PathBuf> {
        let name: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.as_ref().map(|dir| dir.join(format!("{name}.wkey")))
    }

    /// The key named `digest`: the one its file holds, else the key of `built` under
    /// `schedule`, made and written to its file.
    pub fn make(
        &self,
        built: &Built,
        digest: [u8; 32],
        schedule: &BinarySchedule,
    ) -> Result<WordKey, String> {
        self.read_or(digest, schedule, || WordKey::new(built, schedule))
    }

    /// [`Self::make`], a key made taking `built`'s relations as [`WordKey::taking`] does.
    pub fn make_taking(
        &self,
        built: &mut Built,
        digest: [u8; 32],
        schedule: &BinarySchedule,
    ) -> Result<WordKey, String> {
        self.read_or(digest, schedule, || WordKey::taking(built, schedule))
    }

    fn read_or(
        &self,
        digest: [u8; 32],
        schedule: &BinarySchedule,
        build: impl FnOnce() -> Result<WordKey, String>,
    ) -> Result<WordKey, String> {
        let path = self.path(&digest);
        let read = match &path {
            Some(path) if path.exists() => {
                let bytes = tracing::info_span!("read key file")
                    .in_scope(|| std::fs::read(path))
                    .map_err(|e| format!("read {}: {e}", path.display()))?;
                let key = WordKey::from_bytes(&bytes, schedule)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                if key.digest != digest {
                    return Err(format!("{} holds another key", path.display()));
                }
                Some(key)
            }
            _ => None,
        };
        match read {
            Some(key) => Ok(key),
            None => {
                let key = build()?;
                if let Some(path) = &path {
                    let bytes = key.to_bytes()?;
                    tracing::info_span!("write key file").in_scope(|| write_atomically(path, &bytes))?;
                }
                Ok(key)
            }
        }
    }
}

/// Writes `bytes` to a temporary file beside `path`, then renames it into place, so a reader
/// never sees a partial key.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let temporary = path.with_extension(format!("wkey.{}.part", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(|e| format!("write {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

/// The digest naming the key of `built`'s relations with `outputs` outputs:
/// the dimensions, the constants and the relations as [`Built::write`]
/// writes them.  The key's commitment is a function of them.
#[must_use]
pub fn relations_digest(built: &Built, outputs: usize) -> [u8; 32] {
    let system = &built.system;
    let outputs = outputs.min(built.public.len());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ziren word key");
    for count in [
        outputs,
        built.public.len(),
        built.witness.len(),
        system.zero_constraints().len(),
        system.and_constraints().len(),
        system.integer_mul_constraints().len(),
    ] {
        hasher.update(&(count as u64).to_le_bytes());
    }
    for word in &built.public[outputs..] {
        hasher.update(&word.get().to_le_bytes());
    }
    let mut out = std::io::BufWriter::with_capacity(1 << 20, &mut hasher);
    built.write_relations(&mut out).expect("hashing does not fail");
    drop(out);
    *hasher.finalize().as_bytes()
}

/// The serialized size of a proof, in bytes.
pub fn proof_size(proof: &Proof) -> usize {
    postcard::to_allocvec(proof).map_or(0, |bytes| bytes.len())
}

/// The bytes of `proof`'s trace opening, its routing opening and its port reduction.
#[must_use]
pub fn proof_parts(proof: &Proof) -> [usize; 3] {
    let size = |part: Option<Vec<u8>>| part.map_or(0, |bytes| bytes.len());
    [
        size(postcard::to_allocvec(proof.opening()).ok()),
        size(proof.port_opening().and_then(|opening| postcard::to_allocvec(opening).ok())),
        size(proof.ports().and_then(|ports| postcard::to_allocvec(ports).ok())),
    ]
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::{builder::Builder, kb::P};

    #[test]
    fn small_relations_prove_and_verify() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut builder = Builder::new(1);
        let mut acc = builder.hint(1);
        for _ in 0..64 {
            let x = builder.hint(rng.gen_range(0..P));
            let y = builder.hint(rng.gen_range(0..P));
            let sum = builder.add(acc, x);
            acc = builder.mul(sum, y);
        }
        let output = builder.output(0, acc.value);
        builder.assert_zero(acc.terms().chain([output]));
        let built = builder.build().unwrap();
        let key = WordKey::new(&built, &schedule()).unwrap();
        let (commitment, proof, _) = key.prove(&built, None, &mut challenger()).unwrap();
        key.verify(&commitment, &built.public, &proof).unwrap();
        let read = WordKey::from_bytes(&key.to_bytes().unwrap(), &schedule()).unwrap();
        assert_eq!(read.digest, key.digest);
        assert!(read.key == key.key, "the key reads back as written");
        let (commitment, proof, _) = read.prove(&built, None, &mut challenger()).unwrap();
        key.verify(&commitment, &built.public, &proof).unwrap();
        let mut bytes = key.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(WordKey::from_bytes(&bytes, &schedule()).is_err());
        let mut wrong = built.public.clone();
        wrong[0] = Word64::new(wrong[0].get() ^ 1);
        assert!(key.verify(&commitment, &wrong, &proof).is_err());
    }

    /// The opening's queries, grinding and byte bound at the leaf's arity, per schedule.
    #[test]
    #[ignore]
    fn leaf_schedule_sizes() {
        let arity = std::env::var("ZIREN_WORD_ARITY").map_or(31, |a| a.parse().unwrap());
        for regime in
            [zkm_binary_stark::WhirRegime::UniqueDecoding, zkm_binary_stark::WhirRegime::Johnson]
        {
            for log_inv_rate in 1..=6 {
                for folding in 2..=8 {
                    let schedule =
                        BinarySchedule { regime, log_inv_rate, folding, ..Default::default() };
                    match bit_commitment(arity, &schedule) {
                        Ok(pcs) => {
                            let shape = pcs
                                .proof_shape(1, false)
                                .expect("a built schedule has a shape");
                            println!(
                                "{regime:?} rate 2^-{log_inv_rate} fold {folding}: {} queries, {} grind bits, {} bytes",
                                shape.stir_queries,
                                shape.grinding_bits,
                                shape.max_bytes(19, 19, 32).expect("the shape fits a usize")
                            );
                        }
                        Err(e) => println!("{regime:?} rate 2^-{log_inv_rate} fold {folding}: {e}"),
                    }
                }
            }
        }
    }
}
