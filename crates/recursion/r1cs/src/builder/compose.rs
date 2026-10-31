//! A lowering's gadgets as one routed composition: a call per distinct gadget, each
//! instance's words in its own slots, and each word a gadget reads from another gadget
//! copied into a port of the reader, which the routing ties to the word it copies.
//!
//! A gadget is canonical over its slots: its own words in order, then one import slot per
//! distinct word it reads from elsewhere, numbered by first read.  A constant is read from
//! its pool word, so only a pool gadget reads a public word, and only the gadget writing the
//! outputs writes them; the composition's public words are the outputs, then the constants.
//! A copy the lowering made into a port of its own is no relation of the gadget: the routing
//! carries it.

use std::collections::HashMap;

use p3_word::{
    AndConstraint, Component, ComponentCall, ComponentError, Composition, CompositionError,
    ConstraintSystem, IntegerMulConstraint, Operand, Segment, SystemError, ValueIndex, Word64,
    ZeroConstraint,
};
use p3_word_backend::{PortError, PortRef, PortRouting};

use super::{by_owner, template_term, Builder, Term};

/// A lowering as calls of its gadgets, with the words that satisfy them.
pub struct Composed {
    /// The calls.
    pub composition: Composition<Word64>,
    /// The copies between the calls' ports.
    pub routing: PortRouting,
    /// The public words: the outputs, then the constants.
    pub public: Vec<Word64>,
    /// The committed words in the composition's layout.
    pub witness: Vec<Word64>,
}

/// Why a lowering does not compose.
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// The builder was not asked to track its gadgets.
    #[error("the builder did not track its gadgets")]
    Untracked,
    /// Words or relations were made outside every gadget.
    #[error("{0} words or relations belong to no gadget")]
    Unowned(usize),
    /// A gadget writing the outputs has more than one instance.
    #[error("a gadget of {0} instances writes the outputs")]
    SharedOutputs(usize),
    /// A gadget's relations do not form a system.
    #[error(transparent)]
    System(#[from] SystemError),
    /// A gadget's interface does not cover its public words.
    #[error(transparent)]
    Component(#[from] ComponentError),
    /// The calls do not lay out.
    #[error(transparent)]
    Composition(#[from] CompositionError),
    /// The copies do not route.
    #[error(transparent)]
    Ports(#[from] PortError),
}

/// The arity of each relation family.
const ARITY: [usize; 3] = [1, 3, 4];

/// What a gadget's term reads.
#[derive(Clone, Copy)]
enum Slot {
    Own(u32),
    Import(u32),
    Output(u32),
    Constant,
}

/// One gadget made canonical.
#[derive(Default)]
struct Canon {
    /// The code naming its template.
    code: Vec<u64>,
    /// The word each import slot copies.
    imports: Vec<u32>,
    /// The own slots that copy a word, with the word.
    links: Vec<(u32, u32)>,
    /// The public word a pool gadget's constant is.
    constant: Option<u32>,
    /// Whether it writes the outputs.
    outputs: bool,
    /// Its relations over its slots, each a list of operands, when asked for.
    body: Option<[Vec<Vec<Vec<Term>>>; 3]>,
}

/// One distinct gadget.
struct Template {
    gadget: usize,
    instances: usize,
    own: usize,
    imports: usize,
    outputs: bool,
    constant: bool,
    ports: Vec<bool>,
}

/// The words and relations of each gadget, and where each word sits in its gadget.
struct Layout {
    words: (Vec<u32>, Vec<u32>),
    relations: Vec<(Vec<u32>, Vec<u32>)>,
    slot_of: Vec<u32>,
    link: Vec<bool>,
}

impl Builder {
    /// The gadgets tracked since [`Self::track_gadgets`] as one routed composition of their
    /// templates over `outputs` outputs, with its words.
    ///
    /// # Errors
    ///
    /// Returns why the gadgets do not compose.
    pub fn compose(mut self, outputs: usize) -> Result<Composed, ComposeError> {
        self.flush_compressions();
        self.flush_ranges();
        let constants: Vec<u64> = self.public[outputs..].to_vec();
        for value in constants {
            self.pool_word(value);
        }
        let owners = self.owners.as_ref().ok_or(ComposeError::Untracked)?;
        let gadgets = owners.kinds.len();
        let words = by_owner(&owners.words, gadgets);
        let relations: Vec<_> =
            owners.relations.iter().map(|owner_of| by_owner(owner_of, gadgets)).collect();
        let unowned = (words.0[gadgets + 1] - words.0[gadgets]) as usize
            + relations.iter().map(|(start, _)| (start[gadgets + 1] - start[gadgets]) as usize).sum::<usize>();
        if unowned > 0 {
            return Err(ComposeError::Unowned(unowned));
        }
        let mut slot_of = vec![0_u32; self.witness.len()];
        for gadget in 0..gadgets {
            let own = &words.1[words.0[gadget] as usize..words.0[gadget + 1] as usize];
            for (slot, &word) in own.iter().enumerate() {
                slot_of[word as usize] = slot as u32;
            }
        }
        let mut link = vec![false; self.zero.ends.len()];
        for &relation in &owners.links {
            link[relation as usize] = true;
        }
        let pool: HashMap<u32, u32> = self
            .pool
            .iter()
            .filter_map(|(value, word)| {
                let constant = *self.constants.get(value)?;
                Some((constant as u32, word.plain()?.index().position()))
            })
            .collect();
        let layout = Layout { words, relations, slot_of, link };

        let mut ids: HashMap<Vec<u64>, usize> = HashMap::new();
        let mut templates: Vec<Template> = Vec::new();
        let mut template_of = vec![u32::MAX; gadgets];
        let mut instance_of = vec![0_u32; gadgets];
        let mut sources: Vec<(u32, u32)> = Vec::new();
        let mut source_start = vec![0_u32; gadgets + 1];
        let mut canon = Canon::default();
        for gadget in 0..gadgets {
            self.canon(gadget, &layout, &pool, outputs, false, &mut canon);
            let own = layout.words.0[gadget + 1] - layout.words.0[gadget];
            if own == 0 && canon.code.iter().all(|&x| x == 0) {
                source_start[gadget + 1] = sources.len() as u32;
                continue;
            }
            let id = *ids.entry(canon.code.clone()).or_insert_with(|| {
                templates.push(Template {
                    gadget,
                    instances: 0,
                    own: own as usize,
                    imports: canon.imports.len(),
                    outputs: canon.outputs,
                    constant: canon.constant.is_some(),
                    ports: vec![false; own as usize + canon.imports.len()],
                });
                templates.len() - 1
            });
            template_of[gadget] = id as u32;
            instance_of[gadget] = templates[id].instances as u32;
            templates[id].instances += 1;
            sources.extend(canon.imports.iter().enumerate().map(|(k, &word)| (own + k as u32, word)));
            sources.extend(canon.links.iter().copied());
            source_start[gadget + 1] = sources.len() as u32;
        }
        let owner = &owners.words;
        for gadget in 0..gadgets {
            if template_of[gadget] == u32::MAX {
                continue;
            }
            for &(slot, word) in &sources[source_start[gadget] as usize..source_start[gadget + 1] as usize] {
                templates[template_of[gadget] as usize].ports[slot as usize] = true;
                let producer = template_of[owner[word as usize] as usize] as usize;
                templates[producer].ports[layout.slot_of[word as usize] as usize] = true;
            }
        }
        if let Some(writer) = templates.iter().find(|t| t.outputs && t.instances > 1) {
            return Err(ComposeError::SharedOutputs(writer.instances));
        }

        let mut order: Vec<usize> = (0..templates.len()).collect();
        order.sort_by_key(|&t| (!templates[t].outputs, !templates[t].constant, templates[t].gadget));
        let mut call_of = vec![0_usize; templates.len()];
        for (call, &t) in order.iter().enumerate() {
            call_of[t] = call;
        }
        let mut calls = Vec::with_capacity(order.len());
        for &t in &order {
            let template = &templates[t];
            self.canon(template.gadget, &layout, &pool, outputs, true, &mut canon);
            let [zero, and, mul] = canon.body.take().expect("the body was asked for");
            let public = if template.outputs { outputs } else { usize::from(template.constant) };
            let operands = |relation: Vec<Vec<Term>>| relation.into_iter().map(Operand::new);
            let body = ConstraintSystem::new(
                public,
                template.own + template.imports,
                zero.into_iter()
                    .map(|relation| {
                        let [value] = operands(relation).collect::<Vec<_>>().try_into().expect("one operand");
                        ZeroConstraint::new(value)
                    })
                    .collect(),
                and.into_iter()
                    .map(|relation| {
                        let [l, r, o] = operands(relation).collect::<Vec<_>>().try_into().expect("three operands");
                        AndConstraint::new(l, r, o)
                    })
                    .collect(),
                mul.into_iter()
                    .map(|relation| {
                        let [l, r, lo, hi] =
                            operands(relation).collect::<Vec<_>>().try_into().expect("four operands");
                        IntegerMulConstraint::new(l, r, lo, hi)
                    })
                    .collect(),
            )?;
            let (inputs, written) = if template.outputs { (0, outputs) } else { (public, 0) };
            calls.push(ComponentCall::new(Component::new(body, inputs, written)?, template.instances));
        }
        let composition = Composition::interleaved(calls)?;

        let port_index: Vec<Vec<u32>> = templates
            .iter()
            .map(|t| {
                let mut next = 0;
                t.ports.iter().map(|&port| {
                    let index = next;
                    next += u32::from(port);
                    index
                }).collect()
            })
            .collect();
        let ports: Vec<Vec<u32>> = order
            .iter()
            .map(|&t| {
                templates[t].ports.iter().enumerate().filter(|(_, &p)| p).map(|(s, _)| s as u32).collect()
            })
            .collect();
        let port_ref = |gadget: usize, slot: u32| {
            let t = template_of[gadget] as usize;
            PortRef {
                call: call_of[t],
                instance: instance_of[gadget] as usize,
                port: port_index[t][slot as usize] as usize,
            }
        };
        let mut links = Vec::with_capacity(sources.len());
        let mut witness = vec![Word64::new(0); composition.witness_len()];
        let mut public = vec![Word64::new(0); composition.public_len()];
        let place = |gadget: usize, index: ValueIndex| -> Result<usize, CompositionError> {
            let t = template_of[gadget] as usize;
            Ok(composition.resolve(call_of[t], instance_of[gadget] as usize, index)?.position() as usize)
        };
        for gadget in 0..gadgets {
            let t = template_of[gadget] as usize;
            if t == u32::MAX as usize {
                continue;
            }
            let own = &layout.words.1[layout.words.0[gadget] as usize..layout.words.0[gadget + 1] as usize];
            for (slot, &word) in own.iter().enumerate() {
                let at = place(gadget, ValueIndex::witness(slot).expect("a slot index"))?;
                witness[at] = Word64::new(self.witness[word as usize]);
            }
            for &(slot, word) in &sources[source_start[gadget] as usize..source_start[gadget + 1] as usize] {
                let at = place(gadget, ValueIndex::witness(slot as usize).expect("a slot index"))?;
                witness[at] = Word64::new(self.witness[word as usize]);
                let producer = owner[word as usize] as usize;
                links.push((port_ref(gadget, slot), port_ref(producer, layout.slot_of[word as usize])));
            }
            if templates[t].outputs {
                for index in 0..outputs {
                    let at = place(gadget, ValueIndex::public(index).expect("an output index"))?;
                    public[at] = Word64::new(self.public[index]);
                }
            }
            if templates[t].constant {
                self.canon(gadget, &layout, &pool, outputs, false, &mut canon);
                let constant = canon.constant.expect("a pool gadget reads its constant");
                let at = place(gadget, ValueIndex::public(0).expect("a public index"))?;
                public[at] = Word64::new(self.public[constant as usize]);
            }
        }
        let routing = PortRouting::new(&composition, &ports, &links)?;
        Ok(Composed { composition, routing, public, witness })
    }

    /// Makes `gadget` canonical into `canon`, with its relations over its slots when `body`.
    fn canon(
        &self,
        gadget: usize,
        layout: &Layout,
        pool: &HashMap<u32, u32>,
        outputs: usize,
        body: bool,
        canon: &mut Canon,
    ) {
        let owners = self.owners.as_ref().expect("the gadgets are tracked");
        canon.code.clear();
        canon.imports.clear();
        canon.links.clear();
        canon.constant = None;
        canon.outputs = false;
        let mut relations: [Vec<Vec<Vec<Term>>>; 3] = Default::default();
        let first = layout.words.0[gadget];
        let own = layout.words.0[gadget + 1] - first;
        let is_own = |word: u32| owners.words[word as usize] == gadget as u32;
        let mut imported: HashMap<u32, u32> = HashMap::new();
        canon.code.push(u64::from(own));
        let families = [&self.zero, &self.and, &self.mul];
        for (family, (start, order)) in layout.relations.iter().enumerate() {
            for &relation in &order[start[gadget] as usize..start[gadget + 1] as usize] {
                let operands: Vec<&[Term]> = (0..ARITY[family])
                    .map(|operand| {
                        let index = relation as usize * ARITY[family] + operand;
                        let from = index.checked_sub(1).map_or(0, |i| families[family].ends[i]);
                        &families[family].terms[from..families[family].ends[index]]
                    })
                    .collect();
                if family == 0 && layout.link[relation as usize] {
                    if let [source, copy] = operands[0] {
                        let (source, copy) = (source.index(), copy.index());
                        if source.segment() == Segment::Witness
                            && !is_own(source.position())
                            && copy.segment() == Segment::Witness
                            && is_own(copy.position())
                        {
                            let slot = layout.slot_of[copy.position() as usize];
                            canon.links.push((slot, source.position()));
                            canon.code.push(u64::MAX - u64::from(slot));
                            continue;
                        }
                    }
                }
                canon.code.push(family as u64 + 1);
                let mut remapped = Vec::new();
                for terms in operands {
                    canon.code.push(terms.len() as u64);
                    let mut operand = Vec::new();
                    for &term in terms {
                        let index = term.index();
                        let position = index.position();
                        let slot = match index.segment() {
                            Segment::Witness if is_own(position) => {
                                Slot::Own(layout.slot_of[position as usize])
                            }
                            Segment::Witness => {
                                let next = imported.len() as u32;
                                Slot::Import(*imported.entry(position).or_insert_with(|| {
                                    canon.imports.push(position);
                                    next
                                }))
                            }
                            Segment::Public if (position as usize) < outputs => {
                                canon.outputs = true;
                                Slot::Output(position)
                            }
                            Segment::Public => match pool.get(&position) {
                                Some(&word) if !is_own(word) => {
                                    let next = imported.len() as u32;
                                    Slot::Import(*imported.entry(word).or_insert_with(|| {
                                        canon.imports.push(word);
                                        next
                                    }))
                                }
                                _ => {
                                    canon.constant = Some(position);
                                    Slot::Constant
                                }
                            },
                        };
                        let (class, at) = match slot {
                            Slot::Own(s) => (0, s),
                            Slot::Import(k) => (1, k),
                            Slot::Output(p) => (2, p),
                            Slot::Constant => (3, 0),
                        };
                        canon.code.push(template_term(class, at, term));
                        if body {
                            let local = match slot {
                                Slot::Own(s) => ValueIndex::witness(s as usize),
                                Slot::Import(k) => ValueIndex::witness((own + k) as usize),
                                Slot::Output(p) => ValueIndex::public(p as usize),
                                Slot::Constant => ValueIndex::public(0),
                            }
                            .expect("a slot index");
                            operand.push(term.with_index(local));
                        }
                    }
                    if body {
                        remapped.push(operand);
                    }
                }
                if body {
                    relations[family].push(remapped);
                }
            }
        }
        canon.body = body.then_some(relations);
    }
}

#[cfg(test)]
mod tests {
    use p3_word_backend::{PackedWitness, WordProofKey};
    use zkm_binary_stark::{challenger, config::bit_commitment, F};

    use super::*;
    use crate::{builder::Val, kb::P, prove::schedule};

    /// Hinted elements, their running product, three compressions over them and constants,
    /// and two outputs.
    fn lowering() -> Builder {
        let mut builder = Builder::new(2);
        builder.track_gadgets();
        let mut values = Vec::new();
        for i in 0..12_u64 {
            builder.begin_gadget("Hint");
            values.push(builder.hint((i * 7919 + 3) % P));
            builder.end_gadget();
        }
        let mut product = values[0];
        for &value in &values[1..] {
            builder.begin_gadget("MulF");
            product = builder.mul(product, value);
            builder.end_gadget();
        }
        let mut digest = Vec::new();
        for round in 0..3_usize {
            builder.begin_gadget("Blake3");
            let mut cv = [Val::ZERO; 8];
            for (i, word) in cv.iter_mut().enumerate() {
                *word = if i < 5 { values[(i + round) % 12] } else { builder.constant(0x6A09_E667 + i as u64) };
            }
            let mut block = [Val::ZERO; 16];
            for (i, word) in block.iter_mut().enumerate().take(10) {
                *word = values[(3 * i + round) % 12];
            }
            digest = builder.blake3_compress(cv, block, round as u32, 40, 1).to_vec();
            builder.end_gadget();
        }
        builder.begin_gadget("Commit");
        for (index, value) in [product, digest[0]].into_iter().enumerate() {
            let output = builder.output(index, value.value);
            builder.assert_zero(value.terms().chain([output]));
        }
        builder.end_gadget();
        builder
    }

    #[test]
    fn a_composed_lowering_proves_under_its_routing() {
        let built = lowering().build().unwrap();
        built.system.verify(&built.public, &built.witness).unwrap();
        let composed = lowering().compose(2).unwrap();
        assert_eq!(composed.public[..2], built.public[..2]);
        let lowered = composed.composition.lower().unwrap();
        lowered.verify(&composed.public, &composed.witness).unwrap();
        assert!(
            composed.composition.calls().len() < 20,
            "{} calls",
            composed.composition.calls().len()
        );

        let key = WordProofKey::with_ports(composed.composition.clone(), composed.routing.clone())
            .unwrap();
        let pcs = bit_commitment(key.trace_variables(), &schedule()).unwrap();
        let values = PackedWitness::new(key.statement(), &composed.public, &composed.witness).unwrap();
        let (commitment, proof) = key.prove::<F, F, _, _>(&pcs, &values, &mut challenger()).unwrap();
        let routing = key.port_commitment::<F, _, _>(&pcs, &mut challenger()).unwrap().unwrap();
        key.verify_routed::<F, F, _, _>(
            &pcs,
            &commitment,
            &routing,
            &composed.public,
            &proof,
            &mut challenger(),
        )
        .unwrap();
        let mut wrong = composed.public.clone();
        wrong[0] = Word64::new(wrong[0].get() ^ 1);
        assert!(key
            .verify_routed::<F, F, _, _>(&pcs, &commitment, &routing, &wrong, &proof, &mut challenger())
            .is_err());
    }
}
