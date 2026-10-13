//! Versioned fingerprints of the unspecialised AIR and its extraction interface.
//! Hash expression DAGs structurally, never by addresses or HashMap iteration order.
use std::collections::{BTreeMap, HashMap};

use p3_air::{symbolic::SymbolicExpression, Air, BaseAir};
use sha2::{Digest, Sha256};
use zkm_pcs::{AirLookup, Chip, MachineAir};

use crate::{pcl::Felt, picus_builder::PicusBuilder};

type Expr = SymbolicExpression<Felt>;

fn part(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn expression(e: &Expr, memo: &mut HashMap<*const Expr, [u8; 32]>) -> [u8; 32] {
    let key = e as *const _;
    if let Some(h) = memo.get(&key) {
        return *h;
    }
    let mut hash = Sha256::new();
    match e {
        Expr::Leaf(leaf) => {
            part(&mut hash, b"leaf");
            part(&mut hash, format!("{leaf:?}").as_bytes());
        }
        Expr::Add { x, y, .. } | Expr::Sub { x, y, .. } | Expr::Mul { x, y, .. } => {
            let tag = match e {
                Expr::Add { .. } => "add",
                Expr::Sub { .. } => "sub",
                _ => "mul",
            };
            part(&mut hash, tag.as_bytes());
            part(&mut hash, &expression(x, memo));
            part(&mut hash, &expression(y, memo));
        }
        Expr::Neg { x, .. } => {
            part(&mut hash, b"neg");
            part(&mut hash, &expression(x, memo));
        }
    }
    let digest = hash.finalize().into();
    memo.insert(key, digest);
    digest
}

fn lookup(hash: &mut Sha256, l: &AirLookup<Expr>, memo: &mut HashMap<*const Expr, [u8; 32]>) {
    part(hash, format!("{:?}", l.kind).as_bytes());
    part(hash, &expression(&l.multiplicity, memo));
    part(hash, &(l.values.len() as u64).to_le_bytes());
    for e in &l.values {
        part(hash, &expression(e, memo));
    }
}

pub fn chip_fingerprint<A>(chip: &Chip<Felt, A>) -> String
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder>,
{
    let mut b = PicusBuilder::new(chip.air.width(), chip.preprocessed_width());
    chip.air.eval(&mut b);
    let mut hash = Sha256::new();
    part(&mut hash, b"ziren-air-fingerprint-v1:koalabear-2130706433");
    part(&mut hash, chip.name().as_bytes());
    part(&mut hash, format!("{:?}", b.layout).as_bytes());
    part(&mut hash, &(chip.preprocessed_width() as u64).to_le_bytes());
    let mut info = chip.picus_info();
    let names: BTreeMap<_, _> = info.col_to_name.drain().collect();
    let ranges: BTreeMap<_, _> = info.name_to_colrange.drain().collect();
    part(&mut hash, format!("{names:?}{ranges:?}{info:?}").as_bytes());
    part(&mut hash, &[u8::from(chip.selectors_partition_real_rows())]);
    for (_, name) in &info.selector_indices {
        part(&mut hash, &[u8::from(chip.picus_selector_specialization_allowed(name))]);
    }
    let mut memo = HashMap::new();
    part(&mut hash, &(b.constraints.len() as u64).to_le_bytes());
    for e in &b.constraints {
        part(&mut hash, &expression(e, &mut memo));
    }
    for (tag, lookups, scopes) in
        [("send", &b.sends, &b.send_scopes), ("receive", &b.receives, &b.receive_scopes)]
    {
        part(&mut hash, tag.as_bytes());
        part(&mut hash, &(lookups.len() as u64).to_le_bytes());
        for (l, scope) in lookups.iter().zip(scopes) {
            part(&mut hash, format!("{scope:?}").as_bytes());
            lookup(&mut hash, l, &mut memo);
        }
    }
    part(&mut hash, &(b.gadgets.len() as u64).to_le_bytes());
    for (name, operands) in &b.gadgets {
        part(&mut hash, name.as_bytes());
        part(&mut hash, &(operands.len() as u64).to_le_bytes());
        for l in operands {
            lookup(&mut hash, l, &mut memo);
        }
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_core_machine::MipsAir;

    #[test]
    fn fingerprints_ignore_allocation_and_detect_expression_changes() {
        let a = Expr::Leaf(p3_air::symbolic::BaseLeaf::Constant(Felt::ONE));
        let b = Expr::Leaf(p3_air::symbolic::BaseLeaf::Constant(Felt::TWO));
        let digest = |e: &Expr| expression(e, &mut HashMap::new());
        assert_eq!(digest(&(a.clone() + b.clone())), digest(&(a.clone() + b.clone())));
        assert_ne!(digest(&(a.clone() + b.clone())), digest(&(a.clone() * b.clone())));
        assert_ne!(digest(&a), digest(&b));
    }

    #[test]
    fn chip_fingerprint_is_repeatable_with_randomized_annotation_maps() {
        let chips = MipsAir::<Felt>::chips();
        let chip = chips.iter().find(|c| c.name() == "AddSub").unwrap();
        assert_eq!(chip_fingerprint(chip), chip_fingerprint(chip));
    }
}
