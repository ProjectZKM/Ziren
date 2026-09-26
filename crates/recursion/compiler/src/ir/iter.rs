//! Iterator extension for emitting parallel DSL IR blocks.
//!
//! The trait collects an iterator into N sub-blocks,
//! each containing the DSL IR ops emitted by a single invocation of the
//! map closure. The resulting blocks are wrapped in a `DslIr::Parallel`
//! op pushed to the parent builder. The runtime dispatches sub-blocks
//! via rayon `par_iter` (`runtime/mod.rs::execute_blocks`, commit
//! f1f4fee4); the memory layer is thread-safe through `ParMemVec` +
//! the IR-level disjoint-`addrs_written` invariant.
//!
//! The IR-level discipline that makes parallel sound: each sub-block's
//! `addrs_written` range is disjoint from the others' (variable_count
//! is monotonically increasing across the iter — never rewinds). The
//! runtime relies on this invariant; the trait enforces it by
//! construction.

use std::mem;

use super::{Builder, Config, DslIr, DslIrBlock};

/// Extension trait that emits a `DslIr::Parallel` block by collecting
/// an iterator into per-element sub-programs.
pub trait IrIter<C: Config, Item>: Sized {
    /// Map each item through `map_op` while capturing the IR ops
    /// emitted by the closure into a separate sub-block. Push a
    /// single `DslIr::Parallel` op containing all sub-blocks to the
    /// parent builder. Return the collected per-item return values
    /// in the requested container type.
    fn ir_par_map_collect<B, F, S>(self, builder: &mut Builder<C>, map_op: F) -> B
    where
        F: FnMut(&mut Builder<C>, Item) -> S,
        B: Default + Extend<S>;
}

impl<C, I, Item> IrIter<C, Item> for I
where
    C: Config,
    I: Iterator<Item = Item>,
{
    fn ir_par_map_collect<B, F, S>(self, builder: &mut Builder<C>, mut map_op: F) -> B
    where
        F: FnMut(&mut Builder<C>, I::Item) -> S,
        B: Default + Extend<S>,
    {
        let prev_ops = mem::take(builder.get_mut_operations());
        let (blocks, coll): (Vec<_>, B) = self
            .map(|r| {
                let next_addr = builder.variable_count();
                let s = map_op(builder, r);
                let block = DslIrBlock {
                    ops: mem::take(builder.get_mut_operations()),
                    addrs_written: next_addr..builder.variable_count(),
                };
                (block, s)
            })
            .unzip();
        *builder.get_mut_operations() = prev_ops;
        builder.push_op(DslIr::Parallel(blocks));
        coll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::AsmConfig;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn ir_par_map_collect_emits_parallel_block() {
        let mut builder: Builder<AsmConfig<F, EF>> = Builder::default();
        let _outer: crate::ir::Felt<F> = builder.eval(F::from_u32(1));
        let parent_ops_before = builder.get_mut_operations().vec.len();

        let _vals: Vec<crate::ir::Felt<F>> = (0..3u32)
            .ir_par_map_collect(&mut builder, |b, i| -> crate::ir::Felt<F> {
                b.eval(F::from_u32(100 + i))
            });

        let parent_ops_after = builder.get_mut_operations().vec.len();
        assert_eq!(parent_ops_after, parent_ops_before + 1);

        let last_op = builder.get_mut_operations().vec.last().unwrap();
        match last_op {
            DslIr::Parallel(blocks) => {
                assert_eq!(blocks.len(), 3, "expected 3 sub-blocks");
                for (i, b) in blocks.iter().enumerate() {
                    assert!(!b.ops.is_empty(), "sub-block {i} should hold at least the eval op");
                }
            }
            other => panic!("expected DslIr::Parallel, got {other:?}"),
        }
    }
}
