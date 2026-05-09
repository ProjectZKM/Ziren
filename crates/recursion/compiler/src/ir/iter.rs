//! Iterator extension for emitting parallel DSL IR blocks.
//!
//! Ported from SP1 (`/tmp/sp1/crates/recursion/compiler/src/ir/iter.rs`).
//!
//! Phase C of #259. The trait collects an iterator into N sub-blocks,
//! each containing the DSL IR ops emitted by a single invocation of the
//! map closure. The resulting blocks are wrapped in a `DslIr::Parallel`
//! op pushed to the parent builder. Today the runtime collapses
//! `Parallel` to sequential via Phase A4's `iter_instructions`; Phase D
//! will dispatch via `par_iter` once the memory layer is thread-safe.
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
        // Save the parent's op buffer, install an empty one so the
        // closure's emissions accumulate in isolation per iteration.
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
        // Restore the parent's op buffer and push the Parallel op
        // containing the per-iteration sub-blocks.
        *builder.get_mut_operations() = prev_ops;
        // #259 unlock-chain diagnostic: ZIREN_DEBUG_PARALLEL_EMIT=1
        // counts each ir_par_map_collect emission so we can correlate
        // with the runtime-side parallelism_summary readback.
        if std::env::var("ZIREN_DEBUG_PARALLEL_EMIT").is_ok() {
            let total_ops: usize = blocks.iter().map(|b| b.ops.vec.len()).sum();
            eprintln!(
                "[ir_par_emit] blocks={} total_ops={}",
                blocks.len(),
                total_ops
            );
        }
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
        // Build a tiny program: outer scope emits ImmF, then
        // ir_par_map_collect over 3 items each emitting an ImmF.
        // Verify that the parent's operations end with a single
        // DslIr::Parallel(3 blocks).
        let mut builder: Builder<AsmConfig<F, EF>> = Builder::default();
        // Pre-Parallel op: one ImmF in the parent.
        let _outer: crate::ir::Felt<F> = builder.eval(F::from_u32(1));
        let parent_ops_before = builder.get_mut_operations().vec.len();

        // Map 3 items, each emits 1 ImmF.
        let _vals: Vec<crate::ir::Felt<F>> = (0..3u32).ir_par_map_collect(
            &mut builder,
            |b, i| -> crate::ir::Felt<F> { b.eval(F::from_u32(100 + i)) },
        );

        let parent_ops_after = builder.get_mut_operations().vec.len();
        // Exactly one new op (the Parallel) was pushed to the parent.
        assert_eq!(parent_ops_after, parent_ops_before + 1);

        // Inspect the last op — must be Parallel with 3 sub-blocks.
        let last_op = builder.get_mut_operations().vec.last().unwrap();
        match last_op {
            DslIr::Parallel(blocks) => {
                assert_eq!(blocks.len(), 3, "expected 3 sub-blocks");
                for (i, b) in blocks.iter().enumerate() {
                    assert!(
                        !b.ops.is_empty(),
                        "sub-block {i} should hold at least the eval op"
                    );
                }
            }
            other => panic!("expected DslIr::Parallel, got {other:?}"),
        }
    }
}
