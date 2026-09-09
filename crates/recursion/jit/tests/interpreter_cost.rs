//! Where the interpreter's ~33 ns per instruction goes, by construction.
//!
//! `perf` is unavailable on both the dev host and the box
//! (`perf_event_paranoid=4` disallows even user-space profiling), so instead
//! of sampling, this times programs made of ONE opcode at a time.  That
//! attributes cost per opcode directly, and combined with the measured mix
//! from `jit_coverage` it says which arm the walk actually spends its time
//! in — which is what decides whether removing dispatch is worth anything,
//! or whether the cost is in the memory traffic no dispatch change touches.
//!
//! Run with: `cargo test --release -p zkm-recursion-jit --test interpreter_cost -- --ignored --nocapture`

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
use zkm_pcs::{koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig};
use zkm_recursion_core::runtime::{instruction as instr, Instruction, RecursionProgram, Runtime};
use zkm_recursion_core::{
    Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, ExtAluInstr, ExtAluIo, ExtAluOpcode,
    MemAccessKind,
};

type SC = KoalaBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;

fn addr(a: u32) -> Address<F> {
    Address(F::from_u32(a))
}

const SEEDS: [u32; 8] = [1, 2, 3, 5, 7, 11, 13, 17];

/// `n` instructions of one kind, over addresses that are always already
/// written — the same shape a real program has, since a recursion program
/// writes every address exactly once and reads only what precedes it.
fn homogeneous(n: usize, kind: &str) -> RecursionProgram<F> {
    let mut instrs: Vec<Instruction<F>> = SEEDS
        .iter()
        .enumerate()
        .map(|(i, s)| instr::mem(MemAccessKind::Write, 1, i as u32, *s))
        .collect();

    let mut next = SEEDS.len() as u32;
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..n {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = ((s >> 33) as u32) % next;
        // Never divide by a live cell: a zero divisor makes the interpreter
        // error out, and this measures cost, not semantics.
        let b = ((s >> 45) as u32) % SEEDS.len() as u32;
        let one = |op| {
            Instruction::BaseAlu(BaseAluInstr {
                opcode: op,
                mult: F::ONE,
                addrs: BaseAluIo { out: addr(next), in1: addr(a), in2: addr(b) },
            })
        };
        let ext = |op| {
            Instruction::ExtAlu(ExtAluInstr {
                opcode: op,
                mult: F::ONE,
                addrs: ExtAluIo { out: addr(next), in1: addr(a), in2: addr(b) },
            })
        };
        instrs.push(match kind {
            "BaseAlu/Add" => one(BaseAluOpcode::AddF),
            "BaseAlu/Sub" => one(BaseAluOpcode::SubF),
            "BaseAlu/Mul" => one(BaseAluOpcode::MulF),
            "BaseAlu/Div" => one(BaseAluOpcode::DivF),
            "ExtAlu/Add" => ext(ExtAluOpcode::AddE),
            "ExtAlu/Mul" => ext(ExtAluOpcode::MulE),
            "ExtAlu/Div" => ext(ExtAluOpcode::DivE),
            other => panic!("unknown kind {other}"),
        });
        next += 1;
    }

    let raw = zkm_recursion_core::runtime::RawProgram {
        seq_blocks: vec![zkm_recursion_core::runtime::SeqBlock::Basic(
            zkm_recursion_core::runtime::BasicBlock { instrs },
        )],
    };
    let mut program = RecursionProgram::<F>::new(raw, 0, Vec::new(), None);
    program.total_memory = program.computed_total_memory();
    program
}

#[test]
#[ignore = "a measurement, not a gate"]
fn per_opcode_interpreter_cost() {
    const N: usize = 400_000;
    let perm = SC::new().perm;

    // One discarded pass before the table: the first kind measured otherwise
    // absorbs allocator warm-up and first-touch of the record, which showed up
    // as BaseAlu/Add costing 72 ns against Sub's 48 for identical work.
    {
        let p = Arc::new(homogeneous(N, "BaseAlu/Add"));
        let mut r = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(p, perm.clone());
        r.run().expect("warm-up");
    }

    println!("\n  opcode          ns/instr   (interpreter walk, N={N})");
    for kind in [
        "BaseAlu/Add",
        "BaseAlu/Sub",
        "BaseAlu/Mul",
        "BaseAlu/Div",
        "ExtAlu/Add",
        "ExtAlu/Mul",
        "ExtAlu/Div",
    ] {
        let program = Arc::new(homogeneous(N, kind));
        // Best of three: the walk allocates its record up front, so a single
        // run mixes allocation and first-touch into the number.
        let mut best = f64::MAX;
        for _ in 0..3 {
            let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
                program.clone(),
                perm.clone(),
            );
            let t = std::time::Instant::now();
            runtime.run().expect("interpreter");
            best = best.min(t.elapsed().as_secs_f64());
        }
        println!("  {kind:<14}  {:>8.1}", best * 1e9 / N as f64);
    }
}

/// Is `Div`'s cost the field inverse, or the branchy out-of-domain handling
/// around it?  The answer decides whether the lever is a faster inverse or a
/// restructured arm, and the two are entirely different work.
#[test]
#[ignore = "a measurement, not a gate"]
fn where_the_division_cost_is() {
    use p3_field::Field;

    const N: usize = 2_000_000;
    let mut xs: Vec<F> = Vec::with_capacity(N);
    let mut s: u64 = 0x243f_6a88_85a3_08d3;
    for _ in 0..N {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        xs.push(F::from_u32(((s >> 33) as u32) % 0x7f00_0001));
    }

    // Multiplication, as the baseline the inverse is measured against.
    let t = std::time::Instant::now();
    let mut acc = F::ONE;
    for x in &xs {
        acc *= *x;
    }
    let mul_ns = t.elapsed().as_secs_f64() * 1e9 / N as f64;

    let t = std::time::Instant::now();
    let mut sink = F::ZERO;
    for x in &xs {
        if let Some(i) = x.try_inverse() {
            sink += i;
        }
    }
    let inv_ns = t.elapsed().as_secs_f64() * 1e9 / N as f64;

    println!(
        "\n  mul {mul_ns:.2} ns, try_inverse {inv_ns:.2} ns ({:.0}x) \
         [acc={acc:?} sink={sink:?}]",
        inv_ns / mul_ns.max(1e-9)
    );
}

/// The quartic multiply, generic against specialized.
///
/// `BinomialExtensionField::mul` has hand-written arms for `D == 2` and
/// `D == 3` (`cubic_mul`) and falls through to a generic double loop for
/// everything else — including `D == 4`, which is the extension this whole
/// prover runs on.  That arm multiplies by `W` as a full field multiply, so
/// the six wrapping terms cost two Montgomery multiplies each: 22 rather
/// than 16, with `W = 3` done the expensive way and the results accumulated
/// through an array instead of registers.
#[test]
#[ignore = "a measurement, not a gate"]
fn a_specialized_quartic_multiply_against_the_generic_one() {
    use p3_field::extension::BinomialExtensionField;
    use p3_field::BasedVectorSpace;

    type E = BinomialExtensionField<F, 4>;
    const W: u32 = 3;
    const N: usize = 1_000_000;

    // x * 3, as an add chain rather than a Montgomery multiply.
    #[inline(always)]
    fn w3(x: F) -> F {
        x + x + x
    }

    /// Schoolbook mod `X^4 - 3`, accumulators in registers, W folded in.
    #[inline(always)]
    fn quartic(a: [F; 4], b: [F; 4]) -> [F; 4] {
        let c0 = a[0] * b[0] + w3(a[1] * b[3] + a[2] * b[2] + a[3] * b[1]);
        let c1 = a[0] * b[1] + a[1] * b[0] + w3(a[2] * b[3] + a[3] * b[2]);
        let c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w3(a[3] * b[3]);
        let c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0];
        [c0, c1, c2, c3]
    }

    let mut s: u64 = 0x243f_6a88_85a3_08d3;
    let mut rnd = || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        F::from_u32(((s >> 33) as u32) % 0x7f00_0001)
    };
    let xs: Vec<[F; 4]> = (0..N).map(|_| [rnd(), rnd(), rnd(), rnd()]).collect();

    // Equal on every input, first — a faster wrong multiply is worthless.
    for w in xs.windows(2).take(10_000) {
        let (a, b) = (w[0], w[1]);
        let want = E::from_basis_coefficients_slice(&a).unwrap()
            * E::from_basis_coefficients_slice(&b).unwrap();
        let got = quartic(a, b);
        let want: Vec<F> = want.as_basis_coefficients_slice().to_vec();
        assert_eq!(&got[..], &want[..], "specialized quartic disagrees with p3");
    }

    let ext: Vec<E> = xs.iter().map(|a| E::from_basis_coefficients_slice(a).unwrap()).collect();
    let t = std::time::Instant::now();
    let mut acc = E::ONE;
    for e in &ext {
        acc *= *e;
    }
    let generic_ns = t.elapsed().as_secs_f64() * 1e9 / N as f64;

    let t = std::time::Instant::now();
    let mut acc2 = [F::ONE, F::ZERO, F::ZERO, F::ZERO];
    for a in &xs {
        acc2 = quartic(acc2, *a);
    }
    let special_ns = t.elapsed().as_secs_f64() * 1e9 / N as f64;

    println!(
        "\n  quartic mul: p3 generic {generic_ns:.1} ns, specialized {special_ns:.1} ns \
         ({:.2}x)  [W={W}, acc={acc:?} acc2={acc2:?}]",
        generic_ns / special_ns.max(1e-9)
    );
}
