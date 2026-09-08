//! x86-64 emitters for KoalaBear arithmetic.
//!
//! These are the fragments every JIT'd instruction is built from, so they
//! are written and tested on their own before any program-level codegen
//! exists.  A wrong field op here would not crash — it would produce a
//! valid-looking proof of the wrong statement — so each fragment is
//! property-tested against `p3_field`'s own implementation over random
//! inputs and every edge case, and the constants are taken from the
//! `p3-koala-bear` source rather than restated from memory:
//!
//! ```text
//! PRIME      = 0x7f000001
//! MONTY_MU   = 0x81000001
//! MONTY_BITS = 32          (so the Montgomery mask is the low 32 bits)
//! W          = 3           (the quartic extension is X^4 - 3)
//! ```

use dynasmrt::{dynasm, DynasmApi};

/// KoalaBear's prime.
pub const PRIME: u32 = 0x7f00_0001;
/// `-P^{-1} mod 2^32`.
pub const MONTY_MU: u32 = 0x8100_0001;
/// The quartic extension is `X^4 - W`.
pub const W: u32 = 3;

/// `eax = eax + ecx (mod P)`, both inputs already reduced.
///
/// Branch-free: add, speculatively subtract P, and take whichever did not
/// underflow.  `cmovb` rather than a jump because the two cases are
/// data-dependent and unpredictable.
pub fn emit_add(ops: &mut dynasmrt::x64::Assembler) {
    dynasm!(ops
        ; .arch x64
        ; add eax, ecx
        ; mov ecx, eax
        ; sub ecx, DWORD PRIME as i32
        ; cmovnb eax, ecx
    );
}

/// `eax = eax - ecx (mod P)`, both inputs already reduced.
pub fn emit_sub(ops: &mut dynasmrt::x64::Assembler) {
    dynasm!(ops
        ; .arch x64
        ; sub eax, ecx
        ; mov ecx, eax
        ; add ecx, DWORD PRIME as i32
        ; cmovb eax, ecx
    );
}

/// `eax = montgomery_mul(eax, ecx)`.
///
/// Mirrors `monty_reduce(a as u64 * b as u64)` statement for statement:
/// `t = (x * MU) mod 2^32`, `u = t * P`, then the high word of `x - u`
/// with a `+P` correction when that subtraction borrowed.  Clobbers rdx.
pub fn emit_mul(ops: &mut dynasmrt::x64::Assembler) {
    dynasm!(ops
        ; .arch x64
        // rax = x = a * b  (32x32 -> 64, zero-extended operands)
        ; mov eax, eax
        ; mov ecx, ecx
        ; imul rax, rcx
        // ecx = t = low32(x) * MU   (the mask is implicit in the 32-bit op)
        ; mov ecx, eax
        ; imul ecx, ecx, DWORD MONTY_MU as i32
        // rcx = u = t * P
        ; mov ecx, ecx
        ; mov edx, DWORD PRIME as i32
        ; imul rcx, rdx
        // rax = x - u, CF set on borrow
        ; sub rax, rcx
        ; sbb edx, edx            // edx = 0xffffffff on borrow, else 0
        ; shr rax, 32             // high word
        ; and edx, DWORD PRIME as i32  // corr = borrow ? P : 0
        ; add eax, edx
    );
}

/// Which fragment to emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    /// Modular addition.
    Add,
    /// Modular subtraction.
    Sub,
    /// Montgomery multiplication.
    Mul,
}

/// Assemble a standalone `extern "C" fn(u32, u32) -> u32` for one fragment.
///
/// Used by the tests to check a fragment in isolation; the program emitter
/// inlines the same fragments instead of calling them.
///
/// # Panics
/// Panics if the assembler cannot finalize (out of memory for the buffer).
#[must_use]
pub fn assemble_binop(op: BinOp) -> BinOpFn {
    let mut ops = dynasmrt::x64::Assembler::new().expect("dynasm assembler");
    let start = ops.offset();
    // SysV: first arg in edi, second in esi.
    dynasm!(ops
        ; .arch x64
        ; mov eax, edi
        ; mov ecx, esi
    );
    match op {
        BinOp::Add => emit_add(&mut ops),
        BinOp::Sub => emit_sub(&mut ops),
        BinOp::Mul => emit_mul(&mut ops),
    }
    dynasm!(ops ; .arch x64 ; ret);
    let buf = ops.finalize().expect("finalize");
    let ptr = buf.ptr(start);
    BinOpFn { _buf: buf, f: unsafe { std::mem::transmute::<*const u8, RawBinOp>(ptr) } }
}

type RawBinOp = extern "C" fn(u32, u32) -> u32;

/// An assembled fragment, kept alive with its executable buffer.
pub struct BinOpFn {
    _buf: dynasmrt::ExecutableBuffer,
    f: RawBinOp,
}

impl BinOpFn {
    /// Invoke the assembled fragment.
    #[must_use]
    pub fn call(&self, a: u32, b: u32) -> u32 {
        (self.f)(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    /// Montgomery-form words, i.e. what the runtime actually stores.
    fn raw(x: KoalaBear) -> u32 {
        // SAFETY: `MontyField31` is `#[repr(transparent)]` over `u32`; the
        // layout contract in `lib.rs` asserts the size.
        unsafe { std::mem::transmute::<KoalaBear, u32>(x) }
    }
    fn unraw(x: u32) -> KoalaBear {
        unsafe { std::mem::transmute::<u32, KoalaBear>(x) }
    }

    /// A spread of inputs that includes the values where a modular
    /// implementation goes wrong: zero, one, P-1, and the halves either
    /// side of the wrap.
    fn corpus() -> Vec<KoalaBear> {
        let mut v: Vec<KoalaBear> = vec![
            KoalaBear::ZERO,
            KoalaBear::ONE,
            KoalaBear::TWO,
            unraw(PRIME - 1),
            unraw(PRIME - 2),
            unraw(PRIME / 2),
            unraw(PRIME / 2 + 1),
        ];
        // Deterministic pseudo-random spread — no rand dependency needed and
        // a failure is reproducible from the seed alone.
        let mut s: u64 = 0x243f_6a88_85a3_08d3;
        for _ in 0..2000 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push(unraw(((s >> 33) as u32) % PRIME));
        }
        v
    }

    #[test]
    fn add_matches_the_field() {
        let f = assemble_binop(BinOp::Add);
        let c = corpus();
        for (i, &a) in c.iter().enumerate() {
            let b = c[(i * 7 + 3) % c.len()];
            assert_eq!(f.call(raw(a), raw(b)), raw(a + b), "add {a:?} + {b:?}");
        }
    }

    #[test]
    fn sub_matches_the_field() {
        let f = assemble_binop(BinOp::Sub);
        let c = corpus();
        for (i, &a) in c.iter().enumerate() {
            let b = c[(i * 11 + 5) % c.len()];
            assert_eq!(f.call(raw(a), raw(b)), raw(a - b), "sub {a:?} - {b:?}");
        }
    }

    #[test]
    fn mul_matches_the_field() {
        let f = assemble_binop(BinOp::Mul);
        let c = corpus();
        for (i, &a) in c.iter().enumerate() {
            let b = c[(i * 13 + 7) % c.len()];
            assert_eq!(f.call(raw(a), raw(b)), raw(a * b), "mul {a:?} * {b:?}");
        }
    }

    /// Every pair drawn from the edge cases, not just the paired sweep.
    #[test]
    fn the_edges_multiply_correctly() {
        let f = assemble_binop(BinOp::Mul);
        let edges: Vec<u32> = vec![0, 1, 2, PRIME - 1, PRIME - 2, PRIME / 2, PRIME / 2 + 1];
        for &a in &edges {
            for &b in &edges {
                assert_eq!(f.call(a, b), raw(unraw(a) * unraw(b)), "mul {a} * {b}");
            }
        }
    }

    #[test]
    fn the_extension_constant_is_the_one_the_field_uses() {
        // X^4 - 3: guard against the emitter and the field drifting apart.
        assert_eq!(W, 3);
    }
}
