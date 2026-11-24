//! In-circuit helpers for the zerocheck's univariate skip.
//!
//! Mirrors [`zkm_pcs::shard_level::univariate_skip`]: the four low row bits
//! are one variable `Z` on the order-16 subgroup `D = ⟨ω⟩`, read through the
//! Lagrange basis `L_b(Z) = ω^b (Z^16 − 1) / (16 (Z − ω^b))`.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use zkm_pcs::shard_level::univariate_skip::{skip_domain, SKIP_BITS, SKIP_SIZE};
use zkm_recursion_compiler::ir::SymbolicExt;

use crate::zerocheck::{eq_eval, full_geq};
use crate::CircuitConfig;

/// `[L_0(z), …, L_15(z)]`.  `z` is a verifier challenge, so `z ∈ D` (a zero
/// denominator) has probability `16 / |EF|`.
pub fn lagrange_weights<C: CircuitConfig>(
    z: SymbolicExt<C::F, C::EF>,
) -> Vec<SymbolicExt<C::F, C::EF>>
where
    C::F: TwoAdicField,
{
    let dom = skip_domain::<C::F>();
    let mut zp = z;
    for _ in 0..SKIP_BITS {
        zp = zp * zp;
    }
    let vanish = zp - SymbolicExt::<C::F, C::EF>::ONE;
    let inv16 = C::F::from_usize(SKIP_SIZE).inverse();
    dom.iter()
        .map(|&w| {
            let c = SymbolicExt::<C::F, C::EF>::from(w * inv16);
            let d = z - SymbolicExt::<C::F, C::EF>::from(w);
            vanish * c / d
        })
        .collect()
}

/// `eq#(ζ_lo, z) = Σ_b eq(ζ_lo, b)·L_b(z)`, `zeta_lo` LSB-first.
pub fn eq_sharp<C: CircuitConfig>(
    zeta_lo: &[SymbolicExt<C::F, C::EF>],
    weights: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    assert_eq!(zeta_lo.len(), SKIP_BITS);
    let mut acc = SymbolicExt::<C::F, C::EF>::ZERO;
    for (b, &w) in weights.iter().enumerate() {
        let mut e = SymbolicExt::<C::F, C::EF>::ONE;
        for (i, &z) in zeta_lo.iter().enumerate() {
            e *= if (b >> i) & 1 == 1 { z } else { SymbolicExt::<C::F, C::EF>::ONE - z };
        }
        acc += e * w;
    }
    acc
}

/// The padded-row indicator `[row ≥ h]` at the skip point; host twin
/// `skip_geq_host`.  `degree` is the `N + 1` big-endian bits of `h`,
/// `z_extended = (0, z_hi)`.  With `ρ = Σ_{b ≥ h mod 16} L_b(r0)` it is
/// `geq_{h >> 4}(z_hi) − (1 − ρ)·eq(z_hi, h >> 4)`.
pub fn skip_geq<C: CircuitConfig>(
    degree: &[SymbolicExt<C::F, C::EF>],
    z_extended: &[SymbolicExt<C::F, C::EF>],
    weights: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    let split = degree.len() - SKIP_BITS;
    let (hi_bits, lo_bits) = degree.split_at(split);
    let mut lo_ext = Vec::with_capacity(SKIP_BITS + 1);
    lo_ext.push(SymbolicExt::ZERO);
    lo_ext.extend_from_slice(lo_bits);
    let mut rho = SymbolicExt::<C::F, C::EF>::ZERO;
    for (b, &w) in weights.iter().enumerate() {
        let b_bits: Vec<SymbolicExt<C::F, C::EF>> = (0..=SKIP_BITS)
            .rev()
            .map(|i| if (b >> i) & 1 == 1 { SymbolicExt::ONE } else { SymbolicExt::ZERO })
            .collect();
        rho += w * full_geq::<C>(&lo_ext, &b_bits);
    }
    full_geq::<C>(hi_bits, z_extended)
        - (SymbolicExt::<C::F, C::EF>::ONE - rho) * eq_eval::<C>(hi_bits, z_extended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkm_pcs::{InnerChallenge, InnerVal};
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;
    type EF = InnerChallenge;

    fn value(s: SymbolicExt<InnerVal, EF>) -> EF {
        match s {
            SymbolicExt::Const(v) => v,
            _ => panic!("constant inputs must fold to a constant"),
        }
    }

    fn bits(v: usize, n: usize) -> Vec<SymbolicExt<InnerVal, EF>> {
        (0..n).rev().map(|i| SymbolicExt::from(EF::from_bool((v >> i) & 1 == 1))).collect()
    }

    /// At an integer row (`z_hi` boolean, `r0 = ω^{row mod 16}`, where the
    /// weights are the host's point-on-`D` case) the skip padding indicator
    /// is exactly `[row ≥ h]`.
    #[test]
    fn skip_geq_is_the_row_indicator_at_integer_rows() {
        let n = 6;
        let w = EF::two_adic_generator(4);
        for h in [0usize, 1, 15, 16, 17, 31, 40, 63, 64] {
            let degree = bits(h, n + 1);
            for row in 0..(1usize << n) {
                let r0 = w.exp_u64((row & 15) as u64);
                let weights: Vec<SymbolicExt<InnerVal, EF>> =
                    zkm_pcs::shard_level::univariate_skip::lagrange_weights::<InnerVal, EF>(r0)
                        .iter()
                        .map(|&l| SymbolicExt::from(l))
                        .collect();
                let mut z_ext = vec![SymbolicExt::ZERO];
                z_ext.extend(bits(row >> 4, n - SKIP_BITS));
                let got = value(skip_geq::<C>(&degree, &z_ext, &weights));
                assert_eq!(got, EF::from_bool(row >= h), "h={h} row={row}");
            }
        }
    }

    /// The circuit `eq#` equals the host one.
    #[test]
    fn eq_sharp_matches_host() {
        let zeta: Vec<EF> = (0..4).map(|i| EF::from_u32(3 + 7 * i)).collect();
        let r0 = EF::from_u32(1234567);
        let host = zkm_pcs::shard_level::univariate_skip::eq_sharp::<InnerVal, EF>(&zeta, r0);
        let zs: Vec<_> = zeta.iter().map(|&z| SymbolicExt::from(z)).collect();
        let weights = lagrange_weights::<C>(SymbolicExt::from(r0));
        assert_eq!(value(eq_sharp::<C>(&zs, &weights)), host);
    }
}
