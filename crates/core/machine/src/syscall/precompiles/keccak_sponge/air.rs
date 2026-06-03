//! Keccak-sponge **worker** AIR — one keccak-f round per row.
//!
//! This is a direct port of SP1's single-row `keccak256` round AIR: all of the
//! keccak-f permutation constraints (θ/ρ/π via `c`/`c'`/`a'`, χ via `a''`, ι via
//! `a'''[0][0]`) are evaluated **within one row** over the `p3_keccak`
//! `KeccakCols`, and the round-to-round state hand-off — which `p3_keccak`'s
//! multi-row SubAir does with a `when_transition` window the single-row BaseFold
//! folder cannot evaluate — is carried on the `PrecompileChain` bus instead:
//! each row RECEIVEs the round input `a` and SENDs the round output `a'''`.  The
//! [`super::control`] chip seeds round 0 (the absorbed block state) and drains
//! round 24 (the permuted state).

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{NUM_ROUNDS, U64_LIMBS};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{air::AirLookup, LookupKind, LookupScope, ZKMAirBuilder};

use super::{
    columns::{KeccakSpongeCols, NUM_KECCAK_SPONGE_COLS},
    constants::rc_value_bit,
    KeccakSpongeChip, BITS_PER_LIMB,
};

/// Bus tag for the keccak round-chain bus (distinguishes it from the block-chain
/// bus, which shares `LookupKind::PrecompileChain`).
pub(crate) const KECCAK_BUS_ROUND: u32 = 0;
/// Bus tag for the keccak block-chain (sponge) bus.
pub(crate) const KECCAK_BUS_BLOCK: u32 = 1;

impl<F> BaseAir<F> for KeccakSpongeChip {
    fn width(&self) -> usize {
        NUM_KECCAK_SPONGE_COLS
    }
}

impl<AB> Air<AB> for KeccakSpongeChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &KeccakSpongeCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let andn = |a: AB::Expr, b: AB::Expr| b.clone() - a * b;
        let xor = |a: AB::Expr, b: AB::Expr| a.clone() + b.clone() - a * b.double();
        let xor3 = |a: AB::Expr, b: AB::Expr, c: AB::Expr| xor(a, xor(b, c));

        // Flag constraints: each `step_flags` bit is boolean, exactly one is set,
        // and `index = Σ i·step_flags[i]` is the round number.
        let mut sum_flags = AB::Expr::ZERO;
        let mut computed_index = AB::Expr::ZERO;
        for i in 0..NUM_ROUNDS {
            builder.assert_bool(local.keccak.step_flags[i]);
            sum_flags = sum_flags.clone() + local.keccak.step_flags[i].into();
            computed_index = computed_index.clone()
                + AB::Expr::from_u32(i as u32) * local.keccak.step_flags[i].into();
        }
        builder.assert_one(sum_flags);
        builder.when(local.is_real).assert_eq(computed_index, local.index);

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            for z in 0..64 {
                builder.assert_bool(local.keccak.c[x][z]);
                let xor_val = xor3(
                    local.keccak.c[x][z].into(),
                    local.keccak.c[(x + 4) % 5][z].into(),
                    local.keccak.c[(x + 1) % 5][(z + 63) % 64].into(),
                );
                let c_prime = local.keccak.c_prime[x][z];
                builder.assert_eq(c_prime, xor_val);
            }
        }

        // A[x, y, z] = xor(A'[x, y, z], C[x, z], C'[x, z]).
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z: usize| {
                    let a_prime: AB::Var = local.keccak.a_prime[y][x][z];
                    let c: AB::Var = local.keccak.c[x][z];
                    let c_prime: AB::Var = local.keccak.c_prime[x][z];
                    xor3(a_prime.into(), c.into(), c_prime.into())
                };

                for limb in 0..U64_LIMBS {
                    let a_limb = local.keccak.a[y][x][limb];
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| {
                            builder.assert_bool(local.keccak.a_prime[y][x][z]);
                            acc.double() + get_bit(z)
                        });
                    builder.assert_eq(computed_limb, a_limb);
                }
            }
        }

        // sum_{i=0}^4 A'[x, i, z] = C'[x, z], so diff*(diff-2)*(diff-4) = 0.
        for x in 0..5 {
            for z in 0..64 {
                let sum: AB::Expr = (0..5).map(|y| local.keccak.a_prime[y][x][z].into()).sum();
                let diff = sum - local.keccak.c_prime[x][z];
                let four = AB::Expr::from_u32(4);
                builder.assert_zero(
                    diff.clone() * (diff.clone() - AB::Expr::from_u32(2)) * (diff - four),
                );
            }
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for y in 0..5 {
            for x in 0..5 {
                let get_bit = |z: usize| {
                    let andn_val = andn(
                        local.keccak.b((x + 1) % 5, y, z).into(),
                        local.keccak.b((x + 2) % 5, y, z).into(),
                    );
                    xor(local.keccak.b(x, y, z).into(), andn_val)
                };

                for limb in 0..U64_LIMBS {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                    builder.assert_eq(computed_limb, local.keccak.a_prime_prime[y][x][limb]);
                }
            }
        }

        // A'''[0, 0] = A''[0, 0] XOR RC.
        for limb in 0..U64_LIMBS {
            let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| {
                    builder.assert_bool(local.keccak.a_prime_prime_0_0_bits[z]);
                    acc.double() + local.keccak.a_prime_prime_0_0_bits[z].into()
                });
            let a_prime_prime_0_0_limb = local.keccak.a_prime_prime[0][0][limb];
            builder.assert_eq(computed_a_prime_prime_0_0_limb, a_prime_prime_0_0_limb);
        }

        let get_xored_bit = |i: usize| {
            let mut rc_bit_i = AB::Expr::ZERO;
            for r in 0..NUM_ROUNDS {
                let this_round = local.keccak.step_flags[r];
                let this_round_constant = AB::Expr::from_u8(rc_value_bit(r, i));
                rc_bit_i = rc_bit_i.clone() + this_round.into() * this_round_constant;
            }

            xor(local.keccak.a_prime_prime_0_0_bits[i].into(), rc_bit_i)
        };

        for limb in 0..U64_LIMBS {
            let a_prime_prime_prime_0_0_limb = local.keccak.a_prime_prime_prime_0_0_limbs[limb];
            let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
            builder.assert_eq(
                computed_a_prime_prime_prime_0_0_limb,
                a_prime_prime_prime_0_0_limb,
            );
        }

        // Round-chain bus: receive `a` @ (block, index), send `a'''` @ (block, index+1).
        self.eval_state_bus(builder, local);
    }
}

impl KeccakSpongeChip {
    fn eval_state_bus<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &KeccakSpongeCols<AB::Var>,
    ) {
        let pid = AB::Expr::from_u32(SyscallCode::KECCAK_SPONGE.syscall_id());
        let header = |index: AB::Expr| -> Vec<AB::Expr> {
            vec![
                pid.clone(),
                AB::Expr::from_u32(KECCAK_BUS_ROUND),
                local.clk.into(),
                local.block.into(),
                index,
            ]
        };

        // Receive the round input `a` @ index (state in (y, x, limb) order).
        let mut recv = header(local.index.into());
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..U64_LIMBS {
                    recv.push(local.keccak.a[y][x][limb].into());
                }
            }
        }
        builder.receive(
            AirLookup::new(recv, local.is_real.into(), LookupKind::PrecompileChain),
            LookupScope::Local,
        );

        // Send the round output `a'''` @ index + 1.
        let mut send = header(local.index.into() + AB::Expr::ONE);
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..U64_LIMBS {
                    send.push(local.keccak.a_prime_prime_prime(y, x, limb).into());
                }
            }
        }
        builder.send(
            AirLookup::new(send, local.is_real.into(), LookupKind::PrecompileChain),
            LookupScope::Local,
        );
    }
}
