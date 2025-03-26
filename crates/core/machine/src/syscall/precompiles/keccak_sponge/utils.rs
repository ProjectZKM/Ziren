use tiny_keccak::keccakf;
use crate::syscall::precompiles::keccak_sponge::KECCAK_STATE_U32S;

/// Like tiny-keccak's `keccakf`, but deals with `u32` limbs instead of `u64` limbs.
pub(crate) fn keccakf_u32s(state_u32s: &mut [u32; KECCAK_STATE_U32S]) {
    let mut state_u64s: [u64; 25] = core::array::from_fn(|i| {
        let lo = state_u32s[i * 2] as u64;
        let hi = state_u32s[i * 2 + 1] as u64;
        lo | (hi << 32)
    });
    keccakf(&mut state_u64s);
    *state_u32s = core::array::from_fn(|i| {
        let u64_limb = state_u64s[i / 2];
        let is_hi = i % 2;
        (u64_limb >> (is_hi * 32)) as u32
    });
}