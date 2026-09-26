use alloc::vec::Vec;

use crate::{
    converter::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point,
    },
    cursor::Cursor,
    groth16::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey},
};

use super::error::Groth16Error;

/// Load the Groth16 proof from the given byte slice.
///
/// The byte slice is represented as 2 uncompressed g1 points, and one uncompressed g2 point,
/// as outputted from Gnark.
pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {
    let at = |r: core::ops::Range<usize>| {
        buffer.get(r).ok_or(Groth16Error::GeneralError(crate::error::Error::InvalidData))
    };
    let ar = uncompressed_bytes_to_g1_point(at(0..64)?)?;
    let bs = uncompressed_bytes_to_g2_point(at(64..192)?)?;
    let krs = uncompressed_bytes_to_g1_point(at(192..256)?)?;

    Ok(Groth16Proof { ar, bs, krs })
}

/// Load the Groth16 verification key from the given byte slice.
///
/// The gnark verification key includes a lot of extraneous information. We only extract the necessary
/// elements to verify a proof.
pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {
    let mut c = Cursor::new(buffer);
    let g1c = |c: &mut Cursor<'_>| -> Result<_, Groth16Error> {
        Ok(unchecked_compressed_x_to_g1_point(c.take(32)?)?)
    };
    let g2c = |c: &mut Cursor<'_>| -> Result<_, Groth16Error> {
        Ok(unchecked_compressed_x_to_g2_point(c.take(64)?)?)
    };

    let g1_alpha = g1c(&mut c)?;
    c.skip(32)?;
    let g2_beta = g2c(&mut c)?;
    let g2_gamma = g2c(&mut c)?;
    c.skip(32)?;
    let g2_delta = g2c(&mut c)?;

    let num_k = c.u32_be()?;
    let mut k = Vec::new();
    for _ in 0..num_k {
        k.push(g1c(&mut c)?);
    }

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 { alpha: g1_alpha, k },
        g2: Groth16G2 { beta: -g2_beta, gamma: g2_gamma, delta: g2_delta },
    })
}

#[cfg(test)]
mod tests {
    use super::{load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes};

    /// See the note in the plonk converter's tests: these run against the
    /// loaders directly, because the public wrappers reject earlier.
    #[test]
    fn loaders_are_total() {
        for n in 0..700usize {
            let _ = load_groth16_proof_from_bytes(&vec![0u8; n]);
            let _ = load_groth16_verifying_key_from_bytes(&vec![0u8; n]);
        }
    }

    #[test]
    fn vk_loader_rejects_a_hostile_k_count() {
        let mut vk = vec![0u8; 512];
        vk[288..292].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(load_groth16_verifying_key_from_bytes(&vk).is_err());
    }
}
