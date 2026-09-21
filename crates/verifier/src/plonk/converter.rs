use crate::{
    converter::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point,
    },
    cursor::Cursor,
    error::Error,
};
use alloc::vec::Vec;
use substrate_bn::{AffineG1, Fr, G2};

use super::{
    error::PlonkError,
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

pub(crate) fn load_plonk_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<PlonkVerifyingKey, PlonkError> {
    // Reached from the public `verify_gnark_proof`, so the verifying key is as
    // untrusted as the proof: both `num_qcp` and
    // `num_commitment_constraint_indexes` come out of these same bytes.
    let mut c = Cursor::new(buffer);
    let fr = |c: &mut Cursor<'_>| -> Result<Fr, PlonkError> {
        Fr::from_slice(c.take(32)?).map_err(|e| PlonkError::GeneralError(Error::Field(e)))
    };
    let g1c = |c: &mut Cursor<'_>| -> Result<AffineG1, PlonkError> {
        Ok(unchecked_compressed_x_to_g1_point(c.take(32)?)?)
    };

    let size = c.u64_be()? as usize;
    let size_inv = fr(&mut c)?;
    let generator = fr(&mut c)?;
    let nb_public_variables = c.u64_be()? as usize;
    let coset_shift = fr(&mut c)?;
    let s0 = g1c(&mut c)?;
    let s1 = g1c(&mut c)?;
    let s2 = g1c(&mut c)?;
    let ql = g1c(&mut c)?;
    let qr = g1c(&mut c)?;
    let qm = g1c(&mut c)?;
    let qo = g1c(&mut c)?;
    let qk = g1c(&mut c)?;

    let num_qcp = c.u32_be()?;
    let mut qcp = Vec::new();
    for _ in 0..num_qcp {
        qcp.push(g1c(&mut c)?);
    }

    let g1 = g1c(&mut c)?;
    let g2_0 = unchecked_compressed_x_to_g2_point(c.take(64)?)?;
    let g2_1 = unchecked_compressed_x_to_g2_point(c.take(64)?)?;

    c.skip(33788)?;

    // `count` refuses a length the remaining bytes could not back, so a hostile
    // u64 cannot reserve gigabytes before the reads fail.
    let num_commitment_constraint_indexes = c.count(8)?;
    let mut commitment_constraint_indexes = Vec::with_capacity(num_commitment_constraint_indexes);
    for _ in 0..num_commitment_constraint_indexes {
        commitment_constraint_indexes.push(c.u64_be()? as usize);
    }

    let result = PlonkVerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::KZGVerifyingKey {
            g2: [G2::from(g2_0), G2::from(g2_1)],
            g1: g1.into(),
            lines: [[[LineEvaluationAff {
                r0: E2 { a0: Fr::zero(), a1: Fr::zero() },
                r1: E2 { a0: Fr::zero(), a1: Fr::zero() },
            }; 66]; 2]; 2],
        },
        coset_shift,
        s: [s0, s1, s2],
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    };

    Ok(result)
}

/// See https://github.com/jtguibas/gnark/blob/26e3df73fc223292be8b7fc0b7451caa4059a649/backend/plonk/bn254/solidity.go
/// for how the proof is serialized.
pub(crate) fn load_plonk_proof_from_bytes(
    buffer: &[u8],
    num_bsb22_commitments: usize,
) -> Result<PlonkProof, PlonkError> {
    // Every read goes through the cursor: a guard on the leading 384 bytes is
    // not enough, because the very next field starts there and `num_bsb22_
    // commitments` makes the tail variable-length.
    let mut c = Cursor::new(buffer);
    let g1 = |c: &mut Cursor<'_>| -> Result<AffineG1, PlonkError> {
        Ok(uncompressed_bytes_to_g1_point(c.take(64)?)?)
    };
    let lro0 = g1(&mut c)?;
    let lro1 = g1(&mut c)?;
    let lro2 = g1(&mut c)?;
    let h0 = g1(&mut c)?;
    let h1 = g1(&mut c)?;
    let h2 = g1(&mut c)?;

    let fr = |c: &mut Cursor<'_>| -> Result<Fr, PlonkError> {
        Fr::from_slice(c.take(32)?).map_err(|e| PlonkError::GeneralError(Error::Field(e)))
    };

    // Stores l_at_zeta, r_at_zeta, o_at_zeta, s1_at_zeta, s2_at_zeta, bsb22_commitments
    let mut claimed_values = Vec::with_capacity(5 + num_bsb22_commitments);
    for _ in 1..6 {
        claimed_values.push(fr(&mut c)?);
    }

    let z = g1(&mut c)?;
    let z_shifted_opening_value = fr(&mut c)?;

    let batched_proof_h = g1(&mut c)?;
    let z_shifted_opening_h = g1(&mut c)?;

    for _ in 0..num_bsb22_commitments {
        claimed_values.push(fr(&mut c)?);
    }

    let mut bsb22_commitments = Vec::with_capacity(num_bsb22_commitments);
    for _ in 0..num_bsb22_commitments {
        bsb22_commitments.push(g1(&mut c)?);
    }

    let result = PlonkProof {
        lro: [lro0, lro1, lro2],
        z,
        h: [h0, h1, h2],
        bsb22_commitments,
        batched_proof: BatchOpeningProof { h: batched_proof_h, claimed_values },
        z_shifted_opening: OpeningProof {
            h: z_shifted_opening_h,
            claimed_value: z_shifted_opening_value,
        },
    };

    Ok(result)
}

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<[u8; 64], PlonkError> {
    let mut bytes: [u8; 64] = unsafe { core::mem::transmute(*g1) };
    bytes[..32].reverse();
    bytes[32..].reverse();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes};

    /// Totality over arbitrary bytes: these loaders are reached from the public
    /// `verify_gnark_proof` with caller-supplied input, so no length may panic.
    ///
    /// Testing the loaders directly rather than through `PlonkVerifier::verify`
    /// is deliberate: `verify` rejects on a vkey-hash prefix mismatch, and
    /// `verify_gnark_proof` parses the VK first, so a truncation test written
    /// against either never reaches the proof loader at all.
    /// 64 uncompressed bytes for the BN254 G1 generator `(1, 2)`.
    ///
    /// Zero bytes are NOT a point -- `AffineG1::new(0, 0)` is not on the curve,
    /// so a zero-filled proof fails at the very first read and never reaches
    /// the later offsets. The truncation test needs the leading points to parse
    /// so that it actually walks past byte 384.
    fn g1_generator() -> [u8; 64] {
        let mut b = [0u8; 64];
        b[31] = 1; // x = 1
        b[63] = 2; // y = 2
        b
    }

    /// A proof whose first six points are real, then zeros.
    fn well_formed_prefix(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len.max(384)];
        for i in 0..6 {
            v[i * 64..(i + 1) * 64].copy_from_slice(&g1_generator());
        }
        v.truncate(len);
        v
    }

    #[test]
    fn proof_loader_is_total() {
        // Every boundary through and well past 384, where `buffer[384..416]`
        // used to panic, and with a commitment count that extends the tail.
        for commitments in [0usize, 1, 3] {
            for n in 0..1100usize {
                let _ = load_plonk_proof_from_bytes(&well_formed_prefix(n), commitments);
            }
        }
    }

    #[test]
    fn proof_loader_survives_the_384_boundary() {
        // The exact input the first attempt at this fix still panicked on: six
        // valid points and nothing after them.
        assert!(load_plonk_proof_from_bytes(&well_formed_prefix(384), 0).is_err());
        for n in 384..520usize {
            assert!(load_plonk_proof_from_bytes(&well_formed_prefix(n), 0).is_err());
        }
    }

    #[test]
    fn proof_loader_rejects_a_hostile_commitment_count() {
        let _ = load_plonk_proof_from_bytes(&vec![0u8; 1024], usize::MAX);
        assert!(load_plonk_proof_from_bytes(&vec![0u8; 1024], usize::MAX).is_err());
    }

    #[test]
    fn vk_loader_is_total() {
        for n in 0..1200usize {
            let _ = load_plonk_verifying_key_from_bytes(&vec![0u8; n]);
        }
    }

    #[test]
    fn vk_loader_rejects_hostile_counts() {
        // num_qcp at 368..372 and the index count near the end are both read
        // out of the buffer being parsed.
        let mut vk = vec![0u8; 40000];
        vk[368..372].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(load_plonk_verifying_key_from_bytes(&vk).is_err());

        let mut vk = vec![0u8; 40000];
        let at = 372 + 160 + 33788;
        vk[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(load_plonk_verifying_key_from_bytes(&vk).is_err());
    }
}
