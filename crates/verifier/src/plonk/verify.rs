use alloc::{string::ToString, vec, vec::Vec};
use core::hash::Hasher;
use substrate_bn::{arith::U256, AffineG1, Fr};

use crate::{
    error::Error,
    plonk::{kzg::BatchOpeningProof, transcript::Transcript},
};

use super::{
    converter::g1_to_bytes, error::PlonkError, kzg, PlonkProof, ALPHA, BETA, GAMMA, U, ZETA,
};
#[derive(Debug)]
pub(crate) struct PlonkVerifyingKey {
    pub(crate) size: usize,
    pub(crate) size_inv: Fr,
    pub(crate) generator: Fr,
    pub(crate) nb_public_variables: usize,

    pub(crate) kzg: kzg::KZGVerifyingKey,

    pub(crate) coset_shift: Fr,

    pub(crate) s: [kzg::Digest; 3],

    pub(crate) ql: kzg::Digest,
    pub(crate) qr: kzg::Digest,
    pub(crate) qm: kzg::Digest,
    pub(crate) qo: kzg::Digest,
    pub(crate) qk: kzg::Digest,
    pub(crate) qcp: Vec<kzg::Digest>,

    pub(crate) commitment_constraint_indexes: Vec<usize>,
}

/// Verifies a PLONK proof using algebraic inputs.
///
/// # Arguments
///
/// * `vk` - The verifying key
/// * `proof` - The PLONK proof
/// * `public_inputs` - The public inputs to the circuit
///
/// # Returns
///
/// * `Result<bool, PlonkError>` - Returns true if the proof is valid, or an error if verification fails
pub(crate) fn verify_plonk_algebraic(
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof,
    public_inputs: &[Fr],
) -> Result<(), PlonkError> {
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err(PlonkError::Bsb22CommitmentMismatch);
    }

    if public_inputs.len() != vk.nb_public_variables {
        return Err(PlonkError::InvalidWitness);
    }

    let mut fs = Transcript::new(Some(
        [GAMMA.to_string(), BETA.to_string(), ALPHA.to_string(), ZETA.to_string(), U.to_string()]
            .to_vec(),
    ))?;

    bind_public_data(&mut fs, GAMMA, vk, public_inputs)?;

    let gamma = derive_randomness(
        &mut fs,
        GAMMA,
        Some([proof.lro[0], proof.lro[1], proof.lro[2]].to_vec()),
    )?;

    let beta = derive_randomness(&mut fs, BETA, None)?;

    let mut alpha_deps: Vec<AffineG1> = proof.bsb22_commitments.to_vec();
    alpha_deps.push(proof.z);
    let alpha = derive_randomness(&mut fs, ALPHA, Some(alpha_deps))?;

    let zeta =
        derive_randomness(&mut fs, ZETA, Some([proof.h[0], proof.h[1], proof.h[2]].to_vec()))?;

    let one = Fr::one();
    let n = U256::from(vk.size as u64);
    let n =
        Fr::from_slice(&n.to_bytes_be()).map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    let zeta_power_n = zeta.pow(n);
    let zh_zeta = zeta_power_n - one;

    let mut lagrange_one = (zeta - one).inverse().ok_or(PlonkError::InverseNotFound)?;
    lagrange_one *= zh_zeta;
    lagrange_one *= vk.size_inv;

    let mut pi = Fr::zero();
    let mut accw = Fr::one();
    let mut dens = Vec::with_capacity(public_inputs.len());

    for _ in 0..public_inputs.len() {
        let mut temp = zeta;
        temp -= accw;
        dens.push(temp);
        accw *= vk.generator;
    }

    let inv_dens = batch_invert(&dens)?;

    accw = Fr::one();
    let mut xi_li;
    for (i, public_input) in public_inputs.iter().enumerate() {
        xi_li = zh_zeta;
        xi_li *= inv_dens[i];
        xi_li *= vk.size_inv;
        xi_li *= accw;
        xi_li *= *public_input;
        accw *= vk.generator;
        pi += xi_li;
    }

    let mut hash_to_field = crate::plonk::hash_to_field::WrappedHashToField::new(b"BSB22-Plonk")?;

    for i in 0..vk.commitment_constraint_indexes.len() {
        hash_to_field.write(&g1_to_bytes(&proof.bsb22_commitments[i])?);
        let hash_bts = hash_to_field.sum()?;
        hash_to_field.reset();
        let hashed_cmt = Fr::from_bytes_be_mod_order(&hash_bts)
            .map_err(|_| Error::FailedToGetFrFromRandomBytes)?;

        let exponent =
            U256::from((vk.nb_public_variables + vk.commitment_constraint_indexes[i]) as u64);
        let exponent = Fr::new(exponent).ok_or(PlonkError::BeyondTheModulus)?;
        let w_pow_i = vk.generator.pow(exponent);
        let mut den = zeta;
        den -= w_pow_i;
        let mut lagrange = zh_zeta;
        lagrange *= w_pow_i;
        lagrange /= den;
        lagrange *= vk.size_inv;

        xi_li = lagrange;
        xi_li *= hashed_cmt;
        pi += xi_li;
    }

    let l = proof.batched_proof.claimed_values[0];
    let r = proof.batched_proof.claimed_values[1];
    let o = proof.batched_proof.claimed_values[2];
    let s1 = proof.batched_proof.claimed_values[3];
    let s2 = proof.batched_proof.claimed_values[4];

    let zu = proof.z_shifted_opening.claimed_value;

    let alpha_square_lagrange_one = {
        let mut tmp = lagrange_one;
        tmp *= alpha;
        tmp *= alpha;
        tmp
    };

    let mut tmp = beta;
    tmp *= s1;
    tmp += gamma;
    tmp += l;
    let mut const_lin = tmp;

    tmp = beta;
    tmp *= s2;
    tmp += gamma;
    tmp += r;

    const_lin *= tmp;

    tmp = o;
    tmp += gamma;

    const_lin *= tmp;
    const_lin *= alpha;
    const_lin *= zu;

    const_lin -= alpha_square_lagrange_one;
    const_lin += pi;

    const_lin = -const_lin;

    let mut _s1 = beta * s1 + l + gamma;
    let tmp = beta * s2 + r + gamma;
    _s1 = _s1 * tmp * beta * alpha * zu;

    let mut _s2 = beta * zeta + gamma + l;
    let mut tmp = beta * vk.coset_shift * zeta + gamma + r;
    _s2 *= tmp;
    tmp = beta * vk.coset_shift * vk.coset_shift * zeta + gamma + o;
    _s2 *= tmp;
    _s2 *= alpha;
    _s2 = -_s2;

    let coeff_z = alpha_square_lagrange_one + _s2;

    let rl = l * r;

    let n_plus_two = U256::from(vk.size as u64 + 2);
    let n_plus_two = Fr::from_slice(&n_plus_two.to_bytes_be())
        .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;

    let mut zeta_n_plus_two_zh = zeta.pow(n_plus_two);
    let mut zeta_n_plus_two_square_zh = zeta_n_plus_two_zh * zeta_n_plus_two_zh;
    zeta_n_plus_two_zh *= zh_zeta;
    zeta_n_plus_two_zh = -zeta_n_plus_two_zh;
    zeta_n_plus_two_square_zh *= zh_zeta;
    zeta_n_plus_two_square_zh = -zeta_n_plus_two_square_zh;
    let zh = -zh_zeta;

    let mut points = Vec::new();
    points.extend_from_slice(&proof.bsb22_commitments);
    points.push(vk.ql);
    points.push(vk.qr);
    points.push(vk.qm);
    points.push(vk.qo);
    points.push(vk.qk);
    points.push(vk.s[2]);
    points.push(proof.z);
    points.push(proof.h[0]);
    points.push(proof.h[1]);
    points.push(proof.h[2]);

    let qc = proof.batched_proof.claimed_values[5..].to_vec();

    let mut scalars = Vec::new();
    scalars.extend_from_slice(&qc);
    scalars.push(l);
    scalars.push(r);
    scalars.push(rl);
    scalars.push(o);
    scalars.push(one);
    scalars.push(_s1);
    scalars.push(coeff_z);
    scalars.push(zh);
    scalars.push(zeta_n_plus_two_zh);
    scalars.push(zeta_n_plus_two_square_zh);

    let linearized_polynomial_digest = AffineG1::msm(&points, &scalars);

    let mut digests_to_fold = vec![AffineG1::default(); vk.qcp.len() + 6];
    digests_to_fold[6..].copy_from_slice(&vk.qcp);
    digests_to_fold[0] = linearized_polynomial_digest;
    digests_to_fold[1] = proof.lro[0];
    digests_to_fold[2] = proof.lro[1];
    digests_to_fold[3] = proof.lro[2];
    digests_to_fold[4] = vk.s[0];
    digests_to_fold[5] = vk.s[1];

    let claimed_values = [vec![const_lin], proof.batched_proof.claimed_values.clone()].concat();
    let batch_opening_proof = BatchOpeningProof { h: proof.batched_proof.h, claimed_values };

    let (folded_proof, folded_digest) = kzg::fold_proof(
        digests_to_fold,
        &batch_opening_proof,
        &zeta,
        Some(zu.into_u256().to_bytes_be().to_vec()),
        &mut fs,
    )?;

    let u = derive_randomness(
        &mut fs,
        U,
        Some(vec![folded_digest, proof.z, folded_proof.h, proof.z_shifted_opening.h]),
    )?;

    let shifted_zeta = zeta * vk.generator;

    let folded_digest: AffineG1 = folded_digest;

    kzg::batch_verify_multi_points(
        [folded_digest, proof.z].to_vec(),
        [folded_proof, proof.z_shifted_opening].to_vec(),
        [zeta, shifted_zeta].to_vec(),
        u,
        &vk.kzg,
    )?;

    Ok(())
}

/// Binds all plonk public data to the transcript.
fn bind_public_data(
    transcript: &mut Transcript,
    challenge: &str,
    vk: &PlonkVerifyingKey,
    public_inputs: &[Fr],
) -> Result<(), PlonkError> {
    transcript.bind(challenge, &g1_to_bytes(&vk.s[0])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[1])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[2])?)?;

    transcript.bind(challenge, &g1_to_bytes(&vk.ql)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qr)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qm)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qo)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qk)?)?;

    for qcp in vk.qcp.iter() {
        transcript.bind(challenge, &g1_to_bytes(qcp)?)?;
    }

    for public_input in public_inputs.iter() {
        transcript.bind(challenge, &public_input.into_u256().to_bytes_be())?;
    }

    Ok(())
}

/// Derives the randomness from the transcript.
///
/// If you want to include some data for a challenge that isn't an affine g1 point, use
/// [`Transcript::bind`] to bind the data to the transcript before deriving the randomness.
fn derive_randomness(
    transcript: &mut Transcript,
    challenge: &str,
    points: Option<Vec<AffineG1>>,
) -> Result<Fr, PlonkError> {
    if let Some(points) = points {
        for point in points {
            let buf = g1_to_bytes(&point)?;
            transcript.bind(challenge, &buf)?;
        }
    }

    let b = transcript.compute_challenge(challenge)?;
    let x = Fr::from_bytes_be_mod_order(b.as_slice())
        .map_err(|e| PlonkError::GeneralError(Error::Field(e)))?;
    Ok(x)
}

/// Wrapper for [`batch_inversion`].
fn batch_invert(elements: &[Fr]) -> Result<Vec<Fr>, PlonkError> {
    let mut elements = elements.to_vec();
    batch_inversion(&mut elements);
    Ok(elements)
}

/// Inverts a batch of Fr elements.
fn batch_inversion(v: &mut [Fr]) {
    batch_inversion_and_mul(v, &Fr::one());
}

/// Inverts a batch of Fr elements and multiplies them by a given coefficient.
fn batch_inversion_and_mul(v: &mut [Fr], coeff: &Fr) {
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = Fr::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp *= *f;
        prod.push(tmp);
    }

    tmp = tmp.inverse().unwrap();

    tmp *= *coeff;

    for (f, s) in v
        .iter_mut()
        .rev()
        .filter(|f| !f.is_zero())
        .zip(prod.into_iter().rev().skip(1).chain(Some(Fr::one())))
    {
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}
