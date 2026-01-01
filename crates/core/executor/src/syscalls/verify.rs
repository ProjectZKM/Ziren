use crate::program::MAX_MEMORY;

use crate::ExecutionError;

use super::{Syscall, SyscallCode, SyscallContext};

pub(crate) struct VerifySyscall;

impl Syscall for VerifySyscall {
    #[allow(clippy::mut_mut)]
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        vkey_ptr: u32,
        pv_digest_ptr: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let rt = &mut ctx.rt;

        // vkey_ptr is a pointer to [u32; 8] which contains the verification key.
        // pv_digest_ptr is a pointer to [u32; 8] which contains the public values digest.

        if !vkey_ptr.is_multiple_of(4) || !pv_digest_ptr.is_multiple_of(4) {
            return Err(ExecutionError::InvalidSyscallArgs());
        }

        if vkey_ptr as usize + 32 > MAX_MEMORY || pv_digest_ptr as usize + 32 > MAX_MEMORY {
            return Err(ExecutionError::InvalidSyscallArgs());
        }

        let vkey = (0..8).map(|i| rt.word(vkey_ptr + i * 4)).collect::<Vec<u32>>();

        let pv_digest = (0..8).map(|i| rt.word(pv_digest_ptr + i * 4)).collect::<Vec<u32>>();

        let proof_index = rt.state.proof_stream_ptr;
        if proof_index >= rt.state.proof_stream.len() {
            panic!("Not enough proofs were written to the runtime.");
        }
        let (proof, proof_vk) = &rt.state.proof_stream[proof_index].clone();
        rt.state.proof_stream_ptr += 1;

        let vkey_bytes: [u32; 8] = vkey.try_into().unwrap();
        let pv_digest_bytes: [u32; 8] = pv_digest.try_into().unwrap();

        if let Some(verifier) = rt.subproof_verifier {
            if let Err(e) =
                verifier.verify_deferred_proof(proof, proof_vk, vkey_bytes, pv_digest_bytes)
            {
                log::error!(
                    "Failed to verify proof {proof_index} with digest {}: {}",
                    hex::encode(bytemuck::cast_slice(&pv_digest_bytes)),
                    e
                );
                return Err(ExecutionError::ExceptionOrTrap());
            }
        } else if rt.state.proof_stream_ptr == 1 {
            tracing::info!("Not verifying sub proof during runtime");
        };

        Ok(None)
    }
}
