use num::BigUint;
use std::marker::PhantomData;
use zkm_curves::weierstrass::{FieldType, FpOpField};

use crate::{
    events::{FieldOperation, Fp2AddSubEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
    ExecutionError,
};

pub struct Fp2AddSubSyscall<P, const S: usize> {
    op: FieldOperation,
    _marker: PhantomData<P>,
}

impl<P, const S: usize> Fp2AddSubSyscall<P, S> {
    pub const fn new(op: FieldOperation) -> Self {
        Self { op, _marker: PhantomData }
    }
}

impl<P: FpOpField, const S: usize> Syscall for Fp2AddSubSyscall<P, S> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Result<Option<u32>, ExecutionError> {
        let clk = rt.clk;
        let x_ptr = arg1;
        if !x_ptr.is_multiple_of(4) {
            panic!();
        }
        let y_ptr = arg2;
        if !y_ptr.is_multiple_of(4) {
            panic!();
        }

        //let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

        let x = rt.slice_unsafe::<S>(x_ptr);
        let (y_memory_records, y) = rt.mr_array::<S>(y_ptr);
        rt.clk += 1;

        let (ac0, ac1) = x.split_at(x.len() / 2);
        let (bc0, bc1) = y.split_at(y.len() / 2);

        let ac0 = &BigUint::from_slice(ac0);
        let ac1 = &BigUint::from_slice(ac1);
        let bc0 = &BigUint::from_slice(bc0);
        let bc1 = &BigUint::from_slice(bc1);
        let modulus = &BigUint::from_bytes_le(P::MODULUS);

        let (c0, c1) = match self.op {
            FieldOperation::Add => ((ac0 + bc0) % modulus, (ac1 + bc1) % modulus),
            FieldOperation::Sub => {
                ((ac0 + modulus - bc0) % modulus, (ac1 + modulus - bc1) % modulus)
            }
            _ => panic!("Invalid operation"),
        };

        let mut result = c0.to_u32_digits();
        result.resize(S / 2, 0);
        result.extend_from_slice(&c1.to_u32_digits());
        result.resize(S, 0);

        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let shard = rt.current_shard();
        let op = self.op;
        let event = Fp2AddSubEvent {
            shard,
            clk,
            op,
            x_ptr,
            x: x.to_vec(),
            y_ptr,
            y: x.to_vec(),
            x_memory_records,
            y_memory_records: y_memory_records.to_vec(),
            local_mem_access: rt.postprocess(),
        };
        match P::FIELD_TYPE {
            // All the fp2 add and sub events for a given curve are coalesced to the curve's fp2 add operation.  Only check for
            // that operation.
            // TODO:  Fix this.
            FieldType::Bn254 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
                        SyscallCode::BN254_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt.rt.syscall_event(
                    clk,
                    None,
                    rt.next_pc,
                    syscall_code.syscall_id(),
                    arg1,
                    arg2,
                );
                rt.add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bn254Fp2AddSub(event),
                );
            }
            FieldType::Bls12381 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
                        SyscallCode::BLS12381_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt.rt.syscall_event(
                    clk,
                    None,
                    rt.next_pc,
                    syscall_code.syscall_id(),
                    arg1,
                    arg2,
                );
                rt.add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bls12381Fp2AddSub(event),
                );
            }
        }
        Ok(None)
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
