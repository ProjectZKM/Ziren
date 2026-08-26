use std::borrow::Borrow;

use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction<F> {
    BaseAlu(BaseAluInstr<F>),
    ExtAlu(ExtAluInstr<F>),
    Mem(MemInstr<F>),
    Poseidon2(Box<Poseidon2Instr<F>>),
    Select(SelectInstr<F>),
    HintBits(HintBitsInstr<F>),
    HintAddCurve(Box<HintAddCurveInstr<F>>),
    Print(PrintInstr<F>),
    HintExt2Felts(HintExt2FeltsInstr<F>),
    /// Constrained twin of `HintExt2Felts`: same operands, but the rows land
    /// on the `Ext2Felt` chip, which RECEIVES the input block and sends its
    /// limbs — so no call-site re-binding is needed.  Compress-machine
    /// programs only; shrink/wrap keep `HintExt2Felts` (their machines have
    /// no `Ext2Felt` chip — the wrap R1CS must not change).
    Ext2Felts(HintExt2FeltsInstr<F>),
    CommitPublicValues(Box<CommitPublicValuesInstr<F>>),
    Hint(HintInstr<F>),
}

/// The executor walks millions of these per recursion node and the program
/// cache holds every distinct program at once, so the enum's WIDTH is a
/// first-order cost twice over: it sets the memory traffic of the dispatch
/// loop and it sets the cache's resident size.  A variant is boxed as soon as
/// it would widen the enum for everyone else -- `HintAddCurve` carries six
/// `Vec`s (144 bytes) and appears a handful of times in a program of millions.
const _: () = assert!(
    std::mem::size_of::<Instruction<u32>>() <= 40,
    "Instruction grew: box the widest variant rather than widening every instruction",
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintBitsInstr<F> {
    /// Addresses and mults of the output bits.
    pub output_addrs_mults: Vec<(Address<F>, F)>,
    /// Input value to decompose.
    pub input_addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrintInstr<F> {
    pub field_elt_type: FieldEltType,
    pub addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintAddCurveInstr<F> {
    pub output_x_addrs_mults: Vec<(Address<F>, F)>,
    pub output_y_addrs_mults: Vec<(Address<F>, F)>,
    pub input1_x_addrs: Vec<Address<F>>,
    pub input1_y_addrs: Vec<Address<F>>,
    pub input2_x_addrs: Vec<Address<F>>,
    pub input2_y_addrs: Vec<Address<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintInstr<F> {
    /// Addresses and mults of the output felts.
    pub output_addrs_mults: Vec<(Address<F>, F)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintExt2FeltsInstr<F> {
    /// Addresses and mults of the output bits.
    pub output_addrs_mults: [(Address<F>, F); D],
    /// Input value to decompose.
    pub input_addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FieldEltType {
    Base,
    Extension,
}

pub fn base_alu<F: PrimeCharacteristicRing>(
    opcode: BaseAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::BaseAlu(BaseAluInstr {
        opcode,
        mult: F::from_u32(mult),
        addrs: BaseAluIo {
            out: Address(F::from_u32(out)),
            in1: Address(F::from_u32(in1)),
            in2: Address(F::from_u32(in2)),
        },
    })
}

pub fn ext_alu<F: PrimeCharacteristicRing>(
    opcode: ExtAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::ExtAlu(ExtAluInstr {
        opcode,
        mult: F::from_u32(mult),
        addrs: ExtAluIo {
            out: Address(F::from_u32(out)),
            in1: Address(F::from_u32(in1)),
            in2: Address(F::from_u32(in2)),
        },
    })
}

pub fn mem<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: u32,
) -> Instruction<F> {
    mem_single(kind, mult, addr, F::from_u32(val))
}

pub fn mem_single<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: F,
) -> Instruction<F> {
    mem_block(kind, mult, addr, Block::from(val))
}

pub fn mem_ext<F: Field + Copy, EF: ExtensionField<F>>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: EF,
) -> Instruction<F> {
    mem_block(kind, mult, addr, val.as_basis_coefficients_slice().into())
}

pub fn mem_block<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: Block<F>,
) -> Instruction<F> {
    Instruction::Mem(MemInstr {
        addrs: MemIo { inner: Address(F::from_u32(addr)) },
        vals: MemIo { inner: val },
        mult: F::from_u32(mult),
        kind,
    })
}

pub fn poseidon2<F: PrimeCharacteristicRing>(
    mults: [u32; WIDTH],
    output: [u32; WIDTH],
    input: [u32; WIDTH],
) -> Instruction<F> {
    Instruction::Poseidon2(Box::new(Poseidon2Instr {
        mults: mults.map(F::from_u32),
        addrs: Poseidon2Io {
            output: output.map(F::from_u32).map(Address),
            input: input.map(F::from_u32).map(Address),
        },
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn select<F: PrimeCharacteristicRing>(
    mult1: u32,
    mult2: u32,
    bit: u32,
    out1: u32,
    out2: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::Select(SelectInstr {
        mult1: F::from_u32(mult1),
        mult2: F::from_u32(mult2),
        addrs: SelectIo {
            bit: Address(F::from_u32(bit)),
            out1: Address(F::from_u32(out1)),
            out2: Address(F::from_u32(out2)),
            in1: Address(F::from_u32(in1)),
            in2: Address(F::from_u32(in2)),
        },
    })
}

pub fn commit_public_values<F: PrimeCharacteristicRing>(
    public_values_a: &RecursionPublicValues<u32>,
) -> Instruction<F> {
    let pv_a = public_values_a.as_array().map(|pv| Address(F::from_u32(pv)));
    let pv_address: &RecursionPublicValues<Address<F>> = pv_a.as_slice().borrow();

    Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
        pv_addrs: pv_address.clone(),
    }))
}
