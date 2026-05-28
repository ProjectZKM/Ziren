use chips::poseidon2_skinny::WIDTH;
use core::fmt::Debug;
use instruction::{
    FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr,
};
use itertools::Itertools;
use p3_field::{
    Field, PrimeCharacteristicRing, ExtensionField, PrimeField, PrimeField64, TwoAdicField,
};
use std::{borrow::Borrow, collections::HashMap, mem::transmute};
use vec_map::VecMap;
use zkm_core_machine::utils::{zkm_debug_mode, SpanBuilder};
use zkm_recursion_core::{
    air::{Block, RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    BaseAluInstr, BaseAluOpcode,
};
use zkm_stark::septic_curve::SepticCurve;

use zkm_recursion_core::*;

use crate::prelude::*;

/// The number of instructions to preallocate in a recursion program
const PREALLOC_INSTRUCTIONS: usize = 10000000;

/// The backend for the circuit compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler<C: Config> {
    pub next_addr: C::F,
    /// Map the frame pointers of the variables to the "physical" addresses.
    pub virtual_to_physical: VecMap<Address<C::F>>,
    /// Map base or extension field constants to "physical" addresses and mults.
    pub consts: HashMap<Imm<C::F, C::EF>, (Address<C::F>, C::F)>,
    /// Map each "physical" address to its read count.
    pub addr_to_mult: VecMap<C::F>,
}

impl<C: Config> AsmCompiler<C>
where
    C::F: PrimeField64,
{
    /// Allocate a fresh address. Checks that the address space is not full.
    pub fn alloc(next_addr: &mut C::F) -> Address<C::F> {
        let id = Address(*next_addr);
        *next_addr += C::F::ONE;
        if next_addr.is_zero() {
            panic!("out of address space");
        }
        id
    }

    /// Map `fp` to its existing address without changing its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_ghost_vaddr(&mut self, vaddr: usize) -> Address<C::F> {
        self.read_vaddr_internal(vaddr, false)
    }

    /// Map `fp` to its existing address and increment its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_vaddr(&mut self, vaddr: usize) -> Address<C::F> {
        self.read_vaddr_internal(vaddr, true)
    }

    pub fn read_vaddr_internal(&mut self, vaddr: usize, increment_mult: bool) -> Address<C::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(_) => panic!("expected entry: virtual_physical[{vaddr:?}]"),
            Entry::Occupied(entry) => {
                if increment_mult {
                    // This is a read, so we increment the mult.
                    match self.addr_to_mult.get_mut(entry.get().as_usize()) {
                        Some(mult) => *mult += C::F::ONE,
                        None => panic!("expected entry: virtual_physical[{vaddr:?}]"),
                    }
                }
                *entry.into_mut()
            }
        }
    }

    /// Map `fp` to a fresh address and initialize the mult to 0.
    ///
    /// Ensures that `fp` has not already been written to.
    pub fn write_fp(&mut self, vaddr: usize) -> Address<C::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr.as_usize(), C::F::ZERO) {
                    panic!("unexpected entry in addr_to_mult: {x:?}");
                }
                *entry.insert(addr)
            }
            Entry::Occupied(entry) => {
                panic!("unexpected entry: virtual_to_physical[{:?}] = {:?}", vaddr, entry.get())
            }
        }
    }

    /// Increment the existing `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        self.read_addr_internal(addr, true)
    }

    /// Retrieves `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_ghost_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        self.read_addr_internal(addr, true)
    }

    fn read_addr_internal(&mut self, addr: Address<C::F>, increment_mult: bool) -> &mut C::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(_) => panic!("expected entry: addr_to_mult[{:?}]", addr.as_usize()),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                let mult = entry.into_mut();
                if increment_mult {
                    *mult += C::F::ONE;
                }
                mult
            }
        }
    }

    /// Associate a `mult` of zero with `addr`.
    ///
    /// Ensures that `addr` has not already been written to.
    pub fn write_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(entry) => entry.insert(C::F::ZERO),
            Entry::Occupied(entry) => {
                panic!("unexpected entry: addr_to_mult[{:?}] = {:?}", addr.as_usize(), entry.get())
            }
        }
    }

    /// Read a constant (a.k.a. immediate).
    ///
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const(&mut self, imm: Imm<C::F, C::EF>) -> Address<C::F> {
        self.consts
            .entry(imm)
            .and_modify(|(_, x)| *x += C::F::ONE)
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), C::F::ONE))
            .0
    }

    /// Read a constant (a.k.a. immediate).
    ///
    /// Does not increment the mult. Creates an entry if it does not yet exist.
    pub fn read_ghost_const(&mut self, imm: Imm<C::F, C::EF>) -> Address<C::F> {
        self.consts.entry(imm).or_insert_with(|| (Self::alloc(&mut self.next_addr), C::F::ZERO)).0
    }

    fn mem_write_const(&mut self, dst: impl Reg<C>, src: Imm<C::F, C::EF>) -> Instruction<C::F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo { inner: dst.write(self) },
            vals: MemIo { inner: src.as_block() },
            mult: C::F::ZERO,
            kind: MemAccessKind::Write,
        })
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: C::F::ZERO,
            addrs: BaseAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: C::F::ZERO,
            addrs: ExtAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    /// Emit `lhs == rhs` as `(lhs - rhs) / 0 = out` (DivF by 0).
    /// The AIR catches `lhs != rhs` because the constraint
    /// `divisor * out = numerator` becomes `0 * out = (lhs - rhs)`,
    /// which has no solution unless `lhs == rhs`.
    ///
    /// **Uses plain `DivF`** (SP1-parity — see SP1
    /// `crates/recursion/compiler/src/circuit/compiler.rs`'s
    /// `base_assert_eq`).  The runtime's `DivF` mult=0 guard makes
    /// dead-branch execution graceful (returns 0; constraint gated
    /// off via `is_div_active = is_div AND mult>0` so no AIR
    /// obligation on the dead row).  Live-branch failures still
    /// panic via `DivFOutOfDomain` since mult>0 bypasses the guard.
    ///
    /// The previous `DivFAssert` opcode used here was designed to
    /// "always fire" the constraint even when mult=0 — but that
    /// blocks the standard dead-branch idiom (assertions inside
    /// Select branches where only one side's mult is nonzero), which
    /// the recursion DSL relies on heavily.  Matches SP1's
    /// behaviour on the same DSL patterns.
    fn base_assert_eq(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, diff, Imm::F(C::F::ZERO)));
    }

    fn base_assert_ne(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, Imm::F(C::F::ONE), diff));
    }

    fn ext_assert_eq(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, diff, Imm::EF(C::EF::ZERO)));
    }

    fn ext_assert_ne(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, Imm::EF(C::EF::ONE), diff));
    }

    #[inline(always)]
    fn poseidon2_permute(
        &mut self,
        dst: [impl Reg<C>; WIDTH],
        src: [impl Reg<C>; WIDTH],
    ) -> Instruction<C::F> {
        Instruction::Poseidon2(Box::new(Poseidon2Instr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [C::F::ZERO; WIDTH],
        }))
    }

    #[inline(always)]
    fn select(
        &mut self,
        bit: impl Reg<C>,
        dst1: impl Reg<C>,
        dst2: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::Select(SelectInstr {
            addrs: SelectIo {
                bit: bit.read(self),
                out1: dst1.write(self),
                out2: dst2.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
            mult1: C::F::ZERO,
            mult2: C::F::ZERO,
        })
    }

    fn exp_reverse_bits(
        &mut self,
        dst: impl Reg<C>,
        base: impl Reg<C>,
        exp: impl IntoIterator<Item = impl Reg<C>>,
    ) -> Instruction<C::F> {
        Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
            addrs: ExpReverseBitsIo {
                result: dst.write(self),
                base: base.read(self),
                exp: exp.into_iter().map(|r| r.read(self)).collect(),
            },
            mult: C::F::ZERO,
        })
    }

    fn hint_bit_decomposition(
        &mut self,
        value: impl Reg<C>,
        output: impl IntoIterator<Item = impl Reg<C>>,
    ) -> Instruction<C::F> {
        Instruction::HintBits(HintBitsInstr {
            output_addrs_mults: output.into_iter().map(|r| (r.write(self), C::F::ZERO)).collect(),
            input_addr: value.read_ghost(self),
        })
    }

    fn add_curve(
        &mut self,
        output: SepticCurve<Felt<C::F>>,
        input1: SepticCurve<Felt<C::F>>,
        input2: SepticCurve<Felt<C::F>>,
    ) -> Instruction<C::F> {
        Instruction::HintAddCurve(HintAddCurveInstr {
            output_x_addrs_mults: output
                .x
                .0
                .into_iter()
                .map(|r| (r.write(self), C::F::ZERO))
                .collect(),
            output_y_addrs_mults: output
                .y
                .0
                .into_iter()
                .map(|r| (r.write(self), C::F::ZERO))
                .collect(),
            input1_x_addrs: input1.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input1_y_addrs: input1.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_x_addrs: input2.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_y_addrs: input2.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
        })
    }

    fn commit_public_values(
        &mut self,
        public_values: &RecursionPublicValues<Felt<C::F>>,
    ) -> Instruction<C::F> {
        public_values.digest.iter().for_each(|x| {
            let _ = x.read(self);
        });
        let pv_addrs =
            unsafe {
                transmute::<
                    RecursionPublicValues<Felt<C::F>>,
                    [Felt<C::F>; RECURSIVE_PROOF_NUM_PV_ELTS],
                >(*public_values)
            }
            .map(|pv| pv.read_ghost(self));

        let public_values_a: &RecursionPublicValues<Address<C::F>> = pv_addrs.as_slice().borrow();
        Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
            pv_addrs: *public_values_a,
        }))
    }

    fn print_f(&mut self, addr: impl Reg<C>) -> Instruction<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Base,
            addr: addr.read_ghost(self),
        })
    }

    fn print_e(&mut self, addr: impl Reg<C>) -> Instruction<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Extension,
            addr: addr.read_ghost(self),
        })
    }

    fn ext2felts(&mut self, felts: [impl Reg<C>; D], ext: impl Reg<C>) -> Instruction<C::F> {
        Instruction::HintExt2Felts(HintExt2FeltsInstr {
            output_addrs_mults: felts.map(|r| (r.write(self), C::F::ZERO)),
            input_addr: ext.read_ghost(self),
        })
    }

    fn hint(&mut self, output: &[impl Reg<C>]) -> Instruction<C::F> {
        Instruction::Hint(HintInstr {
            output_addrs_mults: output.iter().map(|r| (r.write(self), C::F::ZERO)).collect(),
        })
    }

    /// Compiles one instruction, passing one or more instructions to `consumer`.
    ///
    /// We do not simply return a `Vec` for performance reasons --- results would be immediately fed
    /// to `flat_map`, so we employ fusion/deforestation to eliminate intermediate data structures.
    #[inline]
    pub fn compile_one<F>(
        &mut self,
        ir_instr: DslIr<C>,
        mut consumer: impl FnMut(Result<Instruction<C::F>, CompileOneErr<C>>),
    ) where
        F: PrimeField + TwoAdicField,
        C: Config<N = F, F = F> + Debug,
    {
        // For readability. Avoids polluting outer scope.
        use BaseAluOpcode::*;
        use ExtAluOpcode::*;

        let mut f = |instr| consumer(Ok(instr));
        match ir_instr {
            DslIr::ImmV(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmF(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmE(dst, src) => f(self.mem_write_const(dst, Imm::EF(src))),

            DslIr::AddV(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddVI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddF(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddFI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddE(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),
            DslIr::AddEF(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::F(rhs))),
            DslIr::AddEFFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),

            DslIr::SubV(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubVI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubVIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubF(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubFI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubFIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubE(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),
            DslIr::SubEI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::EF(rhs))),
            DslIr::SubEIN(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, Imm::EF(lhs), rhs)),
            DslIr::SubEFI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::F(rhs))),
            DslIr::SubEF(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),

            DslIr::MulV(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulVI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulF(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulFI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulE(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),
            DslIr::MulEI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::EF(rhs))),
            DslIr::MulEFI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::F(rhs))),
            DslIr::MulEF(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),

            DslIr::DivF(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, rhs)),
            DslIr::DivFI(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, Imm::F(rhs))),
            DslIr::DivFIN(dst, lhs, rhs) => f(self.base_alu(DivF, dst, Imm::F(lhs), rhs)),
            DslIr::DivE(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),
            DslIr::DivEI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::EF(rhs))),
            DslIr::DivEIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::EF(lhs), rhs)),
            DslIr::DivEFI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::F(rhs))),
            DslIr::DivEFIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::F(lhs), rhs)),
            DslIr::DivEF(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),

            DslIr::NegV(dst, src) => f(self.base_alu(SubF, dst, Imm::F(C::F::ZERO), src)),
            DslIr::NegF(dst, src) => f(self.base_alu(SubF, dst, Imm::F(C::F::ZERO), src)),
            DslIr::NegE(dst, src) => f(self.ext_alu(SubE, dst, Imm::EF(C::EF::ZERO), src)),
            DslIr::InvV(dst, src) => f(self.base_alu(DivF, dst, Imm::F(C::F::ONE), src)),
            DslIr::InvF(dst, src) => f(self.base_alu(DivF, dst, Imm::F(C::F::ONE), src)),
            DslIr::InvE(dst, src) => f(self.ext_alu(DivE, dst, Imm::F(C::F::ONE), src)),

            DslIr::Select(bit, dst1, dst2, lhs, rhs) => f(self.select(bit, dst1, dst2, lhs, rhs)),

            DslIr::AssertEqV(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqF(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqE(lhs, rhs) => self.ext_assert_eq(lhs, rhs, f),
            DslIr::AssertEqVI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqFI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqEI(lhs, rhs) => self.ext_assert_eq(lhs, Imm::EF(rhs), f),

            DslIr::AssertNeV(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeF(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeE(lhs, rhs) => self.ext_assert_ne(lhs, rhs, f),
            DslIr::AssertNeVI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeFI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeEI(lhs, rhs) => self.ext_assert_ne(lhs, Imm::EF(rhs), f),

            DslIr::CircuitV2Poseidon2PermuteKoalaBear(data) => {
                f(self.poseidon2_permute(data.0, data.1))
            }
            DslIr::CircuitV2ExpReverseBits(dst, base, exp) => {
                f(self.exp_reverse_bits(dst, base, exp))
            }
            DslIr::CircuitV2HintBitsF(output, value) => {
                f(self.hint_bit_decomposition(value, output))
            }
            DslIr::CircuitV2CommitPublicValues(public_values) => {
                f(self.commit_public_values(&public_values))
            }
            DslIr::CircuitV2HintAddCurve(output, point1, point2) => {
                f(self.add_curve(output, point1, point2))
            }

            DslIr::PrintV(dst) => f(self.print_f(dst)),
            DslIr::PrintF(dst) => f(self.print_f(dst)),
            DslIr::PrintE(dst) => f(self.print_e(dst)),
            DslIr::CircuitV2HintFelts(output) => f(self.hint(&output)),
            DslIr::CircuitV2HintExts(output) => f(self.hint(&output)),
            DslIr::CircuitExt2Felt(felts, ext) => f(self.ext2felts(felts, ext)),
            DslIr::CycleTrackerV2Enter(name) => {
                consumer(Err(CompileOneErr::CycleTrackerEnter(name)))
            }
            DslIr::CycleTrackerV2Exit => consumer(Err(CompileOneErr::CycleTrackerExit)),
            DslIr::ReduceE(_) => {}
            instr => consumer(Err(CompileOneErr::Unsupported(instr))),
        }
    }

    /// Emit the instructions from a list of operations in the DSL.
    pub fn compile<F>(&mut self, operations: TracedVec<DslIr<C>>) -> RecursionProgram<C::F>
    where
        F: PrimeField + TwoAdicField,
        C: Config<N = F, F = F> + Debug,
    {
        // In debug mode, we perform cycle tracking and keep track of backtraces.
        // Otherwise, we ignore cycle tracking instructions and pass around an empty Vec of traces.
        let debug_mode = zkm_debug_mode();
        // Compile each IR instruction into a SeqBlock structure (#259
        //). Most ops accumulate into the current Basic block;
        // a `DslIr::Parallel` op flushes the current Basic block and
        // pushes a `SeqBlock::Parallel(per_subprogram_RawProgram)`.
        // This step also counts the number of times each address is
        // read from. Backfill below walks the resulting flat
        // iter_mut, which descends into Parallel sub-programs.
        let (mut top_seq_blocks, traces) = tracing::debug_span!("compile_one loop").in_scope(|| {
            let mut traces = vec![];
            let mut span_builder = if debug_mode {
                Some(SpanBuilder::<_, &'static str>::new("cycle_tracker".to_string()))
            } else {
                None
            };
            let blocks = self.compile_block(operations, debug_mode, &mut traces, span_builder.as_mut());
            if let Some(span_builder) = span_builder {
                let cycle_tracker_root_span = span_builder.finish().unwrap();
                for line in cycle_tracker_root_span.lines() {
                    tracing::info!("{}", line);
                }
            }
            (blocks, traces)
        });

        // Replace the mults using the address count data gathered in this previous.
        // Exhaustive match for refactoring purposes.
        let total_memory = self.addr_to_mult.len() + self.consts.len();
        let mut backfill = |(mult, addr): (&mut F, &Address<F>)| {
            *mult = self.addr_to_mult.remove(addr.as_usize()).unwrap()
        };
        tracing::debug_span!("backfill mult").in_scope(|| {
            // Walk all instructions across the SeqBlock structure
            // (descends into Parallel sub-programs via the SeqBlock
            // iterator boilerplate in seq_block.rs).
            for asm_instr in top_seq_blocks.iter_mut().flatten() {
                match asm_instr {
                    Instruction::BaseAlu(BaseAluInstr {
                        mult,
                        addrs: BaseAluIo { out: ref addr, .. },
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::ExtAlu(ExtAluInstr {
                        mult,
                        addrs: ExtAluIo { out: ref addr, .. },
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::Mem(MemInstr {
                        addrs: MemIo { inner: ref addr },
                        mult,
                        kind: MemAccessKind::Write,
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::Poseidon2(instr) => {
                        let Poseidon2SkinnyInstr {
                            addrs: Poseidon2Io { output: ref addrs, .. },
                            mults,
                        } = instr.as_mut();
                        mults.iter_mut().zip(addrs).for_each(&mut backfill);
                    }
                    Instruction::Select(SelectInstr {
                        addrs: SelectIo { out1: ref addr1, out2: ref addr2, .. },
                        mult1,
                        mult2,
                    }) => {
                        backfill((mult1, addr1));
                        backfill((mult2, addr2));
                    }
                    Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                        addrs: ExpReverseBitsIo { result: ref addr, .. },
                        mult,
                    }) => backfill((mult, addr)),
                    Instruction::HintBits(HintBitsInstr { output_addrs_mults, .. })
                    | Instruction::Hint(HintInstr { output_addrs_mults, .. }) => {
                        output_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    Instruction::HintExt2Felts(HintExt2FeltsInstr {
                        output_addrs_mults, ..
                    }) => {
                        output_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    Instruction::HintAddCurve(HintAddCurveInstr {
                        output_x_addrs_mults,
                        output_y_addrs_mults,
                        ..
                    }) => {
                        output_x_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                        output_y_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    // Instructions that do not write to memory.
                    Instruction::Mem(MemInstr { kind: MemAccessKind::Read, .. })
                    | Instruction::CommitPublicValues(_)
                    | Instruction::Print(_) => (),
                }
            }
        });
        debug_assert!(self.addr_to_mult.is_empty());
        // Initialize constants.
        let total_consts = self.consts.len();
        let instrs_consts: Vec<Instruction<C::F>> = self
            .consts
            .drain()
            .sorted_by_key(|x| x.1 .0 .0)
            .map(|(imm, (addr, mult))| {
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: imm.as_block() },
                    mult,
                    kind: MemAccessKind::Write,
                })
            })
            .collect();
        tracing::debug!("number of consts to initialize: {}", instrs_consts.len());
        // Reset the other fields.
        self.next_addr = Default::default();
        self.virtual_to_physical.clear();
        // #259 Phase C: assemble the final SeqBlock structure. Constants
        // are prepended as a Basic block; the user's compiled SeqBlocks
        // (which may contain SeqBlock::Parallel) follow. Traces are
        // prepended with `None`s for the const init prefix.
        let final_traces: Vec<_> = tracing::debug_span!("construct program").in_scope(|| {
            if debug_mode {
                std::iter::repeat_n(None, total_consts).chain(traces).collect()
            } else {
                traces
            }
        });
        let mut final_seq_blocks: Vec<SeqBlock<Instruction<C::F>>> =
            Vec::with_capacity(top_seq_blocks.len() + 1);
        if !instrs_consts.is_empty() {
            final_seq_blocks.push(SeqBlock::Basic(BasicBlock { instrs: instrs_consts }));
        }
        final_seq_blocks.extend(top_seq_blocks);
        let seq_blocks = zkm_recursion_core::runtime::RawProgram { seq_blocks: final_seq_blocks };
        RecursionProgram { seq_blocks, total_memory, traces: final_traces, shape: None }
    }

    /// Compile a TracedVec of DSL ops into a `Vec<SeqBlock<Instruction<F>>>`.
    ///
    /// Most ops accumulate into a "current Basic block" buffer.
    /// `DslIr::Parallel(par_blocks)` flushes the current buffer to a
    /// `SeqBlock::Basic`, then recursively compiles each sub-block
    /// into its own `RawProgram`, and pushes a `SeqBlock::Parallel`.
    /// Cycle-tracker enter/exit ops thread through `span_builder`
    /// as in the legacy compile loop.
    ///
    /// SP1 ref: `/tmp/sp1/crates/recursion/compiler/src/circuit/compiler.rs::compile_raw_program`
    /// (lines 639-697).
    fn compile_block<F>(
        &mut self,
        operations: TracedVec<DslIr<C>>,
        debug_mode: bool,
        traces: &mut Vec<Option<backtrace::Backtrace>>,
        mut span_builder: Option<&mut SpanBuilder<String, &'static str>>,
    ) -> Vec<SeqBlock<Instruction<C::F>>>
    where
        F: PrimeField + TwoAdicField,
        C: Config<N = F, F = F> + Debug,
    {
        let mut seq_blocks: Vec<SeqBlock<Instruction<C::F>>> = Vec::new();
        let mut current_basic: Vec<Instruction<C::F>> = Vec::with_capacity(PREALLOC_INSTRUCTIONS);
        for (ir_instr, trace) in operations {
            // Use an enum to pull the per-instruction outcomes out of
            // the FnMut closure (the closure is Send-bound and we
            // can't borrow span_builder mutably across it).
            enum Outcome<F> {
                Push(F),
                Enter(String),
                Exit,
            }
            let mut outcomes: Vec<Outcome<Instruction<C::F>>> = Vec::new();
            match ir_instr {
                DslIr::Parallel(par_blocks) => {
                    // Flush the in-progress Basic block before opening the
                    // Parallel boundary.
                    if !current_basic.is_empty() {
                        seq_blocks.push(SeqBlock::Basic(BasicBlock {
                            instrs: std::mem::take(&mut current_basic),
                        }));
                    }
                    // Recursively compile each sub-block into its own
                    // RawProgram. The span builder is threaded
                    // through so cycle-tracker enter/exit ops nested
                    // inside a Parallel block continue to register.
                    let sub_progs: Vec<zkm_recursion_core::runtime::RawProgram<Instruction<C::F>>> =
                        par_blocks
                            .into_iter()
                            .map(|b| {
                                let blocks = self.compile_block(
                                    b.ops,
                                    debug_mode,
                                    traces,
                                    span_builder.as_deref_mut(),
                                );
                                zkm_recursion_core::runtime::RawProgram { seq_blocks: blocks }
                            })
                            .collect();
                    seq_blocks.push(SeqBlock::Parallel(sub_progs));
                }
                other => {
                    let trace_clone = trace.clone();
                    self.compile_one(other, |item| match item {
                        Ok(instr) => outcomes.push(Outcome::Push(instr)),
                        Err(CompileOneErr::CycleTrackerEnter(name)) => {
                            outcomes.push(Outcome::Enter(name))
                        }
                        Err(CompileOneErr::CycleTrackerExit) => outcomes.push(Outcome::Exit),
                        Err(CompileOneErr::Unsupported(instr)) => {
                            panic!("unsupported instruction: {instr:?}\nbacktrace: {trace_clone:?}")
                        }
                    });
                    // Drain outcomes outside the closure so we can
                    // mutate span_builder freely.
                    for outcome in outcomes {
                        match outcome {
                            Outcome::Push(instr) => {
                                if debug_mode {
                                    println!("instr: {instr:?}");
                                    if let Some(sb) = span_builder.as_deref_mut() {
                                        sb.item(instr_name(&instr));
                                    }
                                    #[cfg(feature = "debug")]
                                    traces.push(trace.clone());
                                }
                                current_basic.push(instr);
                            }
                            Outcome::Enter(name) => {
                                if let Some(sb) = span_builder.as_deref_mut() {
                                    sb.enter(name);
                                }
                            }
                            Outcome::Exit => {
                                if let Some(sb) = span_builder.as_deref_mut() {
                                    sb.exit().unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }
        // Flush trailing Basic block.
        if !current_basic.is_empty() {
            seq_blocks.push(SeqBlock::Basic(BasicBlock { instrs: current_basic }));
        }
        seq_blocks
    }
}

/// Used for cycle tracking.
const fn instr_name<F>(instr: &Instruction<F>) -> &'static str {
    match instr {
        Instruction::BaseAlu(_) => "BaseAlu",
        Instruction::ExtAlu(_) => "ExtAlu",
        Instruction::Mem(_) => "Mem",
        Instruction::Poseidon2(_) => "Poseidon2",
        Instruction::Select(_) => "Select",
        Instruction::ExpReverseBitsLen(_) => "ExpReverseBitsLen",
        Instruction::HintBits(_) => "HintBits",
        Instruction::Print(_) => "Print",
        Instruction::HintExt2Felts(_) => "HintExt2Felts",
        Instruction::Hint(_) => "Hint",
        Instruction::HintAddCurve(_) => "HintAddCurve",
        Instruction::CommitPublicValues(_) => "CommitPublicValues",
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CompileOneErr<C: Config> {
    Unsupported(DslIr<C>),
    CycleTrackerEnter(String),
    CycleTrackerExit,
}

/// Immediate (i.e. constant) field element.
///
/// Required to distinguish a base and extension field element at the type level,
/// since the IR's instructions do not provide this information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Imm<F, EF> {
    /// Element of the base field `F`.
    F(F),
    /// Element of the extension field `EF`.
    EF(EF),
}

impl<F, EF> Imm<F, EF>
where
    F: Field + Copy,
    EF: ExtensionField<F>,
{
    // Get a `Block` of memory representing this immediate.
    pub fn as_block(&self) -> Block<F> {
        match self {
            Imm::F(f) => Block::from(*f),
            Imm::EF(ef) => ef.as_basis_coefficients_slice().into(),
        }
    }
}

/// Utility functions for various register types.
trait Reg<C: Config> {
    /// Mark the register as to be read from, returning the "physical" address.
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;

    /// Get the "physical" address of the register, assigning a new address if necessary.
    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;

    /// Mark the register as to be written to, returning the "physical" address.
    fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;
}

macro_rules! impl_reg_borrowed {
    ($a:ty) => {
        impl<C, T> Reg<C> for $a
        where
            C: Config,
            T: Reg<C> + ?Sized,
        {
            fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).read(compiler)
            }

            fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).read_ghost(compiler)
            }

            fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).write(compiler)
            }
        }
    };
}

// Allow for more flexibility in arguments.
impl_reg_borrowed!(&T);
impl_reg_borrowed!(&mut T);
impl_reg_borrowed!(Box<T>);

macro_rules! impl_reg_vaddr {
    ($a:ty) => {
        impl<C: Config<F: PrimeField64>> Reg<C> for $a {
            fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_vaddr(self.idx as usize)
            }
            fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_ghost_vaddr(self.idx as usize)
            }
            fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.write_fp(self.idx as usize)
            }
        }
    };
}

// These three types wrap a `u32` but they don't share a trait.
impl_reg_vaddr!(Var<C::F>);
impl_reg_vaddr!(Felt<C::F>);
impl_reg_vaddr!(Ext<C::F, C::EF>);

impl<C: Config<F: PrimeField64>> Reg<C> for Imm<C::F, C::EF> {
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_const(*self)
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_ghost_const(*self)
    }

    fn write(&self, _compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl<C: Config<F: PrimeField64>> Reg<C> for Address<C::F> {
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_addr(*self);
        *self
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_ghost_addr(*self);
        *self
    }

    fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.write_addr(*self);
        *self
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::BufRead, iter::zip, sync::Arc};

    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::Poseidon2InternalLayerKoalaBear;
    use p3_symmetric::{CryptographicHasher, Permutation};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    /// Generate random field elements using rand 0.8 compatible approach.
    fn rand_felt_iter(seed: u64) -> impl Iterator<Item = F> {
        let mut rng = StdRng::seed_from_u64(seed);
        std::iter::from_fn(move || Some(F::from_u64(rng.gen::<u64>())))
    }

    /// Generate random [F; 4] arrays using rand 0.8 compatible approach.
    fn rand_felt4_iter(seed: u64) -> impl Iterator<Item = [F; 4]> {
        let mut rng = StdRng::seed_from_u64(seed);
        std::iter::from_fn(move || {
            Some(core::array::from_fn(|_| F::from_u64(rng.gen::<u64>())))
        })
    }

    /// Generate random [F; 16] arrays using rand 0.8 compatible approach.
    fn rand_felt16_iter(seed: u64) -> impl Iterator<Item = [F; 16]> {
        let mut rng = StdRng::seed_from_u64(seed);
        std::iter::from_fn(move || {
            Some(core::array::from_fn(|_| F::from_u64(rng.gen::<u64>())))
        })
    }

    use zkm_core_machine::utils::{run_test_machine, setup_logger};
    use zkm_recursion_core::{machine::RecursionAir, RecursionProgram, Runtime};
    use zkm_stark::{
        inner_perm, koala_bear_poseidon2::KoalaBearPoseidon2, InnerHash, KoalaBearPoseidon2Inner,
        StarkGenericConfig,
    };

    use crate::circuit::{AsmBuilder, AsmConfig, CircuitV2Builder};

    use super::*;

    type SC = KoalaBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    fn test_operations(operations: TracedVec<DslIr<AsmConfig<F, EF>>>) {
        test_operations_with_runner(operations, |program| {
            let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
                program,
                KoalaBearPoseidon2Inner::new().perm,
            );
            runtime.run().unwrap();
            runtime.record
        });
    }

    fn test_operations_with_runner(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        run: impl FnOnce(Arc<RecursionProgram<F>>) -> ExecutionRecord<F>,
    ) {
        let mut compiler = super::AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = Arc::new(compiler.compile(operations));
        let record = run(program.clone());

        // Run with the poseidon2 wide chip.
        let wide_machine =
            RecursionAir::<_, 3>::machine_wide_with_all_chips(KoalaBearPoseidon2::default());
        let (pk, vk) = wide_machine.setup(&program);
        let result = run_test_machine(vec![record.clone()], wide_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }

        // Run with the poseidon2 skinny chip.
        let skinny_machine = RecursionAir::<_, 9>::machine_skinny_with_all_chips(
            KoalaBearPoseidon2::ultra_compressed(),
        );
        let (pk, vk) = skinny_machine.setup(&program);
        let result = run_test_machine(vec![record.clone()], skinny_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }
    }

    #[test]
    fn test_poseidon2() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = rand_felt16_iter(0xCAFEDA7E);
        for _ in 0..1 {
            let input_1: [F; WIDTH] = rng.next().unwrap();
            let output_1 = inner_perm().permute(input_1);

            let input_1_felts = input_1.map(|x| builder.eval(x));
            let output_1_felts = builder.poseidon2_permute_v2(input_1_felts);
            let expected: [Felt<_>; WIDTH] = output_1.map(|x| builder.eval(x));
            for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }

        test_operations(builder.into_operations());
    }

    #[test]
    fn test_poseidon2_hash() {
        let perm = inner_perm();
        let hasher = InnerHash::new(perm.clone());

        let input: [F; 26] = [
            F::from_u32(0),
            F::from_u32(1),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(2),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
            F::from_u32(3),
        ];
        let expected = hasher.hash_iter(input);
        println!("{expected:?}");

        let mut builder = AsmBuilder::<F, EF>::default();
        let input_felts: [Felt<_>; 26] = input.map(|x| builder.eval(x));
        let result = builder.poseidon2_hash_v2(&input_felts);

        for (actual_f, expected_f) in zip(result, expected) {
            builder.assert_felt_eq(actual_f, expected_f);
        }
    }

    #[test]
    fn test_exp_reverse_bits() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = rand_felt_iter(0xEC0BEEF);
        for _ in 0..100 {
            let power_f = rng.next().unwrap();
            let power = power_f.as_canonical_u32();
            let power_bits = (0..NUM_BITS).map(|i| (power >> i) & 1).collect::<Vec<_>>();

            let input_felt = builder.eval(power_f);
            let power_bits_felt = builder.num2bits_v2_f(input_felt, NUM_BITS);

            let base = rng.next().unwrap();
            let base_felt = builder.eval(base);
            let result_felt = builder.exp_reverse_bits_v2(base_felt, power_bits_felt);

            let expected = power_bits
                .into_iter()
                .rev()
                .zip(std::iter::successors(Some(base), |x| Some(x.square())))
                .map(|(bit, base_pow)| match bit {
                    0 => F::ONE,
                    1 => base_pow,
                    _ => panic!("not a bit: {bit}"),
                })
                .product::<F>();
            let expected_felt: Felt<_> = builder.eval(expected);
            builder.assert_felt_eq(result_felt, expected_felt);
        }
        test_operations(builder.into_operations());
    }

    #[test]
    fn test_hint_bit_decomposition() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = rand_felt_iter(0xC0FFEE7AB1E);
        for _ in 0..100 {
            let input_f = rng.next().unwrap();
            let input = input_f.as_canonical_u32();
            let output = (0..NUM_BITS).map(|i| (input >> i) & 1).collect::<Vec<_>>();

            let input_felt = builder.eval(input_f);
            let output_felts = builder.num2bits_v2_f(input_felt, NUM_BITS);
            let expected: Vec<Felt<_>> =
                output.into_iter().map(|x| builder.eval(F::from_u32(x))).collect();
            for (lhs, rhs) in output_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }
        test_operations(builder.into_operations());
    }

    #[test]
    fn test_print_and_cycle_tracker() {
        const ITERS: usize = 5;

        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();

        let input_fs = rand_felt_iter(0xC0FFEE7AB1E)
            .take(ITERS)
            .collect::<Vec<_>>();

        let input_efs = rand_felt4_iter(0x7EA7AB1E)
            .take(ITERS)
            .collect::<Vec<_>>();

        let mut buf = VecDeque::<u8>::new();

        builder.cycle_tracker_v2_enter("printing felts".to_string());
        for (i, &input_f) in input_fs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing felt {i}"));
            let input_felt = builder.eval(input_f);
            builder.print_f(input_felt);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("printing exts".to_string());
        for (i, input_block) in input_efs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing ext {i}"));
            let input_ext = builder.eval(EF::from_basis_coefficients_slice(input_block).unwrap().cons());
            builder.print_e(input_ext);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        test_operations_with_runner(builder.into_operations(), |program| {
            let mut runtime = Runtime::<F, EF, Poseidon2InternalLayerKoalaBear<16>>::new(
                program,
                KoalaBearPoseidon2Inner::new().perm,
            );
            runtime.debug_stdout = Box::new(&mut buf);
            runtime.run().unwrap();
            runtime.record
        });

        let input_str_fs = input_fs.into_iter().map(|elt| format!("{elt}"));
        let input_str_efs = input_efs.into_iter().map(|elt| format!("{elt:?}"));
        let input_strs = input_str_fs.chain(input_str_efs);

        for (input_str, line) in zip(input_strs, buf.lines()) {
            let line = line.unwrap();
            assert!(line.contains(&input_str));
        }
    }

    #[test]
    fn test_ext2felts() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut ext_iter = rand_felt4_iter(0x3264);
        let mut random_ext = move || EF::from_basis_coefficients_slice(&ext_iter.next().unwrap()).unwrap();
        for _ in 0..100 {
            let input = random_ext();
            let output: &[F] = input.as_basis_coefficients_slice();

            let input_ext = builder.eval(input.cons());
            let output_felts = builder.ext2felt_v2(input_ext);
            let expected: Vec<Felt<_>> = output.iter().map(|&x| builder.eval(x)).collect();
            for (lhs, rhs) in output_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }
        test_operations(builder.into_operations());
    }

    macro_rules! test_assert_fixture {
        ($assert_felt:ident, $assert_ext:ident, $should_offset:literal) => {
            {
                use std::convert::identity;
                let mut builder = AsmBuilder::<F, EF>::default();
                // Test with F (felt)
                {
                    let mut elts = rand_felt_iter(0xDEADBEEF);
                    for _ in 0..100 {
                        let a: F = elts.next().unwrap();
                        let b: F = elts.next().unwrap();
                        let c = a + b;
                        let ar: Felt<_> = builder.eval(identity(a));
                        let br: Felt<_> = builder.eval(identity(b));
                        let cr: Felt<_> = builder.eval(ar + br);
                        let cm = if $should_offset {
                            c + elts.find(|x| !x.is_zero()).unwrap()
                        } else {
                            c
                        };
                        builder.$assert_felt(cr, identity(cm));
                    }
                }
                // Test with EF (ext)
                {
                    let mut ext_iter = rand_felt4_iter(0xABADCAFE);
                    let mut elts = std::iter::from_fn(move || {
                        Some(EF::from_basis_coefficients_slice(&ext_iter.next().unwrap()).unwrap())
                    });
                    for _ in 0..100 {
                        let a: EF = elts.next().unwrap();
                        let b: EF = elts.next().unwrap();
                        let c = a + b;
                        let ar: Ext<_, _> = builder.eval(EF::cons(a));
                        let br: Ext<_, _> = builder.eval(EF::cons(b));
                        let cr: Ext<_, _> = builder.eval(ar + br);
                        let cm = if $should_offset {
                            c + elts.find(|x| !x.is_zero()).unwrap()
                        } else {
                            c
                        };
                        builder.$assert_ext(cr, EF::cons(cm));
                    }
                }
                test_operations(builder.into_operations());
            }
        };
    }

    #[test]
    fn test_assert_eq_noop() {
        test_assert_fixture!(assert_felt_eq, assert_ext_eq, false);
    }

    #[test]
    #[should_panic]
    fn test_assert_eq_panics() {
        test_assert_fixture!(assert_felt_eq, assert_ext_eq, true);
    }

    #[test]
    fn test_assert_ne_noop() {
        test_assert_fixture!(assert_felt_ne, assert_ext_ne, true);
    }

    #[test]
    #[should_panic]
    fn test_assert_ne_panics() {
        test_assert_fixture!(assert_felt_ne, assert_ext_ne, false);
    }
}
