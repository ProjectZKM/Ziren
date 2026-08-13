//! Columns and constraints shared by every memory-instruction chip.
//!
//! The memory instructions used to live in a single 79-column, 14-selector
//! union chip (`MemoryInstrs`).  Every row of that chip paid for the columns of
//! every other memory opcode: a `LW` row carried the store-masking flags, the
//! sign-extension gadget and the unaligned-load scratch it never used.
//!
//! The union is now split into per-width chips (see the sibling modules), each
//! of which embeds this shared block plus only the columns its own opcodes
//! need.  The block also carries the *inlined* effective-address addition:
//! `addr = op_b + op_c` is proven here with an [`AddOperation`] (value + 3
//! carries) instead of being delegated to the `AddSub` chip over the ALU bus,
//! which removes one 19-cell `AddSub` dependency row per memory instruction.

use std::mem::size_of;

use hashbrown::HashMap;
use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use rayon::iter::{ParallelBridge, ParallelIterator};
use zkm_derive::{AlignedBorrow, PicusAnnotations};
use zkm_pcs::{air::ZKMAirBuilder, PicusInfo, Word};

use zkm_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent, MemoryAccessPosition},
    ByteOpcode, NUM_REGISTERS,
};
use zkm_primitives::consts::WORD_SIZE;

use crate::air::WordAirBuilder;
use crate::{
    air::ZKMCoreAirBuilder,
    memory::MemoryReadWriteCols,
    operations::{AddOperation, IsZeroOperation, KoalaBearWordRangeChecker},
    utils::zeroed_f_vec,
};

/// The number of columns shared by every memory-instruction chip.
pub const NUM_MEMORY_INSTR_COMMON_COLS: usize = size_of::<MemoryInstrCommonCols<u8>>();

/// The columns every memory instruction needs, regardless of width or direction.
#[derive(AlignedBorrow, PicusAnnotations, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryInstrCommonCols<T> {
    /// Program fetch, register access and `(clk, pc)` chaining; live on every
    /// real row (every memory-instruction row is an instruction).
    pub frame: crate::frame::InstructionFrameCols<T>,

    /// The current/next program counter of the instruction.
    pub pc: T,
    pub next_pc: T,

    /// The shard number.
    pub shard: T,
    /// The clock cycle number.
    pub clk: T,

    /// The value of the first operand.
    pub op_a_value: Word<T>,
    /// The value of the second operand.
    pub op_b_value: Word<T>,
    /// The value of the third operand.
    pub op_c_value: Word<T>,
    /// The previous value of `op_a` — the `hi` slot of the instruction bus.
    pub prev_a_val: Word<T>,

    /// The effective address `op_b + op_c`, computed INLINE.
    ///
    /// `addr_add.value` is the (unaligned) address word; the three carry bits
    /// prove the byte-wise addition.  This replaces the `send_alu(ADD, ..)`
    /// the union chip used to emit, and with it the `AddSub` row it required.
    pub addr_add: AddOperation<T>,

    /// The address's least significant two bits, i.e. `addr_word[0] & 0b11`.
    ///
    /// The aligned address is the expression `addr_word.reduce() -
    /// addr_ls_two_bits`; it is no longer a witnessed column.
    pub addr_ls_two_bits: T,

    /// Gadget to verify that the address word is within the Koala-Bear field.
    pub addr_word_range_checker: KoalaBearWordRangeChecker<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryReadWriteCols<T>,

    /// This is used to check if the most significant three bytes of the memory address are all
    /// zero.
    pub most_sig_bytes_zero: IsZeroOperation<T>,
}

impl<T> MemoryInstrCommonCols<T> {
    /// The (unaligned) effective address word.
    #[inline]
    pub fn addr_word(&self) -> Word<T>
    where
        T: Copy,
    {
        self.addr_add.value
    }
}

/// Constrains everything that is common to all memory instructions:
///
/// 1. `addr_word = op_b_value + op_c_value` (inlined — no `AddSub` row).
/// 2. `addr_word` is a canonical Koala-Bear word whose bytes are range checked.
/// 3. `addr_word >= NUM_REGISTERS`, so memory instructions cannot alias registers.
/// 4. `addr_ls_two_bits = addr_word[0] & 0b11`.
/// 5. The memory access at the aligned address.
///
/// Returns the aligned-address expression (`addr_word.reduce() - addr_ls_two_bits`).
pub fn eval_memory_common<AB: ZKMCoreAirBuilder>(
    builder: &mut AB,
    cols: &MemoryInstrCommonCols<AB::Var>,
    is_real: AB::Expr,
) -> AB::Expr {
    // Verify `addr_word = op_b_value + op_c_value` in-place.  `AddOperation::eval`
    // range checks all four bytes of both operands and of the result, which
    // subsumes the explicit `slice_range_check_u8(addr_word[1..3])` the union
    // chip performed.
    AddOperation::<AB::F>::eval(
        builder,
        cols.op_b_value,
        cols.op_c_value,
        cols.addr_add,
        is_real.clone(),
    );
    let addr_word = cols.addr_add.value;

    // Range check the addr_word to be a valid koalabear word.
    KoalaBearWordRangeChecker::<AB::F>::range_check(
        builder,
        addr_word,
        cols.addr_word_range_checker,
        is_real.clone(),
    );

    // We check that `addr_word >= NUM_REGISTERS`, or `addr_word > NUM_REGISTERS - 1` to avoid
    // registers.  Check that if the most significant bytes are zero, then the least significant
    // byte is at least NUM_REGISTERS.
    builder.send_byte(
        ByteOpcode::LTU.as_field::<AB::F>(),
        AB::Expr::ONE,
        AB::Expr::from_u8(NUM_REGISTERS as u8 - 1),
        addr_word[0],
        cols.most_sig_bytes_zero.result,
    );

    // SAFETY: Check that the above interaction is only sent if the row is real.
    builder.when(cols.most_sig_bytes_zero.result).assert_one(is_real.clone());

    // Check the most_sig_byte_zero flag.  The three most significant bytes are byte range
    // checked by `AddOperation::eval`, so the only way their sum is zero is if all are zero.
    IsZeroOperation::<AB::F>::eval(
        builder,
        addr_word[1] + addr_word[2] + addr_word[3],
        cols.most_sig_bytes_zero,
        is_real.clone(),
    );

    // Check the correct value of addr_ls_two_bits.
    builder.send_byte(
        ByteOpcode::AND.as_field::<AB::F>(),
        cols.addr_ls_two_bits,
        addr_word[0],
        AB::Expr::from_u8(0b11),
        is_real.clone(),
    );

    // The aligned address is now an expression rather than a witnessed column: the
    // union chip witnessed `addr_aligned` and asserted `addr_aligned +
    // addr_ls_two_bits == addr_word.reduce()`, which is exactly this definition.
    let addr_aligned = addr_word.reduce::<AB>() - cols.addr_ls_two_bits;

    builder.eval_memory_access(
        cols.shard,
        cols.clk + AB::F::from_u32(MemoryAccessPosition::Memory as u32),
        addr_aligned.clone(),
        &cols.memory_access,
        is_real,
    );

    addr_aligned
}

/// The shared instruction plumbing for the memory chips (the Instruction-bus
/// receive is gone: every row is a real instruction serving itself via the
/// frame).
///
/// Every memory chip supplies the same constants: `next_next_pc = next_pc + 4`,
/// `num_extra_cycles = 0`, `is_rw_a = 1`, `is_check_memory = 1`, `is_halt = 0`,
/// `is_sequential = 1`.
pub fn receive_memory_instruction<AB: ZKMCoreAirBuilder>(
    builder: &mut AB,
    cols: &MemoryInstrCommonCols<AB::Var>,
    opcode: AB::Expr,
    op_a_immutable: AB::Expr,
    is_real: AB::Expr,
) {
    let _ = opcode;

    // A real instruction carries its own program fetch, register access and
    // `(clk, pc)` chaining.  Memory instructions are sequential, never halt.
    crate::frame::eval_instruction_frame(
        builder,
        &cols.frame,
        cols.pc.into(),
        cols.next_pc.into(),
        cols.next_pc + AB::Expr::from_u32(4),
        is_real.clone(),
    );
    builder
        .when(is_real.clone())
        .assert_eq(cols.frame.state_recv_next_pc, cols.next_pc);
    // Every memory instruction reads-and-writes op_a; the plain stores read it
    // immutably (the per-chip `op_a_immutable` expr, NOT including SC).
    builder.assert_eq(cols.frame.is_rw_a, is_real.clone());
    builder.assert_eq(cols.frame.op_a_immutable, op_a_immutable * is_real.clone());
    builder
        .when(is_real.clone())
        .assert_word_eq(cols.frame.hi_or_prev_a, cols.prev_a_val);
    // Bind this chip's operand columns to the frame's register-file view:
    // the chip must compute on exactly the values the register accesses
    // commit (the Instruction bus that used to carry them is gone).
    builder.when(is_real.clone()).assert_word_eq(cols.op_a_value, cols.frame.op_a_value);
    builder.when(is_real.clone()).assert_word_eq(cols.op_b_value, cols.frame.op_b_val());
    builder.when(is_real.clone()).assert_word_eq(cols.op_c_value, cols.frame.op_c_val());
    // The chips keep private shard/clk columns for the Memory-position access:
    // tie them to the frame (the Mul coupling).
    builder.when(is_real.clone()).assert_eq(cols.shard, cols.frame.shard);
    builder.when(is_real).assert_eq(
        cols.clk,
        AB::Expr::from_u32(1u32 << 16) * cols.frame.clk_8bit_limb + cols.frame.clk_16bit_limb,
    );
}

/// Constrains that the address is word aligned, for the opcodes that require it.
///
/// The `LW`/`LL`/`SW`/`SC` chips do not witness the three offset flags at all;
/// they simply pin `addr_ls_two_bits` to zero.
pub fn assert_word_aligned<AB: ZKMCoreAirBuilder>(
    builder: &mut AB,
    cols: &MemoryInstrCommonCols<AB::Var>,
    is_real: AB::Expr,
) {
    builder.when(is_real).assert_zero(cols.addr_ls_two_bits);
}

impl<F: PrimeField32> MemoryInstrCommonCols<F> {
    /// Populates the shared columns from a memory-instruction event.
    ///
    /// Returns the two least significant bits of the effective address, which the
    /// per-chip populate functions use to derive their offset flags and values.
    pub fn populate(
        &mut self,
        event: &MemInstrEvent,
        blu: &mut impl ByteRecord,
        program: &zkm_core_executor::Program,
    ) -> u8 {
        // Every memory-instruction row is a real instruction owning its frame.
        self.frame.populate_from_mem(event, program, blu);

        self.shard = F::from_u32(event.shard);
        debug_assert!(self.shard != F::ZERO);
        self.clk = F::from_u32(event.clk);
        self.pc = F::from_u32(event.pc);
        self.next_pc = F::from_u32(event.next_pc);
        self.op_a_value = event.a.into();
        self.op_b_value = event.b.into();
        self.op_c_value = event.c.into();
        self.prev_a_val = event.prev_a_val.into();

        // Populate memory accesses for reading from memory.
        self.memory_access.populate(event.mem_access, blu);

        // Inline effective-address addition (this also emits the u8 range checks for
        // op_b, op_c and the resulting address word).
        let memory_addr = self.addr_add.populate(blu, event.b, event.c);
        debug_assert_eq!(memory_addr, event.b.wrapping_add(event.c));
        self.addr_word_range_checker.populate(memory_addr);

        let addr_ls_two_bits = (memory_addr % WORD_SIZE as u32) as u8;
        self.addr_ls_two_bits = F::from_u8(addr_ls_two_bits);

        // Add byte lookup event to verify correct calculation of addr_ls_two_bits.
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: addr_ls_two_bits as u16,
            a2: 0,
            b: memory_addr.to_le_bytes()[0],
            c: 0b11,
        });

        let addr_word: Word<F> = memory_addr.into();
        self.most_sig_bytes_zero
            .populate_from_field_element(addr_word[1] + addr_word[2] + addr_word[3]);

        if self.most_sig_bytes_zero.result == F::ONE {
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1,
                a2: 0,
                b: NUM_REGISTERS as u8 - 1,
                c: memory_addr.to_le_bytes()[0],
            });
        }

        addr_ls_two_bits
    }
}

/// Shared trace-generation driver for the memory chips.
///
/// Identical in structure to the driver the union chip used: one parallel pass
/// over the (already opcode-partitioned) event slice, each worker accumulating
/// its own byte-lookup map.
pub(crate) fn generate_memory_trace<F: PrimeField32>(
    events: &[MemInstrEvent],
    padded_nb_rows: usize,
    num_cols: usize,
    event_to_row: impl Fn(&MemInstrEvent, &mut [F], &mut HashMap<ByteLookupEvent, usize>)
        + Sync
        + Send,
    pad_row: impl Fn(&mut [F]) + Sync + Send,
) -> (RowMajorMatrix<F>, Vec<HashMap<ByteLookupEvent, usize>>) {
    let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
    let mut values = zeroed_f_vec(padded_nb_rows * num_cols);

    let blu_events = values
        .chunks_mut(chunk_size * num_cols)
        .enumerate()
        .par_bridge()
        .map(|(i, rows)| {
            let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
            rows.chunks_mut(num_cols).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    event_to_row(&events[idx], row, &mut blu);
                } else {
                    // Padding rows carry no instruction: neutralise the frame
                    // or its register-access multiplicities break the Memory
                    // bus.
                    pad_row(row);
                }
            });
            blu
        })
        .collect::<Vec<_>>();

    (RowMajorMatrix::new(values, num_cols), blu_events)
}

/// Constrains the three sub-word offset flags against `addr_ls_two_bits`.
///
/// Returns the `offset_is_zero` expression (`1 - one - two - three`).  Only the
/// chips whose opcodes can address a sub-word offset witness these flags; the
/// word-aligned chips use [`assert_word_aligned`] instead.
pub fn eval_offset_flags<AB: ZKMCoreAirBuilder>(
    builder: &mut AB,
    addr_ls_two_bits: AB::Var,
    ls_bits_is_one: AB::Var,
    ls_bits_is_two: AB::Var,
    ls_bits_is_three: AB::Var,
) -> AB::Expr {
    let offset_is_zero = AB::Expr::ONE - ls_bits_is_one - ls_bits_is_two - ls_bits_is_three;

    builder.assert_bool(ls_bits_is_one);
    builder.assert_bool(ls_bits_is_two);
    builder.assert_bool(ls_bits_is_three);
    builder.assert_bool(offset_is_zero.clone());

    // SAFETY: due to these constraints at most one of the four flags can be non-zero;
    // as their sum is 1, exactly one flag is on with value 1.
    builder.when(offset_is_zero.clone()).assert_zero(addr_ls_two_bits);
    builder.when(ls_bits_is_one).assert_one(addr_ls_two_bits);
    builder.when(ls_bits_is_two).assert_eq(addr_ls_two_bits, AB::Expr::TWO);
    builder.when(ls_bits_is_three).assert_eq(addr_ls_two_bits, AB::Expr::from_u8(3));

    offset_is_zero
}

/// Populates the three offset flags from the low two address bits.
#[inline]
pub fn populate_offset_flags<F: PrimeField32>(
    addr_ls_two_bits: u8,
    ls_bits_is_one: &mut F,
    ls_bits_is_two: &mut F,
    ls_bits_is_three: &mut F,
) {
    *ls_bits_is_one = F::from_bool(addr_ls_two_bits == 1);
    *ls_bits_is_two = F::from_bool(addr_ls_two_bits == 2);
    *ls_bits_is_three = F::from_bool(addr_ls_two_bits == 3);
}
