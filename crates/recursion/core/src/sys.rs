use crate::{
    air::Block,
    chips::{
        alu_base::{BaseAluAccessCols, BaseAluValueCols},
        alu_ext::{ExtAluAccessCols, ExtAluValueCols},
        exp_reverse_bits::{ExpReverseBitsLenCols, ExpReverseBitsLenPreprocessedCols},
        poseidon2_skinny::columns::{preprocessed::Poseidon2PreprocessedColsSkinny, Poseidon2},
        poseidon2_wide::columns::preprocessed::Poseidon2PreprocessedColsWide,
        public_values::{PublicValuesCols, PublicValuesPreprocessedCols},
        select::{SelectCols, SelectPreprocessedCols},
    },
    BaseAluInstr, BaseAluIo, CommitPublicValuesEvent,
    CommitPublicValuesInstr, ExpReverseBitsEventFFI, ExpReverseBitsInstrFFI, ExtAluInstr, ExtAluIo,
    Poseidon2Event, Poseidon2Instr, SelectEvent, SelectInstr,
};
use p3_koala_bear::KoalaBear;

#[link(name = "zkm-recursion-core-sys", kind = "static")]
extern "C-unwind" {
    pub fn alu_base_event_to_row_koalabear(
        io: &BaseAluIo<KoalaBear>,
        cols: &mut BaseAluValueCols<KoalaBear>,
    );
    pub fn alu_base_instr_to_row_koalabear(
        instr: &BaseAluInstr<KoalaBear>,
        cols: &mut BaseAluAccessCols<KoalaBear>,
    );

    pub fn alu_ext_event_to_row_koalabear(
        io: &ExtAluIo<Block<KoalaBear>>,
        cols: &mut ExtAluValueCols<KoalaBear>,
    );
    pub fn alu_ext_instr_to_row_koalabear(
        instr: &ExtAluInstr<KoalaBear>,
        cols: &mut ExtAluAccessCols<KoalaBear>,
    );

    pub fn exp_reverse_bits_event_to_row_koalabear(
        io: &ExpReverseBitsEventFFI<KoalaBear>,
        i: usize,
        cols: &mut ExpReverseBitsLenCols<KoalaBear>,
    );
    pub fn exp_reverse_bits_instr_to_row_koalabear(
        instr: &ExpReverseBitsInstrFFI<KoalaBear>,
        i: usize,
        len: usize,
        cols: &mut ExpReverseBitsLenPreprocessedCols<KoalaBear>,
    );

    pub fn public_values_event_to_row_koalabear(
        io: &CommitPublicValuesEvent<KoalaBear>,
        digest_idx: usize,
        cols: &mut PublicValuesCols<KoalaBear>,
    );
    pub fn public_values_instr_to_row_koalabear(
        instr: &CommitPublicValuesInstr<KoalaBear>,
        digest_idx: usize,
        cols: &mut PublicValuesPreprocessedCols<KoalaBear>,
    );

    pub fn select_event_to_row_koalabear(
        io: &SelectEvent<KoalaBear>,
        cols: &mut SelectCols<KoalaBear>,
    );
    pub fn select_instr_to_row_koalabear(
        instr: &SelectInstr<KoalaBear>,
        cols: &mut SelectPreprocessedCols<KoalaBear>,
    );

    pub fn poseidon2_skinny_event_to_row_koalabear(
        io: &Poseidon2Event<KoalaBear>,
        cols: *mut Poseidon2<KoalaBear>,
    );
    pub fn poseidon2_skinny_instr_to_row_koalabear(
        instr: &Poseidon2Instr<KoalaBear>,
        i: usize,
        cols: &mut Poseidon2PreprocessedColsSkinny<KoalaBear>,
    );

    pub fn poseidon2_wide_event_to_row_koalabear(
        input: *const KoalaBear,
        input_row: *mut KoalaBear,
        sbox_state: bool,
    );
    pub fn poseidon2_wide_instr_to_row_koalabear(
        instr: &Poseidon2Instr<KoalaBear>,
        cols: &mut Poseidon2PreprocessedColsWide<KoalaBear>,
    );
}
