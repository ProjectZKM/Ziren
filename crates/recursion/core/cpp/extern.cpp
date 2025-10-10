#include "kb31_t.hpp"
#include "sys.hpp"

namespace zkm_recursion_core_sys {
using namespace poseidon2;

extern void alu_base_event_to_row_koalabear(const BaseAluIo<KoalaBearP3>* io,
                                           BaseAluValueCols<KoalaBearP3>* cols) {
  alu_base::event_to_row<kb31_t>(
      *reinterpret_cast<const BaseAluIo<kb31_t>*>(io),
      *reinterpret_cast<BaseAluValueCols<kb31_t>*>(cols));
}
extern void alu_base_instr_to_row_koalabear(
    const BaseAluInstr<KoalaBearP3>* instr,
    BaseAluAccessCols<KoalaBearP3>* access) {
  alu_base::instr_to_row<kb31_t>(
      *reinterpret_cast<const BaseAluInstr<kb31_t>*>(instr),
      *reinterpret_cast<BaseAluAccessCols<kb31_t>*>(access));
}

extern void alu_ext_event_to_row_koalabear(const ExtAluIo<Block<KoalaBearP3>>* io,
                                          ExtAluValueCols<KoalaBearP3>* cols) {
  alu_ext::event_to_row<kb31_t>(
      *reinterpret_cast<const ExtAluIo<Block<kb31_t>>*>(io),
      *reinterpret_cast<ExtAluValueCols<kb31_t>*>(cols));
}
extern void alu_ext_instr_to_row_koalabear(
    const ExtAluInstr<KoalaBearP3>* instr,
    ExtAluAccessCols<KoalaBearP3>* access) {
  alu_ext::instr_to_row<kb31_t>(
      *reinterpret_cast<const ExtAluInstr<kb31_t>*>(instr),
      *reinterpret_cast<ExtAluAccessCols<kb31_t>*>(access));
}

extern void batch_fri_event_to_row_koalabear(const BatchFRIEvent<KoalaBearP3>* io,
                                            BatchFRICols<KoalaBearP3>* cols) {
  batch_fri::event_to_row<kb31_t>(
      *reinterpret_cast<const BatchFRIEvent<kb31_t>*>(io),
      *reinterpret_cast<BatchFRICols<kb31_t>*>(cols));
}
extern void batch_fri_instr_to_row_koalabear(
    const BatchFRIInstrFFI<KoalaBearP3>* instr,
    BatchFRIPreprocessedCols<KoalaBearP3>* cols, size_t index) {
  batch_fri::instr_to_row<kb31_t>(
      *reinterpret_cast<const BatchFRIInstrFFI<kb31_t>*>(instr),
      *reinterpret_cast<BatchFRIPreprocessedCols<kb31_t>*>(cols), index);
}

extern void exp_reverse_bits_event_to_row_koalabear(
    const ExpReverseBitsEventFFI<KoalaBearP3>* io, size_t i,
    ExpReverseBitsLenCols<KoalaBearP3>* cols) {
  exp_reverse_bits::event_to_row<kb31_t>(
      *reinterpret_cast<const ExpReverseBitsEventFFI<kb31_t>*>(io), i,
      *reinterpret_cast<ExpReverseBitsLenCols<kb31_t>*>(cols));
}
extern void exp_reverse_bits_instr_to_row_koalabear(
    const ExpReverseBitsInstrFFI<KoalaBearP3>* instr, size_t i, size_t len,
    ExpReverseBitsLenPreprocessedCols<KoalaBearP3>* cols) {
  exp_reverse_bits::instr_to_row<kb31_t>(
      *reinterpret_cast<const ExpReverseBitsInstrFFI<kb31_t>*>(instr), i, len,
      *reinterpret_cast<ExpReverseBitsLenPreprocessedCols<kb31_t>*>(cols));
}

extern void fri_fold_event_to_row_koalabear(const FriFoldEvent<KoalaBearP3>* io,
                                           FriFoldCols<KoalaBearP3>* cols) {
  fri_fold::event_to_row<kb31_t>(
      *reinterpret_cast<const FriFoldEvent<kb31_t>*>(io),
      *reinterpret_cast<FriFoldCols<kb31_t>*>(cols));
}
extern void fri_fold_instr_to_row_koalabear(
    const FriFoldInstrFFI<KoalaBearP3>* instr, size_t i,
    FriFoldPreprocessedCols<KoalaBearP3>* cols) {
  fri_fold::instr_to_row<kb31_t>(
      *reinterpret_cast<const FriFoldInstrFFI<kb31_t>*>(instr), i,
      *reinterpret_cast<FriFoldPreprocessedCols<kb31_t>*>(cols));
}

extern void public_values_event_to_row_koalabear(
    const CommitPublicValuesEvent<KoalaBearP3>* io, size_t digest_idx,
    PublicValuesCols<KoalaBearP3>* cols) {
  public_values::event_to_row<kb31_t>(
      *reinterpret_cast<const CommitPublicValuesEvent<kb31_t>*>(io), digest_idx,
      *reinterpret_cast<PublicValuesCols<kb31_t>*>(cols));
}
extern void public_values_instr_to_row_koalabear(
    const CommitPublicValuesInstr<KoalaBearP3>* instr, size_t digest_idx,
    PublicValuesPreprocessedCols<KoalaBearP3>* cols) {
  public_values::instr_to_row<kb31_t>(
      *reinterpret_cast<const CommitPublicValuesInstr<kb31_t>*>(instr),
      digest_idx,
      *reinterpret_cast<PublicValuesPreprocessedCols<kb31_t>*>(cols));
}

extern void select_event_to_row_koalabear(const SelectEvent<KoalaBearP3>* io,
                                         SelectCols<KoalaBearP3>* cols) {
  select::event_to_row<kb31_t>(
      *reinterpret_cast<const SelectEvent<kb31_t>*>(io),
      *reinterpret_cast<SelectCols<kb31_t>*>(cols));
}
extern void select_instr_to_row_koalabear(
    const SelectInstr<KoalaBearP3>* instr,
    SelectPreprocessedCols<KoalaBearP3>* cols) {
  select::instr_to_row<kb31_t>(
      *reinterpret_cast<const SelectInstr<kb31_t>*>(instr),
      *reinterpret_cast<SelectPreprocessedCols<kb31_t>*>(cols));
}

extern void poseidon2_skinny_event_to_row_koalabear(
    const Poseidon2Event<KoalaBearP3>* event,
    Poseidon2<KoalaBearP3> cols[OUTPUT_ROUND_IDX + 1]) {
  poseidon2_skinny::event_to_row<kb31_t>(
      *reinterpret_cast<const Poseidon2Event<kb31_t>*>(event),
      reinterpret_cast<Poseidon2<kb31_t>*>(cols));
}
extern void poseidon2_skinny_instr_to_row_koalabear(
    const Poseidon2Instr<KoalaBearP3>* instr, size_t i,
    Poseidon2PreprocessedColsSkinny<KoalaBearP3>* cols) {
  poseidon2_skinny::instr_to_row<kb31_t>(
      *reinterpret_cast<const Poseidon2Instr<kb31_t>*>(instr), i,
      *reinterpret_cast<Poseidon2PreprocessedColsSkinny<kb31_t>*>(cols));
}

extern "C" void poseidon2_wide_event_to_row_koalabear(const KoalaBearP3* input,
                                                     KoalaBearP3* input_row,
                                                     bool sbox_state) {
  poseidon2_wide::event_to_row<kb31_t>(reinterpret_cast<const kb31_t*>(input),
                                       reinterpret_cast<kb31_t*>(input_row), 0,
                                       1, sbox_state);
}
extern void poseidon2_wide_instr_to_row_koalabear(
    const Poseidon2SkinnyInstr<KoalaBearP3>* instr,
    Poseidon2PreprocessedColsWide<KoalaBearP3>* cols) {
  poseidon2_wide::instr_to_row<kb31_t>(
      *reinterpret_cast<const Poseidon2SkinnyInstr<kb31_t>*>(instr),
      *reinterpret_cast<Poseidon2PreprocessedColsWide<kb31_t>*>(cols));
}

}  // namespace zkm_recursion_core_sys
