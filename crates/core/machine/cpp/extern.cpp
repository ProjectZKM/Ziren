#include "kb31_t.hpp"
#include "sys.hpp"

namespace zkm_core_machine_sys {
extern void add_sub_event_to_row_koalabear(
    const AluEvent* event,
    AddSubCols<KoalaBearP3>* cols
) {
    AddSubCols<kb31_t>* cols_kb31 = reinterpret_cast<AddSubCols<kb31_t>*>(cols);
    add_sub::event_to_row<kb31_t>(*event, *cols_kb31);
}
} // namespace zkm_core_machine_sys
