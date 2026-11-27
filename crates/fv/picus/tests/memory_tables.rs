//! The determinism pass on the two global memory tables.  The file holds one test: extraction
//! numbers fresh variables with a counter the whole process shares.

use p3_air::BaseAir;
use zkm_core_machine::MipsAir;
use zkm_pcs::{MachineAir, PROOF_MAX_NUM_PVS};
use zkm_picus::{
    lower::VarLayout,
    pcl::{initialize_fresh_var_ctr, set_field_modulus, Felt},
    picus_builder::{
        build_selector_env, extract_module, ColumnOutputMode, ExtractionConfig,
        ShrCarrySummaryMode, SubmoduleMode,
    },
    propagate::{analyze, Analysis},
};

/// A row receives the address element from the global memory message and sends the two address
/// limbs on the control bus.  The limbs are functions of the element only through the range
/// check of the pair, so the pass determines the row with the limb pair summary.
#[test]
fn global_memory_tables_are_determined() {
    let _ = set_field_modulus(0x7f00_0001);
    let chips = MipsAir::<Felt>::chips();
    for name in ["MemoryGlobalInit", "MemoryGlobalFinalize"] {
        let chip = chips.iter().find(|c| c.name() == name).expect("memory table");
        let info = chip.picus_info();
        let layout = VarLayout {
            main_width: chip.air.width(),
            prep_width: chip.preprocessed_width().max(1),
            num_public: PROOF_MAX_NUM_PVS,
        };
        initialize_fresh_var_ctr(layout.fresh_base());
        let env = build_selector_env(&info, None, true);
        let cfg = ExtractionConfig {
            submodule_mode: SubmoduleMode::Inline,
            shr_carry: ShrCarrySummaryMode::AbstractModule,
            column_output_mode: ColumnOutputMode::InteractionsOnly,
            reify_threshold: 128,
        };
        let (module, _) = extract_module(chip, chip.name(), &env, cfg);
        match analyze(&module) {
            Analysis::Determined { lemmas, .. } => {
                assert!(lemmas.contains("canonical_limbs"), "{name}: lemmas {lemmas:?}")
            }
            other => panic!("{name} is not determined: {other:?}"),
        }
    }
}
