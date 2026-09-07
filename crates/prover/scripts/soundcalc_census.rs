//! Census of the three machines for the `soundcalc` soundness calculator
//! (https://github.com/ethereum/soundcalc): per machine, the trace width,
//! the constraint count, the maximum constraint degree, and the lookup
//! interaction count / width — the inputs SP1's `gen_soundcalc_toml`
//! produces for its own machines.  Prints one TOML-ish block per machine;
//! the PCS parameters come from `crates/pcs` and are filled in by hand.
//!
//! Run:
//!   cargo run --release -p zkm-prover --bin soundcalc_census

use p3_air::BaseAir;
use p3_uni_stark::{get_symbolic_constraints, AirLayout};
use zkm_core_machine::mips::MipsAir;
use zkm_pcs::{air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig, Val};
use zkm_prover::{CompressAir, CoreSC, InnerSC, OuterSC, WrapAir};
use zkm_pcs::PROOF_MAX_NUM_PVS;

fn census<SC, A>(name: &str, machine: &zkm_pcs::StarkMachine<SC, A>)
where
    SC: StarkGenericConfig,
    A: MachineAir<Val<SC>> + p3_air::Air<p3_uni_stark::SymbolicAirBuilder<Val<SC>>>,
{
    let mut chips = 0usize;
    let mut main_width = 0usize;
    let mut pre_width = 0usize;
    let mut constraints = 0usize;
    let mut max_degree = 0usize;
    let mut interactions = 0usize;
    let mut max_fields = 0usize;
    let mut widest_chip = String::new();
    for chip in machine.chips() {
        chips += 1;
        // `SOUNDCALC_CENSUS_CHIPS=1`: one line per chip, for area-by-chip
        // arithmetic against the executor's `ZIREN_SHARD_CLOSE_CENSUS` rows.
        if std::env::var_os("SOUNDCALC_CENSUS_CHIPS").is_some() {
            let fields: usize = chip
                .sends()
                .iter()
                .chain(chip.receives().iter())
                .map(|l| l.values.len())
                .sum();
            if let Some(want) = std::env::var_os("SOUNDCALC_CENSUS_LOOKUPS") {
                if want.to_string_lossy() == chip.name() {
                    for (dir, l) in chip
                        .sends()
                        .iter()
                        .map(|l| ("send", l))
                        .chain(chip.receives().iter().map(|l| ("recv", l)))
                    {
                        let vals: Vec<String> = l
                            .values
                            .iter()
                            .map(|v| format!("{v:?}"))
                            .collect();
                        println!(
                            "lookup {name} {} {dir} kind={:?} arity={} mult={:?} vals={}",
                            chip.name(),
                            l.kind,
                            l.values.len(),
                            l.multiplicity,
                            vals.join(" ")
                        );
                    }
                }
            }
            println!(
                "chip {name} {} main_width={} preprocessed_width={} sends={} receives={} lookup_fields={}",
                chip.name(),
                BaseAir::width(&chip.air),
                chip.preprocessed_width(),
                chip.sends().len(),
                chip.receives().len(),
                fields
            );
        }
        main_width += BaseAir::width(&chip.air);
        pre_width += chip.preprocessed_width();
        let n = get_symbolic_constraints(
            &chip.air,
            AirLayout {
                preprocessed_width: chip.preprocessed_width(),
                main_width: BaseAir::width(&chip.air),
                num_public_values: PROOF_MAX_NUM_PVS,
                ..Default::default()
            },
        )
        .len();
        constraints += n;
        // log_quotient_degree = log2(max_constraint_degree - 1)
        let degree = (1usize << chip.log_quotient_degree()) + 1;
        max_degree = max_degree.max(degree);
        for l in chip.sends().iter().chain(chip.receives().iter()) {
            interactions += 1;
            if l.values.len() > max_fields {
                max_fields = l.values.len();
                widest_chip = chip.air.name();
            }
        }
    }
    println!("[{name}]");
    println!("chips = {chips}");
    println!("trace_columns = {main_width}          # sum of main widths");
    println!("preprocessed_columns = {pre_width}");
    println!("num_constraints = {constraints}");
    println!("air_max_degree = {max_degree}");
    println!("num_lookups_M = {interactions}      # sends + receives over all chips");
    println!("num_columns_S = {max_fields}        # widest interaction tuple ({widest_chip})");
    println!();
}

fn main() {
    let core = MipsAir::<Val<CoreSC>>::machine(KoalaBearPoseidon2::default());
    census("core", &core);
    let compress = CompressAir::<Val<InnerSC>>::compress_machine(InnerSC::default());
    census("compress", &compress);
    let wrap = WrapAir::<Val<OuterSC>>::wrap_machine(OuterSC::default());
    census("wrap", &wrap);
}
