//! Census of the three machines for the `soundcalc` soundness calculator
//! (https://github.com/ethereum/soundcalc): per machine, the trace width, the
//! constraint count, the maximum constraint degree, and the lookup interaction
//! count and width, followed by the schedule every one of them is opened
//! under.
//!
//! The point of emitting both from one run is that the published model cannot
//! then disagree with the code: the machine figures come from the same
//! `StarkMachine` the prover builds, and the schedule figures from the same
//! accessors it reads, so a parameter that moves shows up here rather than
//! staying true only of the day the model was written by hand.
//!
//! Run:
//!   cargo run --release -p zkm-prover --bin soundcalc_census

use p3_air::BaseAir;
use p3_uni_stark::{get_symbolic_constraints, AirLayout};
use zkm_core_machine::mips::MipsAir;
use zkm_pcs::PROOF_MAX_NUM_PVS;
use zkm_pcs::{air::MachineAir, koala_bear_poseidon2::KoalaBearPoseidon2, StarkGenericConfig, Val};
use zkm_prover::{CompressAir, CoreSC, InnerSC, OuterSC, WrapAir};

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
            let fields: usize =
                chip.sends().iter().chain(chip.receives().iter()).map(|l| l.values.len()).sum();
            if let Some(want) = std::env::var_os("SOUNDCALC_CENSUS_LOOKUPS") {
                if want.to_string_lossy() == chip.name() {
                    for (dir, l) in chip
                        .sends()
                        .iter()
                        .map(|l| ("send", l))
                        .chain(chip.receives().iter().map(|l| ("recv", l)))
                    {
                        let vals: Vec<String> = l.values.iter().map(|v| format!("{v:?}")).collect();
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
    println!(
        "num_lookups_M = {interactions}      # sends + receives over EVERY chip of the machine, \
not the largest cluster a shard can hold: an over-approximation, so the lookup term it \
produces is conservative"
    );
    println!(
        "num_columns_S = {}        # widest fingerprinted tuple: {max_fields} values plus the \
kind column ({widest_chip})",
        max_fields + 1
    );
    println!();
}

/// The inner schedule at one stacking height, as the calculator reads it.
///
/// Core and compress share it: both stack at `DEFAULT_LOG_STACKING_HEIGHT` and
/// open under `core_whir_config`, so one block describes both profiles.
fn whir_schedule(name: &str, log_stacking_height: usize) {
    let config = zkm_pcs::whir::jagged::core_whir_config(log_stacking_height);
    let folds: Vec<String> =
        config.round_parameters.iter().map(|r| r.folding_factor.to_string()).collect();
    let rates: Vec<String> = core::iter::once(config.starting_log_inv_rate)
        .chain(config.round_parameters.iter().map(|r| r.log_inv_rate))
        .map(|r| r.to_string())
        .collect();
    let queries: Vec<String> = config
        .round_parameters
        .iter()
        .map(|r| r.num_queries)
        .chain(core::iter::once(config.final_queries))
        .map(|q| q.to_string())
        .collect();
    let ood: Vec<String> =
        config.round_parameters.iter().map(|r| r.ood_samples.to_string()).collect();
    let query_pow: Vec<String> = config
        .round_parameters
        .iter()
        .map(|r| r.queries_pow_bits)
        .chain(core::iter::once(config.final_pow_bits))
        .map(|b| b.to_string())
        .collect();
    println!("[{name}.schedule]");
    println!("log_stacking_height = {log_stacking_height}");
    println!("log_inv_rate = {}", config.starting_log_inv_rate);
    println!("whir_log_inv_rates = [{}]", rates.join(", "));
    println!("folding_factors = [{}]", folds.join(", "));
    println!("num_queries = [{}]            # last entry is the final round", queries.join(", "));
    println!("num_ood_samples = [{}]", ood.join(", "));
    println!("grinding_bits_queries = [{}]", query_pow.join(", "));
    println!("grinding_batching_phase = {}", config.batch_pow_bits);
    println!("per_component_target_bits = {}", zkm_pcs::whir::jagged::per_component_target_bits());
    println!();
}

fn main() {
    let core = MipsAir::<Val<CoreSC>>::machine(KoalaBearPoseidon2::default());
    census("core", &core);
    let compress = CompressAir::<Val<InnerSC>>::compress_machine(InnerSC::default());
    census("compress", &compress);
    let wrap = WrapAir::<Val<OuterSC>>::wrap_machine(OuterSC::default());
    census("wrap", &wrap);

    whir_schedule("inner", zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize);

    let wrap_fri =
        zkm_pcs::basefold::config::FriConfig::<zkm_pcs::jagged_pcs::JaggedVal>::wrap_fri_config();
    println!("[wrap.schedule]");
    println!("log_blowup = {}", wrap_fri.log_blowup);
    println!("num_queries = {}", wrap_fri.num_queries);
    println!("grinding_query_phase = {}", wrap_fri.proof_of_work_bits);
    println!("fri_folding_factor = {}", 1 << wrap_fri.log_folding_arity());
    println!("grinding_batching_phase = {}", zkm_pcs::basefold::config::batch_grinding_bits());
    println!();

    println!("[all_rings]");
    println!("grinding_bits_lookup = {}", zkm_pcs::logup_gkr::gkr_grinding_bits());
    println!(
        "transcript_profile_digest = \"{}\"",
        zkm_pcs::profile::transcript_profile_digest_hex()
    );
}
