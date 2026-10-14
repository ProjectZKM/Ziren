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

/// One WHIR schedule at one stacking height, as the calculator reads it.
///
/// Only the rounds that commit an oracle query one: round 0 opens the stripe
/// trees, round `r` the oracle round `r - 1` committed, and the last round
/// folds and commits nothing, so its `num_queries` is never read.  The final
/// queries open the last committed oracle.  The lists below therefore hold
/// one entry per committed round, and the final phase its own keys.
/// `query_phase_bits` is `q · bits_per_query(rate) + pow` for each phase under
/// the profile's accounting, the figure the per-component target is solved
/// against.
fn whir_schedule(
    name: &str,
    config: &zkm_pcs::whir::config::WhirConfig,
    log_stacking_height: usize,
    accounting: &str,
    bits_per_query: impl Fn(usize) -> f64,
) {
    let rounds = &config.round_parameters;
    let committed = &rounds[..rounds.len() - 1];
    let join = |v: Vec<String>| v.join(", ");
    // The rate of the oracle each committed round queries, then the one the
    // final queries open.
    let queried_rates: Vec<usize> = core::iter::once(config.starting_log_inv_rate)
        .chain(committed.iter().map(|r| r.log_inv_rate))
        .collect();
    let final_rate = *queried_rates.last().unwrap();
    let phase_bits: Vec<String> = committed
        .iter()
        .zip(&queried_rates)
        .map(|(r, &rate)| (r.num_queries, rate, r.queries_pow_bits))
        .chain(core::iter::once((config.final_queries, final_rate, config.final_pow_bits)))
        .map(|(q, rate, pow)| format!("{:.2}", q as f64 * bits_per_query(rate) + pow as f64))
        .collect();
    println!("[{name}.schedule]");
    println!("log_stacking_height = {log_stacking_height}");
    println!("query_accounting = \"{accounting}\"");
    println!("log_inv_rate = {}", config.starting_log_inv_rate);
    println!(
        "committed_log_inv_rates = [{}]   # the stripe trees, then each committed round",
        join(queried_rates.iter().map(|r| r.to_string()).collect())
    );
    println!(
        "folding_factors = [{}]",
        join(rounds.iter().map(|r| r.folding_factor.to_string()).collect())
    );
    println!(
        "grinding_bits_folding = [{}]   # per round, on every folding challenge",
        join(
            rounds
                .iter()
                .map(|r| r.pow_bits.iter().copied().max().unwrap_or(0).to_string())
                .collect()
        )
    );
    println!(
        "num_queries = [{}]   # per committed round",
        join(committed.iter().map(|r| r.num_queries.to_string()).collect())
    );
    println!(
        "num_ood_samples = [{}]   # per committed round",
        join(committed.iter().map(|r| r.ood_samples.to_string()).collect())
    );
    println!(
        "grinding_bits_queries = [{}]   # per committed round",
        join(committed.iter().map(|r| r.queries_pow_bits.to_string()).collect())
    );
    println!("final_queries = {}   # open the last committed oracle", config.final_queries);
    println!("final_log_inv_rate = {final_rate}");
    println!("final_grinding_bits = {}", config.final_pow_bits);
    println!("grinding_batching_phase = {}", config.batch_pow_bits);
    println!("query_phase_bits = [{}]   # per committed round, then final", join(phase_bits));
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

    // Core shards open under the core profile, the root compose (the
    // published compressed proof) under the compress profile; every other
    // recursion node shares the core one.
    let lsh = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    whir_schedule(
        "core",
        &zkm_pcs::whir::jagged::core_whir_config(lsh),
        lsh,
        "unique_decoding",
        zkm_pcs::whir::jagged::bits_per_query,
    );
    let m = zkm_pcs::whir::jagged::compress_johnson_m();
    whir_schedule(
        "compress",
        &zkm_pcs::whir::jagged::compress_whir_config(lsh),
        lsh,
        &if m == 0 { "unique_decoding".to_string() } else { format!("johnson_m{m}") },
        |rate| {
            if m == 0 {
                zkm_pcs::whir::jagged::bits_per_query(rate)
            } else {
                zkm_pcs::whir::jagged::bits_per_query_johnson(rate, m)
            }
        },
    );

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

    // Soundness bounds use what the verifier admits, including its fixed row
    // cube, rather than an honest shard's area fence or a program's row count.
    let log_rows =
        zkm_pcs::shard_level::verifier::JaggedShardVerifier::production_default().max_log_row_count;
    let width = |name: &str| {
        core.chips().iter().find(|chip| chip.name() == name).unwrap().preprocessed_width()
    };
    let prep_cells = (1usize << log_rows) * width("Program")
        + (1usize << 16) * width("Byte")
        + zkm_core_machine::range::NUM_RANGE_ROWS * width("Range");
    let stripe = 1usize << lsh;
    let prep_stripes = zkm_pcs::jagged::committed_dense_len(prep_cells, lsh) / stripe;
    let main_cells = (1usize << zkm_pcs::jagged::MAX_ROUND_LOG_AREA) - 1;
    let main_stripes = zkm_pcs::jagged::committed_dense_len(main_cells, lsh) / stripe;
    let pins = zkm_pcs::jagged::RecursionPins::class(zkm_pcs::jagged::RecursionPins::LAST_CLASS);
    println!("\n[verifier_bounds]");
    println!("max_log_row_count = {log_rows}   # every stage's fixed zerocheck and LogUp cube");
    println!("core_dense_batch = {}   # preprocessed + main stripes", prep_stripes + main_stripes);
    println!("compress_dense_batch = {}", (pins.prep.area + pins.main.area) / stripe);
}
