use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

use clap::{Parser, ValueEnum, ValueHint};
use p3_air::{Air, BaseAir};
use zkm_core_machine::MipsAir;
use zkm_pcs::{Chip, MachineAir, PicusInfo, PROOF_MAX_NUM_PVS};
use zkm_picus::{
    lean,
    lower::VarLayout,
    pcl::{
        initialize_fresh_var_ctr, set_field_modulus, set_picus_names, Felt, PicusConstraint,
        PicusExpr, PicusModule, PicusProgram,
    },
    picus_builder::{
        build_padding_env, build_selector_env, extract_module, ColumnOutputMode, ExtractionConfig,
        PicusBuilder, ShrCarrySummaryMode, SubmoduleMode, MULTIPLICITIES,
    },
    propagate::{analyze, prove_bit, prove_zero, Verdict, ZeroVerdict},
};

/// What the triage proves about a lookup multiplicity.
#[derive(Clone, Debug)]
enum Obligation {
    /// The multiplicity is zero (padding rows).
    Zero(PicusExpr),
    /// The multiplicity is a bit (real rows).
    Bit(PicusExpr),
}

/// The obligations behind a module's postconditions, by module name, as `(origin, obligation)`.
static OBLIGATIONS: std::sync::Mutex<BTreeMap<String, Vec<(String, Obligation)>>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Chips whose rows are a table: their multiplicity is the number of rows that look the entry
/// up, a count the prover fills in, so the bit obligation does not apply to them.
const TABLES: &[&str] = &["Byte", "Program", "Range"];

/// Adds `bit(m)` for every lookup multiplicity `m` of a real-row module that is not a constant
/// after specialization (a constant other than 0 or 1 is kept as an unprovable postcondition, so
/// the triage reports it).
fn add_bit_postconditions(m: &mut PicusModule, chip: &str) {
    if TABLES.contains(&chip) {
        println!("  mult-bits: skipped ({chip} is a table; its multiplicities are counts)");
        return;
    }
    let mults = MULTIPLICITIES.lock().unwrap().get(&m.name).cloned().unwrap_or_default();
    let mut obligations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (origin, mult) in mults {
        if matches!(mult, PicusExpr::Const(0) | PicusExpr::Const(1)) {
            continue;
        }
        if seen.insert(mult.to_string()) {
            m.postconditions.push(PicusConstraint::new_bit(mult.clone()));
        }
        obligations.push((origin, Obligation::Bit(mult)));
    }
    OBLIGATIONS.lock().unwrap().insert(m.name.clone(), obligations);
}

/// The inert-padding module: with `is_real` and every selector at zero, every lookup
/// multiplicity must be zero, so a padding row takes part in no bus and no table.  This is the
/// side condition under which a lookup may be read as a fact about the row that sends it.
fn build_padding_module<A>(
    chip: &Chip<Felt, A>,
    picus_info: &PicusInfo,
    cfg: ExtractionConfig,
) -> Option<(PicusModule, BTreeMap<String, PicusModule>)>
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder>,
{
    let env = build_padding_env(picus_info);
    if env.is_empty() {
        println!("  padding: skipped ({} has neither is_real nor selectors)", chip.name());
        return None;
    }
    let cfg = ExtractionConfig { submodule_mode: SubmoduleMode::Ignore, ..cfg };
    let (mut pad, aux) = extract_module(chip, "padding".to_string(), &env, cfg);
    pad.inputs.clear();
    pad.outputs.clear();
    pad.assume_deterministic.clear();
    let mults = MULTIPLICITIES.lock().unwrap().get("padding").cloned().unwrap_or_default();
    let mut obligations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (origin, mult) in mults {
        if matches!(mult, PicusExpr::Const(0)) {
            continue;
        }
        if seen.insert(mult.to_string()) {
            pad.postconditions
                .push(PicusConstraint::new_equality(mult.clone(), PicusExpr::Const(0)));
        }
        obligations.push((origin, Obligation::Zero(mult)));
    }
    if pad.postconditions.is_empty() {
        println!("  padding: every multiplicity is the constant 0");
        return None;
    }
    OBLIGATIONS.lock().unwrap().insert("padding".to_string(), obligations);
    Some((pad, aux))
}

/// Renders an expression with column names in place of `x_N`.
fn named(e: &PicusExpr) -> String {
    let text = e.to_string();
    let mut out = String::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("x_") {
        out.push_str(&rest[..i]);
        let digits: String = rest[i + 2..].chars().take_while(|c| c.is_ascii_digit()).collect();
        match digits.parse::<usize>() {
            Ok(v) if !digits.is_empty() => {
                out.push_str(&zkm_picus::propagate::var_name(v));
                rest = &rest[i + 2 + digits.len()..];
            }
            _ => {
                out.push_str("x_");
                rest = &rest[i + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Runs the zero obligations of `module` and prints `TAG <label> proved N/M` plus one
/// `TAG-UNPROVED` line per obligation the engine could not close.
fn report_obligations(tag: &str, label: &str, module: &PicusModule) {
    let obligations = OBLIGATIONS.lock().unwrap().get(&module.name).cloned().unwrap_or_default();
    let mut proved = 0;
    let mut unproved = Vec::new();
    let mut assumed = Vec::new();
    let mut cache: BTreeMap<String, ZeroVerdict> = BTreeMap::new();
    for (origin, o) in &obligations {
        let (key, e) = match o {
            Obligation::Zero(e) => (format!("zero {e}"), e),
            Obligation::Bit(e) => (format!("bit {e}"), e),
        };
        let verdict = cache
            .entry(key)
            .or_insert_with(|| match o {
                Obligation::Zero(e) => prove_zero(module, e),
                Obligation::Bit(e) => prove_bit(module, e),
            })
            .clone();
        let shown = named(e);
        match verdict {
            ZeroVerdict::Proved => proved += 1,
            ZeroVerdict::Nonzero(c) => unproved.push(format!("{origin} {shown} = {c}")),
            ZeroVerdict::Unproved(why) => unproved.push(format!("{origin} {shown}: {why}")),
            ZeroVerdict::OnInputs(vs) => {
                zkm_picus::lean::ASSUMED_BITS
                    .lock()
                    .unwrap()
                    .entry(module.name.clone())
                    .or_default()
                    .extend(vs.iter().copied());
                let vs: Vec<String> =
                    vs.iter().map(|v| zkm_picus::propagate::var_name(*v)).collect();
                assumed.push(format!("{origin} {shown} if bus inputs {} are bits", vs.join(", ")));
            }
        }
    }
    println!("{tag} {label} proved {proved}/{} assumed {}", obligations.len(), assumed.len());
    for a in assumed {
        println!("{tag}-ASSUMED {label} {a}");
    }
    for u in unproved {
        println!("{tag}-UNPROVED {label} {u}");
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Chip name to extract (as returned by `MachineAir::name`).  Repeatable.
    #[arg(long)]
    pub chip: Vec<String>,

    /// Extract every chip of the machine.
    #[arg(long, default_value_t = false)]
    pub all: bool,

    /// List the chip names and exit.
    #[arg(long, default_value_t = false)]
    pub list: bool,

    /// Directory for `<Chip>.picus` files.  Can be overridden with PICUS_OUT_DIR.
    #[arg(long = "picus-out-dir", value_name = "DIR", value_hint = ValueHint::DirPath, env = "PICUS_OUT_DIR", default_value = "picus_out")]
    pub picus_out_dir: PathBuf,

    /// Root of the Lean project (`ZirenDet.lean` + `ZirenDet/Chips/<Chip>.lean` are written
    /// under it).  Can be overridden with LEAN_OUT_DIR.
    #[arg(long = "lean-out-dir", value_name = "DIR", value_hint = ValueHint::DirPath, env = "LEAN_OUT_DIR", default_value = "crates/fv/lean4")]
    pub lean_out_dir: PathBuf,

    /// Which back ends to write.
    #[arg(long, value_enum, default_value_t = Format::Both)]
    pub format: Format,

    /// Add `assume-deterministic` for the selector outputs of the top module.
    #[arg(long = "assume-selectors-deterministic", default_value_t = false)]
    pub assume_selectors_deterministic: bool,

    /// How to summarize `ByteOpcode::ShrCarry`.
    #[arg(long = "shrcarry-summary", value_enum, default_value_t = ShrCarrySummaryModeArg::Abstract)]
    pub shrcarry_summary: ShrCarrySummaryModeArg,

    /// Which columns become module outputs.
    #[arg(long = "column-output-mode", value_enum, default_value_t = ColumnOutputModeArg::InteractionsOnly)]
    pub column_output_mode: ColumnOutputModeArg,

    /// Expression size above which a sub-tree is bound to a fresh variable (0 disables).
    #[arg(long = "reify-threshold", default_value_t = 128)]
    pub reify_threshold: usize,

    /// Do not specialize `is_real = 1` (extract padding rows too).
    #[arg(long = "keep-padding", default_value_t = false)]
    pub keep_padding: bool,

    /// Run the determinism propagation triage on every extracted module and write nothing.
    #[arg(long, default_value_t = false)]
    pub analyze: bool,

    /// Run the triage before writing Lean and replay each determined module's derivation as
    /// its determinism proof.
    #[arg(long, default_value_t = false)]
    pub derive: bool,

    /// With `--derive`: admit open steps with `sorry` (report every one) instead of falling
    /// back to `picus_det`.
    #[arg(long = "derive-diagnose", default_value_t = false)]
    pub derive_diagnose: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Format {
    Picus,
    Lean,
    Both,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ShrCarrySummaryModeArg {
    Abstract,
    Precise,
}

impl From<ShrCarrySummaryModeArg> for ShrCarrySummaryMode {
    fn from(value: ShrCarrySummaryModeArg) -> Self {
        match value {
            ShrCarrySummaryModeArg::Abstract => ShrCarrySummaryMode::AbstractModule,
            ShrCarrySummaryModeArg::Precise => ShrCarrySummaryMode::Precise,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ColumnOutputModeArg {
    InteractionsOnly,
    AllNonInputsAreOutputs,
}

impl From<ColumnOutputModeArg> for ColumnOutputMode {
    fn from(value: ColumnOutputModeArg) -> Self {
        match value {
            ColumnOutputModeArg::InteractionsOnly => ColumnOutputMode::InteractionsOnly,
            ColumnOutputModeArg::AllNonInputsAreOutputs => ColumnOutputMode::AllNonInputsAreOutputs,
        }
    }
}

/// Selector-shape module: the chip's polynomial constraints alone (no lookups) must make the
/// selector columns boolean and mutually exclusive — or a partition of the real rows when the
/// chip declares `selectors_partition_real_rows`.
fn build_top_module<A>(
    chip: &Chip<Felt, A>,
    picus_info: &PicusInfo,
    cfg: ExtractionConfig,
    assume_selectors_deterministic: bool,
) -> Option<(PicusModule, BTreeMap<String, PicusModule>)>
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder>,
{
    if picus_info.selector_indices.is_empty() {
        return None;
    }
    let partition = chip.selectors_partition_real_rows();
    let real_row_only = partition && picus_info.is_real_index.is_some();
    let env = build_selector_env(picus_info, None, real_row_only);
    let cfg = ExtractionConfig { submodule_mode: SubmoduleMode::Ignore, ..cfg };
    let (mut top, aux) = extract_module(chip, "top".to_string(), &env, cfg);
    top.inputs.clear();
    top.outputs.clear();
    top.assume_deterministic.clear();

    let mut one_hot_sum = PicusExpr::Const(0);
    for (selector_col, _) in &picus_info.selector_indices {
        let selector = PicusExpr::Var(*selector_col);
        one_hot_sum += selector.clone();
        top.outputs.push(selector.clone());
        top.postconditions.push(PicusConstraint::new_bit(selector.clone()));
        if assume_selectors_deterministic {
            top.assume_deterministic.push(selector);
        }
    }
    if partition {
        if real_row_only {
            top.postconditions.push(PicusConstraint::new_equality(one_hot_sum, 1.into()));
        } else if let Some(is_real) = picus_info.is_real_index {
            let is_real = PicusExpr::Var(is_real);
            top.outputs.push(is_real.clone());
            top.postconditions.push(PicusConstraint::new_bit(is_real.clone()));
            top.postconditions.push(PicusConstraint::new_equality(one_hot_sum, is_real));
        } else {
            top.postconditions.push(PicusConstraint::new_lt(one_hot_sum, 2.into()));
        }
    } else {
        top.postconditions.push(PicusConstraint::new_lt(one_hot_sum, 2.into()));
    }
    Some((top, aux))
}

/// Extracts one chip into a program: one module per (allowed) selector, or a single module when
/// the chip has no selectors, plus the `top` selector-shape module.
fn extract_chip<A>(chip: &Chip<Felt, A>, args: &Args) -> (PicusProgram, HashMap<usize, String>)
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder>,
{
    let picus_info = chip.picus_info();
    let layout = VarLayout {
        main_width: chip.air.width(),
        prep_width: chip.preprocessed_width().max(1),
        num_public: PROOF_MAX_NUM_PVS,
    };
    let mut names = picus_info.col_to_name.clone();
    names.extend(layout.extra_names());
    set_picus_names(names.clone());
    initialize_fresh_var_ctr(layout.fresh_base());

    let koala_prime = 0x7f00_0001;
    let _ = set_field_modulus(koala_prime);
    let mut program = PicusProgram::new(koala_prime);

    let cfg = ExtractionConfig {
        submodule_mode: SubmoduleMode::Inline,
        shr_carry: args.shrcarry_summary.into(),
        column_output_mode: args.column_output_mode.into(),
        reify_threshold: args.reify_threshold,
    };
    let specialize_is_real = !args.keep_padding;

    let mut modules = BTreeMap::new();
    let mut aux_modules = BTreeMap::new();
    let allowed: Vec<&(usize, String)> = picus_info
        .selector_indices
        .iter()
        .filter(|(_, name)| chip.picus_selector_specialization_allowed(name))
        .collect();
    if allowed.is_empty() {
        let env = build_selector_env(&picus_info, None, specialize_is_real);
        println!("  module {} (env {})", chip.name(), format_env(&env, &names));
        let (mut m, mut aux) = extract_module(chip, chip.name(), &env, cfg);
        add_bit_postconditions(&mut m, &chip.name());
        aux_modules.append(&mut aux);
        modules.insert(m.name.clone(), m);
    } else {
        for (col, sel_name) in allowed {
            let env = build_selector_env(&picus_info, Some(*col), specialize_is_real);
            let name = format!("{}__{}", chip.name(), sel_name);
            println!("  module {name} (env {})", format_env(&env, &names));
            let (mut m, mut aux) = extract_module(chip, name, &env, cfg);
            add_bit_postconditions(&mut m, &chip.name());
            aux_modules.append(&mut aux);
            modules.insert(m.name.clone(), m);
        }
    }
    program.add_modules(&mut aux_modules);
    program.add_modules(&mut modules);
    if let Some((top, mut aux)) =
        build_top_module(chip, &picus_info, cfg, args.assume_selectors_deterministic)
    {
        println!("  module top (selector shape)");
        program.add_modules(&mut aux);
        program.add_module("top", top);
    }
    if let Some((pad, mut aux)) = build_padding_module(chip, &picus_info, cfg) {
        println!("  module padding (inert padding rows)");
        program.add_modules(&mut aux);
        program.add_module("padding", pad);
    }
    (program, names)
}

fn format_env(env: &BTreeMap<usize, u64>, names: &HashMap<usize, String>) -> String {
    if env.is_empty() {
        return "{}".to_string();
    }
    let entries = env
        .iter()
        .map(|(k, v)| format!("{} = {v}", names.get(k).cloned().unwrap_or_else(|| format!("x{k}"))))
        .collect::<Vec<_>>();
    format!("{{ {} }}", entries.join(", "))
}

fn main() {
    zkm_core_machine::utils::setup_cli_logger();
    let args = Args::parse();
    let chips = MipsAir::<Felt>::chips();

    if args.list {
        for c in &chips {
            let info = c.picus_info();
            println!(
                "{:28} width={:5} selectors={:2} annotated={}",
                c.name(),
                c.air.width(),
                info.selector_indices.len(),
                !info.col_to_name.is_empty()
            );
        }
        return;
    }

    let selected: Vec<&Chip<Felt, MipsAir<Felt>>> = if args.all {
        chips.iter().collect()
    } else {
        if args.chip.is_empty() {
            panic!("pass --chip <NAME> (repeatable), --all, or --list");
        }
        args.chip
            .iter()
            .map(|name| {
                chips
                    .iter()
                    .find(|c| c.name() == *name)
                    .unwrap_or_else(|| panic!("No chip found named {name}; try --list"))
            })
            .collect()
    };

    zkm_picus::lean::REPLAY_DIAGNOSE
        .store(args.derive_diagnose, std::sync::atomic::Ordering::Relaxed);
    let mut failures = Vec::new();
    for chip in selected {
        println!("Extracting {} .....", chip.name());
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| extract_chip(chip, &args)));
        let (program, names) = match result {
            Ok(x) => x,
            Err(_) => {
                failures.push(chip.name());
                continue;
            }
        };
        zkm_picus::propagate::set_names(names.clone());
        if args.analyze || args.derive {
            if let Some(pad) = program.modules().get("padding") {
                report_obligations("PADDING", &chip.name(), pad);
            }
            for (name, m) in program.modules() {
                if name == "top" || !name.starts_with(&chip.name()) {
                    continue;
                }
                if !m.postconditions.is_empty() {
                    report_obligations("MULTBITS", name, m);
                }
                let verdict = analyze(m);
                let line = match &verdict {
                    Verdict::Determined { branches, rules, lemmas, .. } if lemmas.is_empty() => {
                        format!("DETERMINED branches={branches} rules={rules:?}")
                    }
                    Verdict::Determined { branches, rules, lemmas, .. } => {
                        format!("DETERMINED branches={branches} rules={rules:?} lemmas={lemmas:?}")
                    }
                    Verdict::Stuck { branches, stuck_outputs, opaque } => {
                        let shown: Vec<String> = stuck_outputs
                            .iter()
                            .take(12)
                            .map(|v| names.get(v).cloned().unwrap_or_else(|| format!("expr{v}")))
                            .collect();
                        format!(
                            "STUCK branches={branches} opaque={opaque} stuck={} [{}]",
                            stuck_outputs.len(),
                            shown.join(", ")
                        )
                    }
                    Verdict::TooManyBranches => "TOO_MANY_BRANCHES".to_string(),
                    Verdict::Timeout => "TIMEOUT".to_string(),
                };
                println!("ANALYZE {name} {line}");
                if let Verdict::Determined { derivation, .. } = verdict {
                    zkm_picus::lean::DERIVATIONS.lock().unwrap().insert(name.clone(), derivation);
                }
            }
            if !args.derive {
                continue;
            }
        }
        if matches!(args.format, Format::Picus | Format::Both) {
            let path = args.picus_out_dir.join(format!("{}.picus", chip.name()));
            program.write_to_path(&path).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
            println!("  wrote {}", path.display());
        }
        if matches!(args.format, Format::Lean | Format::Both) {
            let path = lean::write_chip(&program, &chip.name(), &args.lean_out_dir, &names)
                .unwrap_or_else(|e| panic!("write lean for {}: {e}", chip.name()));
            println!("  wrote {}", path.display());
        }
    }
    if matches!(args.format, Format::Lean | Format::Both) {
        lean::write_project_files(&args.lean_out_dir).expect("write lean project files");
    }
    if !failures.is_empty() {
        tracing::warn!("extraction FAILED for {} chip(s): {}", failures.len(), failures.join(", "));
        std::process::exit(1);
    }
    println!("Done.");
}
