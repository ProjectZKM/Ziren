use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use clap::{Parser, ValueEnum, ValueHint};
use p3_air::{Air, BaseAir};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use zkm_core_machine::MipsAir;
use zkm_picus::{
    pcl::{
        initialize_fresh_var_ctr, partial_evaluate_expr, set_field_modulus, set_picus_names, Felt,
        PicusAtom, PicusConstraint, PicusExpr, PicusModule, PicusProgram,
    },
    picus_builder::{
        ColumnOutputMode, ExtractionPhase, PicusBuilder, ShrCarrySummaryMode, SubmoduleMode,
    },
};
use zkm_stark::{Chip, MachineAir, PicusInfo};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Chip name to compile")]
    pub chip: Option<String>,

    /// Directory to write the extracted Picus program(s).
    ///
    /// Can be overridden with PICUS_OUT_DIR.
    #[arg(
        long = "picus-out-dir",
        value_name = "DIR",
        value_hint = ValueHint::DirPath,
        env = "PICUS_OUT_DIR",
        default_value = "picus_out"
    )]
    pub picus_out_dir: PathBuf,

    /// Assume selectors are mutually exclusive and force non-selected selectors to 0 during
    /// selector-based partial evaluation.
    #[arg(long = "assume-selectors-deterministic", default_value_t = false)]
    pub assume_selectors_deterministic: bool,

    /// How to summarize ByteOpcode::ShrCarry during extraction.
    #[arg(long = "shrcarry-summary", value_enum, default_value_t = ShrCarrySummaryModeArg::Abstract)]
    pub shrcarry_summary: ShrCarrySummaryModeArg,

    /// How aggressively to expose chip columns as Picus module outputs.
    #[arg(
        long = "column-output-mode",
        value_enum,
        default_value_t = ColumnOutputModeArg::InteractionsOnly
    )]
    pub column_output_mode: ColumnOutputModeArg,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ShrCarrySummaryModeArg {
    Abstract,
    Precise,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum ColumnOutputModeArg {
    InteractionsOnly,
    AllNonInputsAreOutputs,
}

impl From<ShrCarrySummaryModeArg> for ShrCarrySummaryMode {
    fn from(value: ShrCarrySummaryModeArg) -> Self {
        match value {
            ShrCarrySummaryModeArg::Abstract => ShrCarrySummaryMode::AbstractModule,
            ShrCarrySummaryModeArg::Precise => ShrCarrySummaryMode::Precise,
        }
    }
}

impl From<ColumnOutputModeArg> for ColumnOutputMode {
    fn from(value: ColumnOutputModeArg) -> Self {
        match value {
            ColumnOutputModeArg::InteractionsOnly => ColumnOutputMode::InteractionsOnly,
            ColumnOutputModeArg::AllNonInputsAreOutputs => ColumnOutputMode::AllNonInputsAreOutputs,
        }
    }
}

/// Extracts one selector-specialized module for one chip/phase pair.
///
/// The workflow is:
/// 1. Build a `PicusBuilder` for the requested phase and specialization env.
/// 2. Run the chip AIR once on the primary window.
/// 3. Optionally rerun the AIR on a shifted window so the exposed successor row
///    is itself locally feasible.
/// 4. Recursively inline any deferred sub-chip tasks produced by interactions.
/// 5. Expose inputs/outputs according to `PicusInfo` and the chosen output mode.
///
/// This replaces direct recursion in `MessageBuilder::send()` so extraction can
/// keep one explicit worklist of deferred sub-chip analyses.
fn analyze_chip<'chips, A>(
    chip: &'chips Chip<Felt, A>,
    chips: &'chips [Chip<Felt, A>],
    picus_builder: Option<&mut PicusBuilder<'chips, A>>,
    specialization_env: Option<BTreeMap<usize, u64>>,
    phase: ExtractionPhase,
    submodule_mode: SubmoduleMode,
    shr_carry_summary_mode: ShrCarrySummaryMode,
    column_output_mode: ColumnOutputMode,
) -> (PicusModule, BTreeMap<String, PicusModule>)
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder<'chips, A>>,
{
    let env_for_log = if let Some(builder) = picus_builder.as_ref() {
        format_env(&builder.specialization_env)
    } else if let Some(env) = specialization_env.as_ref() {
        format_env(env)
    } else {
        "{}".to_string()
    };
    println!("Analyzing chip {} under environment {}", chip.name(), env_for_log);

    let builder = if let Some(builder) = picus_builder {
        builder
    } else {
        &mut PicusBuilder::new(
            chip,
            PicusModule::new(format!("{}__{}", chip.name(), phase.module_suffix())),
            chips,
            None,
            specialization_env,
            Some(submodule_mode),
            Some(shr_carry_summary_mode),
            Some(phase),
            None,
        )
    };
    chip.air.eval(builder);
    run_shifted_air_eval(chip, builder);

    // Process deferred tasks recursively
    while let Some(task) = builder.concrete_pending_tasks.pop() {
        let target_chip = builder.get_chip(&task.chip_name);
        let target_picus_info = target_chip.picus_info();

        let selector_col = task.get_actual_var_num_for_col(
            target_picus_info.name_to_colrange.get(&task.selector).unwrap().0,
        );
        let mut env = BTreeMap::new();
        // Set `is_real = 1` if it is set in `picus_info`
        if let Some(id) = target_picus_info.is_real_index {
            let real_id_idx = task.get_actual_var_num_for_col(id);
            env.insert(real_id_idx, 1);
        }
        env.insert(selector_col, 1);
        for (other_selector_col, _) in &target_picus_info.selector_indices {
            let other_actual_selector_col = task.get_actual_var_num_for_col(*other_selector_col);

            if selector_col == other_actual_selector_col {
                continue;
            }
            env.insert(other_actual_selector_col, 0);
        }

        let mut sub_builder = PicusBuilder::new(
            target_chip,
            PicusModule::new(format!("{}__{}", task.chip_name, builder.phase.module_suffix())),
            builder.chips,
            Some(task.main_vars.clone()),
            Some(env.clone()),
            Some(SubmoduleMode::Inline),
            Some(shr_carry_summary_mode),
            Some(builder.phase),
            Some(task.capture_interface),
        );

        let (mut sub_module, aux_modules) = analyze_chip(
            target_chip,
            builder.chips,
            Some(&mut sub_builder),
            None,
            builder.phase,
            SubmoduleMode::Inline,
            shr_carry_summary_mode,
            column_output_mode,
        );
        // Merge submodules
        builder.aux_modules.extend(aux_modules.into_iter());

        sub_module.apply_multiplier(task.multiplicity.clone());
        // Partially evaluate with selector one-hot assignments before inlining constraints.
        let updated_picus_module = sub_module.partial_eval(&env);
        builder.picus_module.constraints.extend_from_slice(&updated_picus_module.constraints);
        builder.picus_module.calls.extend_from_slice(&updated_picus_module.calls);
        if task.capture_interface {
            let propagated_global_outputs = sub_builder
                .global_send_outputs
                .iter()
                .map(|expr| partial_evaluate_expr(expr, &env))
                .collect::<Vec<_>>();
            builder.picus_module.outputs.extend_from_slice(&propagated_global_outputs);
            builder.global_send_outputs.extend(propagated_global_outputs);
        }
        builder.picus_module.postconditions.extend_from_slice(&sub_module.postconditions);
    }
    let picus_info = chip.picus_info();
    if builder.capture_interface {
        builder.expose_transition_inputs(&picus_info.transition_input_ranges);
        builder.expose_annotated_primary_outputs(&picus_info.output_ranges);
        builder.expose_transition_outputs(&picus_info.transition_output_ranges);
        if column_output_mode == ColumnOutputMode::AllNonInputsAreOutputs {
            builder.expose_primary_row_non_inputs_as_outputs(&picus_info.input_ranges);
            builder.expose_full_next_row_as_outputs();
        }
    }
    (builder.picus_module.clone(), builder.aux_modules.clone())
}

/// Re-evaluates the AIR on a shifted row window without exposing new interface ports.
///
/// For phases such as `FirstRow` and `Transition`, the first AIR eval only
/// proves that `row1` is a valid successor of `row0`. This shifted pass reuses
/// the same builder with `(row1, row2)` as `(local, next)` so the exported
/// successor row is also checked as a valid local row.
fn run_shifted_air_eval<'chips, A>(
    chip: &'chips Chip<Felt, A>,
    builder: &mut PicusBuilder<'chips, A>,
) where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder<'chips, A>>,
{
    let Some(shifted_phase) = builder.phase.shifted_eval_phase(builder.local_only) else {
        return;
    };

    let width = builder.main.width();
    assert!(
        builder.main.height() >= 3,
        "shifted eval for phase {:?} requires a 3-row main trace",
        builder.phase
    );

    // Reuse the existing builder by temporarily viewing rows `(1, 2)` as the
    // active `(local, next)` pair. This adds the shifted constraints to the
    // same module while keeping row2 existential.
    let shifted_rows = builder
        .main
        .row_slice(1)
        .iter()
        .chain(builder.main.row_slice(2).iter())
        .copied()
        .collect::<Vec<_>>();
    let original_main =
        std::mem::replace(&mut builder.main, RowMajorMatrix::new(shifted_rows, width));
    let original_phase = std::mem::replace(&mut builder.phase, shifted_phase);
    let original_capture_interface = std::mem::replace(&mut builder.capture_interface, false);
    chip.air.eval(builder);
    builder.capture_interface = original_capture_interface;
    builder.phase = original_phase;
    builder.main = original_main;
}

fn collect_expr_vars(expr: &PicusExpr, vars: &mut BTreeSet<usize>) {
    match expr {
        PicusExpr::Const(_) => {}
        PicusExpr::Var(id) => {
            vars.insert(*id);
        }
        PicusExpr::Add(left, right)
        | PicusExpr::Sub(left, right)
        | PicusExpr::Mul(left, right)
        | PicusExpr::Div(left, right) => {
            collect_expr_vars(left, vars);
            collect_expr_vars(right, vars);
        }
        PicusExpr::Neg(expr) | PicusExpr::Pow(_, expr) => collect_expr_vars(expr, vars),
    }
}

fn collect_interface_vars(module: &PicusModule) -> BTreeSet<usize> {
    let mut vars = BTreeSet::new();
    for expr in &module.inputs {
        collect_expr_vars(expr, &mut vars);
    }
    for expr in &module.outputs {
        collect_expr_vars(expr, &mut vars);
    }
    for call in &module.calls {
        for expr in &call.inputs {
            collect_expr_vars(expr, &mut vars);
        }
        for expr in &call.outputs {
            collect_expr_vars(expr, &mut vars);
        }
    }
    vars
}

fn as_var(expr: &PicusExpr) -> Option<usize> {
    match expr {
        PicusExpr::Var(id) => Some(*id),
        _ => None,
    }
}

fn is_var_minus_one(expr: &PicusExpr, var_id: usize) -> bool {
    matches!(
        expr,
        PicusExpr::Sub(left, right)
            if matches!(&**left, PicusExpr::Var(id) if *id == var_id)
                && matches!(&**right, PicusExpr::Const(1))
    )
}

fn match_bit_expr(expr: &PicusExpr) -> Option<usize> {
    match expr {
        PicusExpr::Mul(left, right) => {
            if let Some(var_id) = as_var(left) {
                if is_var_minus_one(right, var_id) {
                    return Some(var_id);
                }
            }
            if let Some(var_id) = as_var(right) {
                if is_var_minus_one(left, var_id) {
                    return Some(var_id);
                }
            }
            None
        }
        _ => None,
    }
}

fn match_guarded_bit_expr(expr: &PicusExpr) -> Option<usize> {
    match expr {
        PicusExpr::Mul(left, right) => match_bit_expr(left).or_else(|| match_bit_expr(right)),
        _ => None,
    }
}

fn match_guarded_var_product(expr: &PicusExpr) -> Option<usize> {
    match expr {
        PicusExpr::Mul(left, right) => as_var(left).or_else(|| as_var(right)),
        _ => None,
    }
}

fn normalize_constraint(
    constraint: PicusConstraint,
    protected_vars: &BTreeSet<usize>,
) -> PicusConstraint {
    match constraint {
        PicusConstraint::Eq(expr) => {
            let expr = *expr;
            if let Some(var_id) = match_guarded_bit_expr(&expr) {
                if !protected_vars.contains(&var_id) {
                    return PicusConstraint::new_bit(PicusExpr::Var(var_id));
                }
            }
            PicusConstraint::Eq(Box::new(expr))
        }
        PicusConstraint::Leq(left, right) => {
            let left = *left;
            let right = *right;
            if matches!(right, PicusExpr::Const(_)) {
                if let Some(var_id) = match_guarded_var_product(&left) {
                    if !protected_vars.contains(&var_id) {
                        return PicusConstraint::new_leq(PicusExpr::Var(var_id), right);
                    }
                }
            }
            PicusConstraint::Leq(Box::new(left), Box::new(right))
        }
        PicusConstraint::Lt(left, right) => {
            let left = *left;
            let right = *right;
            if matches!(right, PicusExpr::Const(_)) {
                if let Some(var_id) = match_guarded_var_product(&left) {
                    if !protected_vars.contains(&var_id) {
                        return PicusConstraint::new_lt(PicusExpr::Var(var_id), right);
                    }
                }
            }
            PicusConstraint::Lt(Box::new(left), Box::new(right))
        }
        other => other,
    }
}

fn postprocess_module(chip_name: &str, module: &mut PicusModule) {
    if chip_name == "BooleanCircuitGarble" {
        let protected_vars = collect_interface_vars(module);
        let mut constraints = Vec::with_capacity(module.constraints.len());
        let mut seen = BTreeSet::new();
        for constraint in std::mem::take(&mut module.constraints) {
            let normalized = normalize_constraint(constraint, &protected_vars);
            let rendered = normalized.to_string();
            if seen.insert(rendered) {
                constraints.push(normalized);
            }
        }
        module.constraints = constraints;
    }
}

fn postprocess_modules(chip_name: &str, modules: &mut BTreeMap<String, PicusModule>) {
    for module in modules.values_mut() {
        postprocess_module(chip_name, module);
    }
}

fn format_env(env: &BTreeMap<usize, u64>) -> String {
    if env.is_empty() {
        return "{}".to_string();
    }
    let entries =
        env.iter().map(|(k, v)| format!("{} -> {v}", PicusAtom::Var(*k))).collect::<Vec<_>>();
    format!("{{ {} }}", entries.join(", "))
}

fn build_selector_env(
    picus_info: &PicusInfo,
    selected_selector_col: Option<usize>,
) -> BTreeMap<usize, u64> {
    let mut env = BTreeMap::new();
    // Specialize to real rows for chips that carry an `is_real` column.
    if let Some(id) = picus_info.is_real_index {
        env.insert(id, 1);
    }
    // One-hot selector assignment for this extraction pass.
    if let Some(selected_col) = selected_selector_col {
        env.insert(selected_col, 1);
        for (other_selector_col, _) in &picus_info.selector_indices {
            if *other_selector_col != selected_col {
                env.insert(*other_selector_col, 0);
            }
        }
    }
    env
}

fn build_top_module(
    picus_info: &PicusInfo,
    assume_selectors_deterministic: bool,
) -> Option<PicusModule> {
    if picus_info.selector_indices.is_empty() {
        return None;
    }

    let mut top_module = PicusModule::new("top".to_string());
    let mut one_hot_sum = PicusExpr::Const(0);
    for (selector_col, _) in &picus_info.selector_indices {
        let selector_var = PicusExpr::Var(*selector_col);
        one_hot_sum += selector_var.clone();
        top_module.outputs.push(selector_var.clone());
        top_module.postconditions.push(PicusConstraint::new_bit(selector_var.clone()));
        if assume_selectors_deterministic {
            top_module.assume_deterministic.push(selector_var);
        }
    }
    top_module.postconditions.push(PicusConstraint::new_lt(one_hot_sum, 2.into()));
    Some(top_module)
}

fn main() {
    let args = Args::parse();
    let shr_carry_summary_mode: ShrCarrySummaryMode = args.shrcarry_summary.into();
    let column_output_mode: ColumnOutputMode = args.column_output_mode.into();

    if args.chip.is_none() {
        panic!("Chip name must be provided!");
    }

    let chip_name = args.chip.unwrap();
    let chips = MipsAir::<Felt>::chips();

    // Get the chip
    let chip = chips
        .iter()
        .find(|c| c.name() == chip_name)
        .unwrap_or_else(|| panic!("No chip found named {}", chip_name.clone()));
    // get the picus info for the chip
    let picus_info = chip.picus_info();
    // set the var -> readable name mapping
    set_picus_names(picus_info.col_to_name.clone());
    // set base col number for creating fresh values
    let fresh_var_ctr_base = chip.width() + 1;
    initialize_fresh_var_ctr(fresh_var_ctr_base);

    // Set the field modulus for the Picus program:
    let koala_prime = 0x7f000001;
    let _ = set_field_modulus(koala_prime);

    // Initialize the Picus program
    let mut picus_program = PicusProgram::new(koala_prime);

    // Build selector-specialized modules directly by running extraction once per
    // selector assignment. This lets opcodes fold to constants before send-dispatch.
    //
    // Conceptually, extraction proceeds one phase at a time:
    // - `SingleRow` handles degenerate one-row traces.
    // - `FirstRow` and `Transition` materialize an extra witness row and use a
    //   shifted AIR pass to prove the exported successor row is locally valid.
    // - `Boundary` stops at the last real row before padding and does not expose
    //   padding-row outputs.
    // - `LastRow` models the final trace row and only imports carried state.
    println!("Generating Picus program for {} chip.....", chip.name());
    let mut selector_modules = BTreeMap::new();
    let mut all_aux_modules = BTreeMap::new();
    let phases = ExtractionPhase::all(chip.local_only());

    if picus_info.selector_indices.is_empty() && picus_info.is_real_index.is_none() {
        panic!("PicusBuilder needs at least one selector to be enabled!")
    }

    println!("Applying selector-specialized extraction.....");
    println!("selector indices: {:?}", picus_info.selector_indices);
    if picus_info.selector_indices.is_empty() {
        // No selector columns: still run one extraction pass (is_real specialized if present).
        for phase in &phases {
            let env = build_selector_env(&picus_info, None);
            initialize_fresh_var_ctr(fresh_var_ctr_base);
            let (base_module, mut aux_modules) = analyze_chip(
                chip,
                &chips,
                None,
                Some(env.clone()),
                *phase,
                SubmoduleMode::Inline,
                shr_carry_summary_mode,
                column_output_mode,
            );
            all_aux_modules.append(&mut aux_modules);
            let updated_module = base_module.partial_eval(&env);
            selector_modules.insert(updated_module.name.clone(), updated_module);
        }
    } else {
        for phase in &phases {
            for (selector_col, _) in &picus_info.selector_indices {
                let env = build_selector_env(&picus_info, Some(*selector_col));
                initialize_fresh_var_ctr(fresh_var_ctr_base);
                let (base_module, mut aux_modules) = analyze_chip(
                    chip,
                    &chips,
                    None,
                    Some(env.clone()),
                    *phase,
                    SubmoduleMode::Inline,
                    shr_carry_summary_mode,
                    column_output_mode,
                );
                all_aux_modules.append(&mut aux_modules);
                let updated_module = base_module.partial_eval(&env);
                selector_modules.insert(updated_module.name.clone(), updated_module);
            }
        }
    }
    postprocess_modules(&chip.name(), &mut all_aux_modules);
    postprocess_modules(&chip.name(), &mut selector_modules);
    picus_program.add_modules(&mut all_aux_modules);
    picus_program.add_modules(&mut selector_modules);

    // The top module is independent of selector-specialized extraction. It only
    // encodes selector-shape assumptions such as one-hotness/determinism.
    if let Some(top_module) = build_top_module(&picus_info, args.assume_selectors_deterministic) {
        picus_program.add_module("top", top_module);
    }
    let res =
        picus_program.write_to_path(args.picus_out_dir.join(format!("{}.picus", chip.name())));
    if res.is_err() {
        panic!("Failed to write picus file: {res:?}");
    }
    println!("Successfully extracted Picus program");
}
