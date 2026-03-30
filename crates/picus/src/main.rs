use std::{collections::BTreeMap, path::PathBuf};

use clap::{Parser, ValueEnum, ValueHint};
use p3_air::{Air, BaseAir};
use zkm_core_machine::MipsAir;
use zkm_picus::{
    pcl::{
        initialize_fresh_var_ctr, partial_evaluate_expr, set_field_modulus, set_picus_names, Felt,
        PicusAtom, PicusConstraint, PicusExpr, PicusModule, PicusProgram,
    },
    picus_builder::{PicusBuilder, ShrCarrySummaryMode, SubmoduleMode},
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

/// Analyze a single chip and process all its deferred sub-chip tasks.
/// This replaces direct recursion in `MessageBuilder::send()`.
fn analyze_chip<'chips, A>(
    chip: &'chips Chip<Felt, A>,
    chips: &'chips [Chip<Felt, A>],
    picus_builder: Option<&mut PicusBuilder<'chips, A>>,
    specialization_env: Option<BTreeMap<usize, u64>>,
    submodule_mode: SubmoduleMode,
    shr_carry_summary_mode: ShrCarrySummaryMode,
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
            PicusModule::new(chip.name()),
            chips,
            None,
            specialization_env,
            Some(submodule_mode),
            Some(shr_carry_summary_mode),
        )
    };
    chip.air.eval(builder);

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
            PicusModule::new(task.chip_name.clone()),
            builder.chips,
            Some(task.main_vars.clone()),
            Some(env.clone()),
            Some(SubmoduleMode::Inline),
            Some(shr_carry_summary_mode),
        );

        let (mut sub_module, aux_modules) = analyze_chip(
            target_chip,
            builder.chips,
            Some(&mut sub_builder),
            None,
            SubmoduleMode::Inline,
            shr_carry_summary_mode,
        );
        // Merge submodules
        builder.aux_modules.extend(aux_modules.into_iter());

        sub_module.apply_multiplier(task.multiplicity.clone());
        // Partially evaluate with selector one-hot assignments before inlining constraints.
        let updated_picus_module = sub_module.partial_eval(&env);
        builder.picus_module.constraints.extend_from_slice(&updated_picus_module.constraints);
        builder.picus_module.calls.extend_from_slice(&updated_picus_module.calls);
        let propagated_global_outputs = sub_builder
            .global_send_outputs
            .iter()
            .map(|expr| partial_evaluate_expr(expr, &env))
            .collect::<Vec<_>>();
        builder.picus_module.outputs.extend_from_slice(&propagated_global_outputs);
        builder.global_send_outputs.extend(propagated_global_outputs);
        builder.picus_module.postconditions.extend_from_slice(&sub_module.postconditions);
    }
    (builder.picus_module.clone(), builder.aux_modules.clone())
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

fn main() {
    let args = Args::parse();
    let shr_carry_summary_mode: ShrCarrySummaryMode = args.shrcarry_summary.into();

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
    println!("Generating Picus program for {} chip.....", chip.name());
    let mut selector_modules = BTreeMap::new();
    let mut all_aux_modules = BTreeMap::new();

    if picus_info.selector_indices.is_empty() && picus_info.is_real_index.is_none() {
        panic!("PicusBuilder needs at least one selector to be enabled!")
    }

    println!("Applying selector-specialized extraction.....");
    println!("selector indices: {:?}", picus_info.selector_indices);
    if picus_info.selector_indices.is_empty() {
        // No selector columns: still run one extraction pass (is_real specialized if present).
        let env = build_selector_env(&picus_info, None);
        initialize_fresh_var_ctr(fresh_var_ctr_base);
        let (base_module, mut aux_modules) = analyze_chip(
            chip,
            &chips,
            None,
            Some(env.clone()),
            SubmoduleMode::Inline,
            shr_carry_summary_mode,
        );
        all_aux_modules.append(&mut aux_modules);
        let updated_module = base_module.partial_eval(&env);
        selector_modules.insert(updated_module.name.clone(), updated_module);
    } else {
        for (selector_col, _) in &picus_info.selector_indices {
            let env = build_selector_env(&picus_info, Some(*selector_col));
            initialize_fresh_var_ctr(fresh_var_ctr_base);
            let (base_module, mut aux_modules) = analyze_chip(
                chip,
                &chips,
                None,
                Some(env.clone()),
                SubmoduleMode::Inline,
                shr_carry_summary_mode,
            );
            all_aux_modules.append(&mut aux_modules);
            let updated_module = base_module.partial_eval(&env);
            selector_modules.insert(updated_module.name.clone(), updated_module);
        }
    }
    picus_program.add_modules(&mut all_aux_modules);
    picus_program.add_modules(&mut selector_modules);

    // Build the top module only when the chip has selectors to constrain.
    if !picus_info.selector_indices.is_empty() {
        // This keeps top focused on selector determinism while still retaining chip-local constraints.
        let top_env = build_selector_env(&picus_info, None);
        initialize_fresh_var_ctr(fresh_var_ctr_base);
        let (top_base_module, mut top_aux_modules) = analyze_chip(
            chip,
            &chips,
            None,
            Some(top_env.clone()),
            SubmoduleMode::Ignore,
            shr_carry_summary_mode,
        );
        picus_program.add_modules(&mut top_aux_modules);
        let mut top_module = top_base_module.partial_eval(&top_env);
        top_module.name = "top".to_string();
        // Top exists only to prove selector properties, so expose only selectors as outputs.
        top_module.outputs.clear();
        let mut one_hot_sum = PicusExpr::Const(0);
        for (selector_col, _) in &picus_info.selector_indices {
            let selector_var = PicusExpr::Var(*selector_col);
            one_hot_sum += selector_var.clone();
            top_module.outputs.push(selector_var.clone());
            top_module.postconditions.push(PicusConstraint::new_bit(selector_var.clone()));
            if args.assume_selectors_deterministic {
                top_module.assume_deterministic.push(selector_var);
            }
        }
        top_module.postconditions.push(PicusConstraint::new_lt(one_hot_sum, 2.into()));
        picus_program.add_module("top", top_module);
    }
    let res =
        picus_program.write_to_path(args.picus_out_dir.join(format!("{}.picus", chip.name())));
    if res.is_err() {
        panic!("Failed to write picus file: {res:?}");
    }
    println!("Successfully extracted Picus program");
}
