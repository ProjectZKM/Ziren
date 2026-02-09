use std::{collections::BTreeMap, path::PathBuf};

use clap::{Parser, ValueHint};
use p3_air::{Air, BaseAir};
use zkm_core_machine::MipsAir;
use zkm_picus::{
    pcl::{
        initialize_fresh_var_ctr, set_field_modulus, set_picus_names, Felt, PicusModule,
        PicusProgram,
    },
    picus_builder::PicusBuilder,
};
use zkm_stark::{Chip, MachineAir};

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

    /// Directory to write the extracted Picus program(s).
    ///
    /// Can be overridden with PICUS_OUT_DIR.
    pub picus_out_dir: PathBuf,
}

/// Analyze a single chip and process all its deferred sub-chip tasks.
/// This replaces direct recursion in `MessageBuilder::send()`.
fn analyze_chip<'chips, A>(
    chip: &'chips Chip<Felt, A>,
    chips: &'chips [Chip<Felt, A>],
    picus_builder: Option<&mut PicusBuilder<'chips, A>>,
) -> (PicusModule, BTreeMap<String, PicusModule>)
where
    A: MachineAir<Felt> + BaseAir<Felt> + Air<PicusBuilder<'chips, A>>,
{
    println!("Analyzing chip: {}", chip.name());

    let builder = if let Some(builder) = picus_builder {
        builder
    } else {
        &mut PicusBuilder::new(chip, PicusModule::new(chip.name()), chips, None, None)
    };
    chip.air.eval(builder);

    // Process deferred tasks recursively
    while let Some(task) = builder.concrete_pending_tasks.pop() {
        let target_chip = builder.get_chip(&task.chip_name);
        println!("Target chip: {:?}", &task.chip_name);
        let target_picus_info = target_chip.picus_info();

        let mut sub_builder = PicusBuilder::new(
            target_chip,
            PicusModule::new(task.chip_name.clone()),
            builder.chips,
            Some(task.main_vars.clone()),
            Some(task.multiplicity.clone()),
        );

        let (mut sub_module, aux_modules) =
            analyze_chip(target_chip, builder.chips, Some(&mut sub_builder));
        // Merge submodules
        builder.aux_modules.extend(aux_modules.into_iter());

        sub_module.apply_multiplier(task.multiplicity);
        // partially evaluate

        let selector_col = target_picus_info.name_to_colrange.get(&task.selector).unwrap().0;
        let mut env = BTreeMap::new();
        // Set `is_real = 1` if it is set in `picus_info`
        if let Some(id) = target_picus_info.is_real_index {
            env.insert(id, 1);
        }
        env.insert(selector_col, 1);
        for (other_selector_col, _) in &target_picus_info.selector_indices {
            if selector_col == *other_selector_col {
                continue;
            }
            env.insert(*other_selector_col, 0);
        }
        let updated_picus_module = sub_module.partial_eval(&env);
        println!("Updated module: {updated_picus_module}");
        builder.picus_module.constraints.extend_from_slice(&updated_picus_module.constraints);
        builder.picus_module.calls.extend_from_slice(&updated_picus_module.calls);
        builder.picus_module.postconditions.extend_from_slice(&sub_module.postconditions);
    }

    (builder.picus_module.clone(), builder.aux_modules.clone())
}

fn main() {
    let args = Args::parse();

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
    initialize_fresh_var_ctr(chip.width() + 1);

    // Set the field modulus for the Picus program:
    let koala_prime = 0x7f000001;
    let _ = set_field_modulus(koala_prime);

    // Initialize the Picus program
    let mut picus_program = PicusProgram::new(koala_prime);

    // Build the Picus program which will have a single module with the chip constraints
    println!("Generating Picus program for {} chip.....", chip.name());
    let (picus_module, mut aux_modules) = analyze_chip(chip, &chips, None);
    picus_program.add_modules(&mut aux_modules);
    // At this point, we've built a module directly from the constraints. However, this isn't super amenable to verification
    // because the selectors introduce a lot of nonlinearity. So what we do instead is generate distinct Picus modules
    // each of which correspond to a selector being enabled. The selectors are mutually exclusive.
    let mut selector_modules = BTreeMap::new();

    if picus_info.selector_indices.is_empty() {
        panic!("PicusBuilder needs at least one selector to be enabled!")
    }
    println!("Applying selectors program.....");
    println!("PicusInfo: {:?}", picus_info.clone());
    for (selector_col, _) in &picus_info.selector_indices {
        let mut env = BTreeMap::new();
        // Set `is_real = 1` if it is set in `picus_info`
        if let Some(id) = picus_info.is_real_index {
            env.insert(id, 1);
        }
        env.insert(*selector_col, 1);
        for (other_selector_col, _) in &picus_info.selector_indices {
            if selector_col == other_selector_col {
                continue;
            }
            env.insert(*other_selector_col, 0);
        }
        // We generate a new Picus module by partially evaluating our original Picus module with respect
        // to the environment map.
        let updated_picus_module = picus_module.partial_eval(&env);
        selector_modules.insert(updated_picus_module.name.clone(), updated_picus_module);
    }

    picus_program.add_modules(&mut selector_modules);
    let res =
        picus_program.write_to_path(args.picus_out_dir.join(format!("{}.picus", chip.name())));
    if res.is_err() {
        panic!("Failed to write picus file: {res:?}");
    }
    println!("Successfully extracted Picus program");
}
