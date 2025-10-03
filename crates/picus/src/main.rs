use std::{collections::BTreeMap, path::PathBuf};

use clap::{Parser, ValueHint};
use p3_air::{Air, BaseAir};
use zkm_core_machine::MipsAir;
use zkm_picus::{
    pcl::{
        initialize_fresh_var_ctr, set_field_modulus, set_picus_names, Felt, PicusExpr, PicusModule,
        PicusProgram, PicusVar,
    },
    picus_builder::PicusBuilder,
};
use zkm_stark::{MachineAir, ZKM_PROOF_NUM_PV_ELTS};

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

    // Allocate Picus program consisting of a single module that corresponds to the chip.
    let mut picus_module = PicusModule::new(chip.name());

    // Specify the input columns
    for (start, end, _) in &picus_info.input_ranges {
        for col in *start..*end {
            picus_module.inputs.push(PicusExpr::Var(PicusVar { id: col }));
        }
    }
    // Specify the output columns
    for (start, end, _) in &picus_info.output_ranges {
        for col in *start..=*end {
            picus_module.outputs.push(PicusExpr::Var(PicusVar { id: col }));
        }
    }
    // Build the Picus program which will have a single module with the chip constraints
    println!("Generating Picus program for {} chip.....", chip.name());
    let mut picus_builder = PicusBuilder::new(
        chip.preprocessed_width(),
        chip.air.width(),
        ZKM_PROOF_NUM_PV_ELTS,
        picus_module,
    );
    chip.air.eval(&mut picus_builder);
    picus_program.add_modules(&mut picus_builder.aux_modules);
    // At this point, we've built a module directly from the constraints. However, this isn't super amenable to verification
    // because the selectors introduce a lot of nonlinearity. So what we do instead is generate distinct Picus modules
    // each of which correspond to a selector being enabled. The selectors are mutually exclusive.
    let mut selector_modules = BTreeMap::new();

    if picus_info.selector_indices.is_empty() {
        panic!("PicusBuilder needs at least one selector to be enabled!")
    }
    println!("Picus Info: {:?}", picus_info);
    println!("Applying selectors program.....");
    for (selector_col, _) in &picus_info.selector_indices {
        let mut env = BTreeMap::new();
        env.insert(PicusVar { id: *selector_col }, 1);
        for (other_selector_col, _) in &picus_info.selector_indices {
            if selector_col == other_selector_col {
                continue;
            }
            env.insert(PicusVar { id: *other_selector_col }, 0);
        }
        // We generate a new Picus module by partially evaluating our original Picus module with respect
        // to the environment map.
        let updated_picus_module = picus_builder.picus_module.partial_eval(&env);
        selector_modules.insert(updated_picus_module.name.clone(), updated_picus_module);
    }

    picus_program.add_modules(&mut selector_modules);
    let res =
        picus_program.write_to_path(args.picus_out_dir.join(format!("{}.picus", chip.name())));
    if res.is_err() {
        panic!("Failed to write picus file: {:?}", res);
    }
    println!("Successfully extracted Picus program");
}
