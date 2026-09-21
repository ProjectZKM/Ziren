use std::{collections::BTreeMap, path::PathBuf};

use clap::Parser;
use zkm_core_executor::{mips_costs, MipsAirId};
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::shape::Shape;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    maximal_shapes_json: Option<PathBuf>,
    #[clap(short, long)]
    small_shapes_json: Option<PathBuf>,
    #[clap(short, long)]
    lde_threshold_bytes: usize,
}

fn main() {
    setup_logger();

    let args = Args::parse();

    let costs = mips_costs();

    if let Some(maximal_shapes_json) = args.maximal_shapes_json {
        let maximal_shapes: BTreeMap<usize, Vec<Shape<MipsAirId>>> = serde_json::from_slice(
            &std::fs::read(&maximal_shapes_json).expect("failed to read maximal shapes"),
        )
        .expect("failed to deserialize maximal shapes");

        for shapes in maximal_shapes.values() {
            for shape in shapes.iter() {
                let lde_size = shape.estimate_lde_size(&costs);
                if lde_size > args.lde_threshold_bytes {
                    println!("maximal shape: {shape:?}, lde_size: {lde_size}");
                }
            }
        }
    }

    if let Some(small_shapes_json) = args.small_shapes_json {
        let small_shapes: Vec<Shape<MipsAirId>> = serde_json::from_slice(
            &std::fs::read(&small_shapes_json).expect("failed to read small shapes"),
        )
        .expect("failed to deserialize small shapes");

        for shape in small_shapes.iter() {
            let lde_size = shape.estimate_lde_size(&costs);
            if lde_size > args.lde_threshold_bytes {
                println!("small shape: {shape:?}, lde_size: {lde_size}");
            }
        }
    }
}
