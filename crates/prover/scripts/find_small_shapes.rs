use std::{collections::BTreeMap, path::PathBuf};

use clap::Parser;
use zkm_core_executor::MipsAirId;
use zkm_core_machine::utils::setup_logger;
use zkm_stark::shape::Shape;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    maximal_shapes_json: PathBuf,
    #[clap(short, long, value_delimiter = ' ')]
    log2_memory_heights: Vec<usize>,
    #[clap(short, long, default_value = "small_shapes.json")]
    output: PathBuf,
}

fn main() {
    // Setup logger.
    setup_logger();

    // Parse arguments.
    let args = Args::parse();

    // Load the maximal shapes, indexed by log shard size.
    let maximal_shapes: BTreeMap<usize, Vec<Shape<MipsAirId>>> = serde_json::from_slice(
        &std::fs::read(&args.maximal_shapes_json).expect("failed to read maximal shapes"),
    )
    .expect("failed to deserialize maximal shapes");

    // For each maximal shape, generate all small shapes by varying the memory heights.
    let mut small_shapes = Vec::new();
    for (log2_shard_size, shapes) in maximal_shapes.iter() {
        if *log2_shard_size > 22 {
            continue;
        }
        for shape in shapes.iter() {
            for log2_memory_height in args.log2_memory_heights.iter() {
                let mut small_shape = shape.clone();
                let log2_gap_from_22 = 22 - small_shape.log2_height(&MipsAirId::Cpu).unwrap();
                let min_log2_height_threshold = 16 - log2_gap_from_22;
                for air in MipsAirId::core() {
                    let current_log2_height =
                        small_shape.log2_height(&air.clone()).unwrap_or_default();
                    small_shape
                        .insert(air, std::cmp::max(current_log2_height, min_log2_height_threshold));
                }
                small_shape.insert(MipsAirId::MemoryGlobalInit, *log2_memory_height);
                small_shape.insert(MipsAirId::MemoryGlobalFinalize, *log2_memory_height);
                small_shape.insert(MipsAirId::Global, log2_memory_height + 1);
                small_shapes.push(small_shape);
            }
        }
    }

    // Serialize the small shapes.
    let serialized =
        serde_json::to_string_pretty(&small_shapes).expect("failed to serialize small shapes");
    std::fs::write(&args.output, serialized).expect("failed to write small shapes");
}
