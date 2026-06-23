use std::path::PathBuf;

use clap::Parser;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::{
    components::DefaultProverComponents, shapes::build_vk_map_to_file, REDUCE_BATCH_SIZE,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: PathBuf,
    #[clap(short, long, default_value_t = false)]
    dummy: bool,
    #[clap(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    reduce_batch_size: usize,
    #[clap(short, long, default_value_t = 1)]
    num_compiler_workers: usize,
    #[clap(short, long, default_value_t = 1)]
    count_setup_workers: usize,
    #[clap(short, long)]
    start: Option<usize>,
    #[clap(short, long)]
    end: Option<usize>,
    /// Comma-separated arbitrary shape indices (sparse set). Supersedes
    /// --start/--end. Lets a targeted regen build only specific shapes
    /// (e.g. just a program's recursion shapes). Mirrors ziren-gpu.
    #[clap(short, long)]
    indices: Option<String>,
}

fn main() {
    setup_logger();
    let args = Args::parse();

    let reduce_batch_size = args.reduce_batch_size;
    let build_dir = args.build_dir;
    let dummy = args.dummy;
    let num_compiler_workers = args.num_compiler_workers;
    let num_setup_workers = args.count_setup_workers;
    let range_start = args.start;
    let range_end = args.end;
    let indices = args.indices.map(|s| {
        s.split(',')
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.trim().parse::<usize>().expect("--indices: comma-separated usize"))
            .collect::<Vec<usize>>()
    });

    build_vk_map_to_file::<DefaultProverComponents>(
        build_dir,
        reduce_batch_size,
        dummy,
        num_compiler_workers,
        num_setup_workers,
        range_start,
        range_end,
        indices,
    )
    .unwrap();
}
