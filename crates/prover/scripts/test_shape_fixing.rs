use clap::Parser;
use p3_koala_bear::KoalaBear;
use p3_util::log2_ceil_usize;
use zkm_core_executor::{Executor, MipsAirId, Program, ZKMContext};
use zkm_core_machine::{io::ZKMStdin, mips::MipsAir, shape::CoreShapeConfig, utils::setup_logger};
use zkm_stark::ZKMCoreOpts;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_delimiter = ',')]
    list: Vec<String>,
    #[clap(short, long, value_delimiter = ',')]
    shard_size: usize,
}

fn main() {
    // Setup logger.
    setup_logger();

    // Parse arguments.
    let args = Args::parse();

    // Setup the options.
    let config = CoreShapeConfig::<KoalaBear>::default();
    let mut opts = ZKMCoreOpts { shard_batch_size: 1, ..Default::default() };
    opts.shard_size = 1 << args.shard_size;

    // For each program, collect the maximal shapes.
    let program_list = args.list;
    for path in program_list {
        /*
        // Download program and stdin files from S3.
        tracing::info!("download elf and input for {}", s3_path);

        // Download program.bin.
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://zkm-testing-suite/{}/program.bin", s3_path),
                "program.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for program.bin");
        if !status.success() {
            panic!("Failed to download program.bin from S3");
        }

        // Download stdin.bin.
        let status = std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://zkm-testing-suite/{}/stdin.bin", s3_path),
                "stdin.bin",
            ])
            .status()
            .expect("Failed to execute aws s3 cp command for stdin.bin");
        if !status.success() {
            panic!("Failed to download stdin.bin from S3");
        }
        */

        // Read the program and stdin.
        let elf = std::fs::read(path.clone() + "/program.bin").expect("failed to read program");
        let stdin = std::fs::read(path.clone() + "/stdin.bin").expect("failed to read stdin");
        let stdin: ZKMStdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

        // Collect the maximal shapes for each shard size.
        let elf = elf.clone();
        let stdin = stdin.clone();
        let new_context = ZKMContext::default();
        test_shape_fixing(&elf, &stdin, opts, new_context, &config);

        // std::fs::remove_file("program.bin").expect("failed to remove program.bin");
        // std::fs::remove_file("stdin.bin").expect("failed to remove stdin.bin");
    }
}

fn test_shape_fixing(
    elf: &[u8],
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    context: ZKMContext,
    shape_config: &CoreShapeConfig<KoalaBear>,
) {
    // Setup the program.
    let mut program = Program::from(elf).unwrap();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();

    // Setup the executor.
    let mut executor = Executor::with_context(program, opts, context);
    executor.maximal_shapes = Some(
        shape_config.maximal_core_shapes(log2_ceil_usize(opts.shard_size)).into_iter().collect(),
    );
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

    // Collect the maximal shapes.
    let mut finished = false;
    while !finished {
        let (records, f) = executor.execute_record(true).unwrap();
        finished = f;
        for mut record in records {
            let _ = record.defer();
            let heights = MipsAir::<KoalaBear>::core_heights(&record);
            println!("heights: {heights:?}");

            shape_config.fix_shape(&mut record).unwrap();

            if record.contains_cpu()
                && record.shape.unwrap().height(&MipsAirId::Cpu).unwrap() > opts.shard_size
            {
                panic!("something went wrong")
            }
        }
    }
}
