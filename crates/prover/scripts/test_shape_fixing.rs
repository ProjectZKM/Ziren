use clap::Parser;
use p3_koala_bear::KoalaBear;
use p3_util::log2_ceil_usize;
use zkm_core_executor::{Executor, MipsAirId, Program, ZKMContext};
use zkm_core_machine::{io::ZKMStdin, mips::MipsAir, shape::CoreShapeConfig, utils::setup_logger};
use zkm_pcs::ZKMCoreOpts;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_delimiter = ',')]
    list: Vec<String>,
    #[clap(short, long, value_delimiter = ',')]
    shard_size: usize,
}

fn main() {
    setup_logger();

    let args = Args::parse();

    let config = CoreShapeConfig::<KoalaBear>::default();
    let mut opts = ZKMCoreOpts { shard_batch_size: 1, ..Default::default() };
    opts.shard_size = 1 << args.shard_size;

    let program_list = args.list;
    for path in program_list {
        let elf = std::fs::read(path.clone() + "/program.bin").expect("failed to read program");
        let stdin = std::fs::read(path.clone() + "/stdin.bin").expect("failed to read stdin");
        let stdin: ZKMStdin = bincode::deserialize(&stdin).expect("failed to deserialize stdin");

        let elf = elf.clone();
        let stdin = stdin.clone();
        let new_context = ZKMContext::default();
        test_shape_fixing(&elf, &stdin, opts, new_context, &config);
    }
}

fn test_shape_fixing(
    elf: &[u8],
    stdin: &ZKMStdin,
    opts: ZKMCoreOpts,
    context: ZKMContext,
    shape_config: &CoreShapeConfig<KoalaBear>,
) {
    let mut program = Program::from(elf).unwrap();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();

    let mut executor = Executor::with_context(program, opts, context);
    executor.maximal_shapes = Some(
        shape_config.maximal_core_shapes(log2_ceil_usize(opts.shard_size)).into_iter().collect(),
    );
    executor.write_vecs(&stdin.buffer);
    for (proof, vkey) in stdin.proofs.iter() {
        executor.write_proof(proof.clone(), vkey.clone());
    }

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
