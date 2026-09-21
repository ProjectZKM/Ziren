use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use clap::Parser;
use p3_koala_bear::KoalaBear;
use zkm_core_machine::utils::setup_logger;
use zkm_pcs::{shape::OrderedShape, MachineProver};
use zkm_prover::{
    components::DefaultProverComponents,
    shapes::{check_shapes, ZKMCompressProgramShape, ZKMProofShape},
    CompressAir, ShrinkAir, ZKMProver, REDUCE_BATCH_SIZE,
};
use zkm_recursion_core::shape::RecursionShapeConfig;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value_t = false)]
    dummy: bool,
    #[clap(short, long, default_value_t = REDUCE_BATCH_SIZE)]
    recursion_batch_size: usize,
    #[clap(short, long, default_value_t = 1)]
    num_compiler_workers: usize,
    #[clap(short, long, default_value_t = 1)]
    count_setup_workers: usize,
    #[clap(short, long)]
    start: Option<usize>,
    #[clap(short, long)]
    end: Option<usize>,
    /// Height-agnostic raw-height discovery: instead of the chip-by-chip
    /// reduction, measure the per-chip MAXIMAL *natural* (pre-`fix_shape`)
    /// recursion heights across all enumerated shapes in ONE pass and print the
    /// resulting maximal band.
    #[clap(long, default_value_t = false)]
    measure: bool,
}

fn main() {
    setup_logger();

    let args = Args::parse();

    let mut prover = ZKMProver::<DefaultProverComponents>::new();

    prover.vk_verification = !args.dummy;

    let compress_shape_config =
        prover.compress_shape_config.as_ref().expect("recursion shape config not found");

    let candidate = compress_shape_config.union_config_with_extra_room().first().unwrap().clone();

    if args.measure {
        let enum_cfg =
            RecursionShapeConfig::<KoalaBear, CompressAir<KoalaBear>>::from_hash_map(&candidate);

        prover.compress_shape_config = None;

        let all_shapes =
            ZKMProofShape::generate(&enum_cfg, args.recursion_batch_size).collect::<Vec<_>>();
        let num_shapes = all_shapes.len();
        tracing::info!("measure: number of enumerated shapes: {}", num_shapes);

        let height = zkm_prover::VK_MERKLE_TREE_HEIGHT;

        let maxima: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let skipped = Arc::new(Mutex::new(0usize));

        let (shape_tx, shape_rx) =
            std::sync::mpsc::sync_channel::<ZKMProofShape>(args.num_compiler_workers);
        let shape_rx = Mutex::new(shape_rx);

        let ceil_log2 = |rows: usize| -> usize {
            if rows <= 1 {
                0
            } else {
                (usize::BITS - (rows - 1).leading_zeros()) as usize
            }
        };

        std::thread::scope(|s| {
            for _ in 0..args.num_compiler_workers {
                let shape_rx = &shape_rx;
                let prover = &prover;
                let maxima = Arc::clone(&maxima);
                let skipped = Arc::clone(&skipped);
                s.spawn(move || loop {
                    let recvd = {
                        let rx = shape_rx.lock().unwrap();
                        rx.recv()
                    };
                    let shape = match recvd {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let compress_shape =
                        ZKMCompressProgramShape::from_proof_shape(shape.clone(), height);
                    let measured = catch_unwind(AssertUnwindSafe(|| {
                        let program = prover.program_from_shape(compress_shape, None);
                        CompressAir::<KoalaBear>::heights(&program)
                    }));
                    match measured {
                        Ok(per_chip) => {
                            let mut guard = maxima.lock().unwrap();
                            for (chip, rows) in per_chip {
                                let log = ceil_log2(rows);
                                let e = guard.entry(chip).or_insert(0);
                                *e = (*e).max(log);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("measure: skipping shape {:?} (panic: {:?})", shape, e);
                            *skipped.lock().unwrap() += 1;
                        }
                    }
                });
            }

            for shape in all_shapes {
                shape_tx.send(shape).unwrap();
            }
            drop(shape_tx);
        });

        let maxima = Arc::try_unwrap(maxima).unwrap().into_inner().unwrap();
        let skipped = Arc::try_unwrap(skipped).unwrap().into_inner().unwrap();
        let mut sorted: Vec<(String, usize)> = maxima.into_iter().collect();
        sorted.sort();

        println!("MEASURED MAXIMAL BAND (log2): {:?}", sorted);
        println!("measure: skipped (panicked) shapes: {} / {}", skipped, num_shapes);
        return;
    }

    prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&candidate));

    assert!(check_shapes(args.recursion_batch_size, false, args.num_compiler_workers, &prover,));

    let mut answer = candidate.clone();

    for (key, value) in candidate.iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value;
            while !done {
                new_val /= 2;
                answer.insert(key.clone(), new_val);
                prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
                done = !check_shapes(
                    args.recursion_batch_size,
                    false,
                    args.num_compiler_workers,
                    &prover,
                );
            }
            answer.insert(key.clone(), new_val * 2);
        }
    }

    let mut no_precompile_answer = answer.clone();

    for (key, value) in answer.iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value;
            while !done {
                new_val /= 2;
                no_precompile_answer.insert(key.clone(), new_val);
                prover.compress_shape_config =
                    Some(RecursionShapeConfig::from_hash_map(&no_precompile_answer));
                done = !check_shapes(
                    args.recursion_batch_size,
                    true,
                    args.num_compiler_workers,
                    &prover,
                );
            }
            no_precompile_answer.insert(key.clone(), new_val * 2);
        }
    }

    let mut shrink_shape = ShrinkAir::<KoalaBear>::shrink_shape().clone_into_hash_map();

    assert!({
        prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
        catch_unwind(AssertUnwindSafe(|| {
            prover.shrink_prover.setup(&prover.program_from_shape(
                zkm_prover::shapes::ZKMCompressProgramShape::from_proof_shape(
                    ZKMProofShape::Shrink(OrderedShape {
                        inner: answer.clone().into_iter().collect::<Vec<_>>(),
                    }),
                    5,
                ),
                Some(shrink_shape.clone().into()),
            ))
        }))
        .is_ok()
    });

    for (key, value) in shrink_shape.clone().iter() {
        if key != "PublicValues" {
            let mut done = false;
            let mut new_val = *value * 2;
            while !done {
                new_val /= 2;
                shrink_shape.insert(key.clone(), new_val);
                prover.compress_shape_config = Some(RecursionShapeConfig::from_hash_map(&answer));
                done = catch_unwind(AssertUnwindSafe(|| {
                    prover.shrink_prover.setup(&prover.program_from_shape(
                        zkm_prover::shapes::ZKMCompressProgramShape::from_proof_shape(
                            ZKMProofShape::Shrink(OrderedShape {
                                inner: answer.clone().into_iter().collect::<Vec<_>>(),
                            }),
                            5,
                        ),
                        Some(shrink_shape.clone().into()),
                    ))
                }))
                .is_err();
            }
            shrink_shape.insert(key.clone(), new_val * 2);
        }
    }

    println!("Final compress shape: {answer:?}");
    println!("Final compress shape with no precompiles: {no_precompile_answer:?}");
    println!("Final shrink shape: {shrink_shape:?}");
}
