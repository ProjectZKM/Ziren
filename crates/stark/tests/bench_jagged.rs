use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use std::time::Instant;
use zkm_stark::jagged::{
    pack_traces_jagged, hierarchical_jagged_pack, jagged_stats,
};

type F = KoalaBear;

#[test]
fn bench_flat_vs_hierarchical() {
    let chip_specs: Vec<(&str, usize, usize)> = vec![
        ("Cpu",              8192,  70),
        ("AddSub",           4096,  31),
        ("Bitwise",          2048,  26),
        ("ShiftRight",       1024,  45),
        ("DivRem",            512, 170),
        ("Mul",               256,  31),
        ("MemoryGlobalInit", 4096,  11),
        ("MemoryGlobalFin",  4096,  11),
        ("ShaExtend",        2048,  72),
        ("ShaCompress",      2048, 400),
        ("ByteLookup",      65536,  15),
        ("ProgramChip",      8192,  11),
        ("SyscallCore",       256,  31),
        ("KeccakPermute",   1024, 200),
        ("Global",            256,  14),
        ("SepticCurve",       512,  14),
        ("RangeCheck",       8192,   8),
    ];

    let traces: Vec<(String, RowMajorMatrix<F>)> = chip_specs
        .iter()
        .map(|(name, h, w)| {
            (name.to_string(), RowMajorMatrix::new(vec![F::ONE; h * w], *w))
        })
        .collect();

    let total_cols: usize = chip_specs.iter().map(|(_, _, w)| *w).sum();
    let total_cells: usize = chip_specs.iter().map(|(_, h, w)| h * w).sum();

    println!("\n=== Realistic zkVM Shard ({} chips) ===", chip_specs.len());
    println!("Total columns: {}", total_cols);
    println!("Total cells:   {}\n", total_cells);

    // Flat
    let t0 = Instant::now();
    for _ in 0..10 {
        let _ = pack_traces_jagged(&traces);
    }
    let flat_us = t0.elapsed().as_micros() / 10;
    let flat = pack_traces_jagged(&traces);
    let fs = jagged_stats(&flat);

    println!("--- Flat Jagged Packing ---");
    println!("  Pack time:   {}µs", flat_us);
    println!("  Dense vec:   {} values", fs.total_real_values);
    println!("  Padded:      {} values ({:.1}% overhead)", fs.padded_size, (fs.padding_ratio - 1.0) * 100.0);
    println!("  WHIR fan-in: {}\n", fs.total_columns);

    // Hierarchical
    let alpha = F::from_u32(12345);
    let t1 = Instant::now();
    for _ in 0..10 {
        let _ = hierarchical_jagged_pack(&traces, alpha);
    }
    let hier_us = t1.elapsed().as_micros() / 10;
    let (folded, hier) = hierarchical_jagged_pack(&traces, alpha);
    let hs = jagged_stats(&hier);

    println!("--- Hierarchical Jagged Packing ---");
    println!("  Fold+Pack:   {}µs", hier_us);
    println!("  Dense vec:   {} values", hs.total_real_values);
    println!("  Padded:      {} values ({:.1}% overhead)", hs.padded_size, (hs.padding_ratio - 1.0) * 100.0);
    println!("  WHIR fan-in: {}\n", hs.total_columns);

    println!("=== Comparison ===");
    println!("  Fan-in:    {} → {} ({:.0}x reduction)", fs.total_columns, hs.total_columns,
        fs.total_columns as f64 / hs.total_columns as f64);
    println!("  Data:      {} → {} ({:.1}x reduction)", fs.total_real_values, hs.total_real_values,
        fs.total_real_values as f64 / hs.total_real_values as f64);
    println!("  Padded:    {} → {} ({:.1}x reduction)", fs.padded_size, hs.padded_size,
        fs.padded_size as f64 / hs.padded_size as f64);
    println!("  Pack time: {}µs → {}µs", flat_us, hier_us);

    // Per-table breakdown
    println!("\n--- Per-Table Fold Results ---");
    for i in 0..chip_specs.len() {
        let (name, h, w) = chip_specs[i];
        println!("  {:20} {:>5} rows × {:>3} cols → {:>5} values (folded to 1 col)", name, h, w, folded[i].height);
    }
}
