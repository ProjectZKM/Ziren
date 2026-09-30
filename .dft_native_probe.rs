use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

fn main() {
    let input: Vec<_> = (0..4096)
        .map(|i| KoalaBear::from_u64((17 * i * i + 31 * i + 9) as u64))
        .collect();
    let dft = Radix2DitParallel::<KoalaBear>::default();
    let output = dft
        .dft_batch(RowMajorMatrix::new(input, 1))
        .to_row_major_matrix();
    for value in output.values {
        print!("{:08x}", value.as_canonical_u32());
    }
    println!();
}
