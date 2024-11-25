use crate::config::StarkConfig;
use crate::config::StarkGenericConfig;
use p3_field::FieldExtensionAlgebra;
use p3_field::{Field, FieldAlgebra};

pub fn generate_traces<
    F: Field + FieldExtensionAlgebra<F>,
    const D: usize,
    M,
    SC: StarkGenericConfig,
>(
    //all_stark: &AllStark<F, D>,
    //kernel: &Kernel,
    config: SC,
    //timing: &mut TimingTree,
) {
}
