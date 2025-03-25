// //! This code is adapted from tiny-keccak:
// //! https://github.com/debris/tiny-keccak
// pub const WORDS: usize = 25;
//
// pub trait Hasher {
//     /// Absorb additional input. Can be called multiple times.
//     fn update(&mut self, input: &[u8]);
//
//     /// Pad and squeeze the state to the output.
//     fn finalize(self, output: &mut [u8]);
// }
//
// #[derive(Clone, Copy)]
// pub(crate) enum Mode {
//     Absorbing,
//     Squeezing,
// }
