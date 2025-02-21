use crate::hasher::{Hasher, Mode};
use crate::syscall_keccak_permute;

pub const WORDS: usize = 25;

#[derive(Default, Clone)]
pub struct KeccakBuffer([u64; crate::hasher::WORDS]);
impl KeccakBuffer {
    pub(crate) fn words(&mut self) -> &mut [u64; crate::hasher::WORDS] {
        &mut self.0
    }

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; crate::hasher::WORDS * 8] =
            unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        let buffer: &mut [u8; crate::hasher::WORDS * 8] =
            unsafe { core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }

    fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

pub trait KeccakPermutation {
    fn execute(a: &mut KeccakBuffer);
}

pub(crate) struct KeccakState {
    buffer: KeccakBuffer,
    offset: usize,
    rate: usize,
    delim: u8,
    mode: Mode,
    // permutation: core::marker::PhantomData<P>,
}

impl Clone for KeccakState {
    fn clone(&self) -> Self {
        KeccakState {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            mode: self.mode,
            // permutation: core::marker::PhantomData,
        }
    }
}

impl KeccakState {
    pub(crate) fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: KeccakBuffer::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            // permutation: core::marker::PhantomData,
        }
    }

    fn keccak(&mut self) {
        keccakf(self.buffer.words());
        // P::execute(&mut self.buffer);
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        if let Mode::Squeezing = self.mode {
            self.mode = Mode::Absorbing;
            self.fill_block();
        }

        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccak();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        if let Mode::Absorbing = self.mode {
            self.mode = Mode::Squeezing;
            self.pad();
            self.fill_block();
        }

        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.setout(&mut output[op..], offset, rate);
            self.keccak();
            op += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }

    pub(crate) fn finalize(mut self, output: &mut [u8]) {
        self.squeeze(output);
    }

    pub(crate) fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    pub(crate) fn reset(&mut self) {
        self.buffer = KeccakBuffer::default();
        self.offset = 0;
        self.mode = Mode::Absorbing;
    }
}

pub(crate) fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

#[inline]
pub(crate) fn keccakf(state: &mut [u64; 25]) {
    unsafe {
        syscall_keccak_permute(state);
    }
}

#[derive(Clone)]
pub struct Keccak {
    state: KeccakState,
}

impl Keccak {
    const DELIM: u8 = 0x01;

    /// Creates  new [`Keccak`] hasher with a security level of 224 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v224() -> Keccak {
        Keccak::new(224)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Keccak {
        Keccak::new(256)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 384 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v384() -> Keccak {
        Keccak::new(384)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 512 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v512() -> Keccak {
        Keccak::new(512)
    }

    fn new(bits: usize) -> Keccak {
        Keccak { state: KeccakState::new(bits_to_rate(bits), Self::DELIM) }
    }
}

impl Hasher for Keccak {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}
