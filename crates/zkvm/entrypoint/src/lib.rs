//! Ported from Entrypoint for Ziren zkVM.
#![feature(asm_experimental_arch)]
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
use syscalls::MAX_MEMORY;

pub mod syscalls;
pub mod io {
    pub use zkm_lib::io::*;
}
pub mod lib {
    pub use zkm_lib::*;
}

#[cfg(target_os = "zkvm")]
use {
    cfg_if::cfg_if,
    syscalls::{syscall_hint_len, syscall_hint_read},
};

extern crate alloc;

#[cfg(target_os = "zkvm")]
pub mod allocators;

/// Size of the reserved region for input values with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
pub(crate) const EMBEDDED_RESERVED_INPUT_REGION_SIZE: usize = 1024 * 1024 * 1024;

/// Start of the reserved region for inputs with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
pub(crate) const EMBEDDED_RESERVED_INPUT_START: usize =
    MAX_MEMORY - EMBEDDED_RESERVED_INPUT_REGION_SIZE;

/// Pointer to the current position in the reserved region for inputs with the embedded allocator.
#[cfg(all(target_os = "zkvm", feature = "embedded"))]
static mut EMBEDDED_RESERVED_INPUT_PTR: usize = EMBEDDED_RESERVED_INPUT_START;

#[repr(C)]
pub struct ReadVecResult {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

/// Read a buffer from the input stream.
///
/// The buffer is read into uninitialized memory.
///
/// When the `bump` feature is enabled, the buffer is read into a new buffer allocated by the
/// program.
///
/// When the `embedded` feature is enabled, the buffer is read into the reserved input region.
///
/// When there is no allocator selected, the program will fail to compile.
///
/// If the input stream is exhausted, the failed flag will be returned as true. In this case, the other outputs from the function are likely incorrect, which is fine as zkm-lib` always panics in the case that the input stream is exhausted.
#[no_mangle]
pub extern "C" fn read_vec_raw() -> ReadVecResult {
    #[cfg(not(target_os = "zkvm"))]
    unreachable!("read_vec_raw should only be called on the zkvm target.");

    #[cfg(target_os = "zkvm")]
    {
        // Get the length of the input buffer.
        let len = syscall_hint_len();

        // If the length is u32::MAX, then the input stream is exhausted.
        if len == usize::MAX {
            return ReadVecResult { ptr: std::ptr::null_mut(), len: 0, capacity: 0 };
        }

        // Round up to multiple of 4 for whole-word alignment.
        let capacity = (len + 3) / 4 * 4;

        cfg_if! {
            if #[cfg(feature = "embedded")] {
                // Get the existing pointer in the reserved region which is the start of the vec.
                // Increment the pointer by the capacity to set the new pointer to the end of the vec.
                let ptr = unsafe { EMBEDDED_RESERVED_INPUT_PTR };
                if ptr + capacity > MAX_MEMORY {
                    panic!("Input region overflowed.")
                }

                // SAFETY: The VM is single threaded.
                unsafe { EMBEDDED_RESERVED_INPUT_PTR += capacity };

                // Read the vec into uninitialized memory. The syscall assumes the memory is
                // uninitialized, which is true because the input ptr is incremented manually on each
                // read.
                syscall_hint_read(ptr as *mut u8, len);

                // Return the result.
                ReadVecResult {
                    ptr: ptr as *mut u8,
                    len,
                    capacity,
                }
            } else if #[cfg(feature = "bump")] {
                // Allocate a buffer of the required length that is 4 byte aligned.
                let layout = std::alloc::Layout::from_size_align(capacity, 4).expect("vec is too large");

                // SAFETY: The layout was made through the checked constructor.
                let ptr = unsafe { std::alloc::alloc(layout) };

                // Read the vec into uninitialized memory. The syscall assumes the memory is
                // uninitialized, which is true because the bump allocator does not dealloc, so a new
                // alloc is always fresh.
                syscall_hint_read(ptr as *mut u8, len);

                // Return the result.
                ReadVecResult {
                    ptr: ptr as *mut u8,
                    len,
                    capacity,
                }
            } else {
                // An allocator must be selected.
                compile_error!("There is no allocator selected. Please enable the `bump` or `embedded` feature.");
            }
        }
    }
}

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        mod zkvm_generated_main {

            #[no_mangle]
            fn start() {
                super::ZKVM_ENTRY()
            }
        }
    };
}

#[cfg(all(target_os = "zkvm", feature = "libm"))]
mod libm;

/// The number of 32 bit words that the public values digest is composed of.
pub const PV_DIGEST_NUM_WORDS: usize = 8;
pub const POSEIDON_NUM_WORDS: usize = 8;

#[cfg(target_os = "zkvm")]
mod zkvm {
    use crate::syscalls::syscall_halt;

    use cfg_if::cfg_if;
    use getrandom::{register_custom_getrandom, Error};
    use sha2::{Digest, Sha256};

    cfg_if! {
        if #[cfg(feature = "verify")] {
            use p3_koala_bear::KoalaBear;
            use p3_field::FieldAlgebra;

            pub static mut DEFERRED_PROOFS_DIGEST: Option<[KoalaBear; 8]> = None;
        }
    }

    pub static mut PUBLIC_VALUES_HASHER: Option<Sha256> = None;

    #[no_mangle]
    fn _main() {
        #[cfg(all(target_os = "zkvm", feature = "embedded"))]
        crate::allocators::init();

        unsafe {
            PUBLIC_VALUES_HASHER = Some(Sha256::new());
            #[cfg(feature = "verify")]
            {
                DEFERRED_PROOFS_DIGEST = Some([KoalaBear::ZERO; 8]);
            }
            extern "C" {
                fn start();
            }
            start()
        }

        syscall_halt(0);
    }

    core::arch::global_asm!(include_str!("memset.s"));
    core::arch::global_asm!(include_str!("memcpy.s"));

    core::arch::global_asm!(
        r#"
    .section .text.main;
    .globl main;
    main:
        li  $sp, 0xfffc000
        jal _main;
    "#
    );
    fn zkvm_getrandom(s: &mut [u8]) -> Result<(), Error> {
        unsafe {
            crate::syscalls::sys_rand(s.as_mut_ptr(), s.len());
        }

        Ok(())
    }

    register_custom_getrandom!(zkvm_getrandom);
}
