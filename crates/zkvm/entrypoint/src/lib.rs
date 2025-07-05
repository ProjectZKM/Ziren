//! Ported from Entrypoint for Ziren zkVM.
#![feature(asm_experimental_arch)]
pub mod heap;
pub mod syscalls;
pub mod io {
    pub use zkm_lib::io::*;
}
pub mod lib {
    pub use zkm_lib::*;
}

extern crate alloc;

#[macro_export]
macro_rules! entrypoint {
    ($path:path) => {
        const ZKVM_ENTRY: fn() = $path;

        use $crate::heap::SimpleAlloc;

        #[global_allocator]
        static HEAP: SimpleAlloc = SimpleAlloc;

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
