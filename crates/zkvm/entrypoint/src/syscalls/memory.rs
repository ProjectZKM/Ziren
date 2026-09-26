// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Memory addresses must be lower than KoalaBear prime.
pub const MAX_MEMORY: usize = 0x7f000000;

/// Bump-allocates `bytes` bytes aligned to `align` above `_end`.
///
/// # Safety
///
/// `align` must be a power of two, and calls must not run concurrently: the
/// heap cursor `HEAP_POS` is unsynchronized (the guest is single-threaded).
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    extern "C" {
        static _end: u8;
    }

    static mut HEAP_POS: usize = 0;

    let mut heap_pos = unsafe { HEAP_POS };

    if heap_pos == 0 {
        heap_pos = unsafe { (&_end) as *const u8 as usize };
    }

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos += align - offset;
    }

    let ptr = heap_pos as *mut u8;
    let (heap_pos, overflowed) = heap_pos.overflowing_add(bytes);

    if overflowed || MAX_MEMORY < heap_pos {
        panic!("Memory limit exceeded ({MAX_MEMORY:#x})");
    }

    unsafe { HEAP_POS = heap_pos };
    ptr
}
