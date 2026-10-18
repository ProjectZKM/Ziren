use crate::syscalls::sys_alloc_aligned;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

/// Smallest size class, `2^MIN_CLASS_LOG` bytes: room for the free-list link.
const MIN_CLASS_LOG: u32 = 3;
/// Largest recycled size class, `2^MAX_CLASS_LOG` bytes; bigger blocks bump.
const MAX_CLASS_LOG: u32 = 16;
/// The most a fresh class block is aligned to; a request asking for more bumps.
const MAX_CLASS_ALIGN: usize = 4096;
const CLASSES: usize = (MAX_CLASS_LOG - MIN_CLASS_LOG + 1) as usize;

/// A heap allocator that bumps from left to right and recycles freed small
/// blocks.
///
/// Every block of at most `2^MAX_CLASS_LOG` bytes is rounded up to a power of
/// two (its class), and a freed block goes on its class's free list for the
/// next allocation of that class to take.  A zkVM shard pays for every
/// distinct memory word it touches: a word costs a local memory event and two
/// global interactions in each shard that touches it, and one memory
/// initialize and finalize event over the whole execution.  A pure bump
/// allocator hands every allocation fresh words, so the short-lived buffers a
/// program allocates and frees over and over keep touching new memory; reusing
/// them keeps the working set, and with it those events, small.
///
/// A recycled block keeps its old contents, as `GlobalAlloc::alloc` allows;
/// `alloc_zeroed` zeroes.  A hint read writes only into untouched memory and
/// takes [`alloc_untouched`].
///
/// A fresh class block is aligned to its class size, capped at
/// `MAX_CLASS_ALIGN`, so any block of a class satisfies every alignment up to
/// that cap that a request of the class can ask for.  The guest is
/// single-threaded, so the free lists need no synchronisation.
struct SimpleAlloc {
    free: UnsafeCell<[usize; CLASSES]>,
}

unsafe impl Sync for SimpleAlloc {}

/// The size class of `layout`, if it is recycled.
fn class_of(layout: Layout) -> Option<u32> {
    if layout.align() > MAX_CLASS_ALIGN {
        return None;
    }
    let need = layout.size().max(layout.align()).max(1 << MIN_CLASS_LOG);
    let log = usize::BITS - (need - 1).leading_zeros();
    (log <= MAX_CLASS_LOG).then_some(log)
}

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(log) = class_of(layout) else {
            return sys_alloc_aligned(layout.size(), layout.align());
        };
        let head = &mut (*self.free.get())[(log - MIN_CLASS_LOG) as usize];
        if *head != 0 {
            let block = *head as *mut usize;
            *head = *block;
            return block as *mut u8;
        }
        let size = 1usize << log;
        sys_alloc_aligned(size, size.min(MAX_CLASS_ALIGN))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(log) = class_of(layout) {
            let head = &mut (*self.free.get())[(log - MIN_CLASS_LOG) as usize];
            *(ptr as *mut usize) = *head;
            *head = ptr as usize;
        }
    }
}

#[cfg(all(feature = "bump", not(feature = "embedded")))]
#[global_allocator]
static HEAP: SimpleAlloc = SimpleAlloc { free: UnsafeCell::new([0; CLASSES]) };

/// A block for `layout` that the program has never touched, which a hint read
/// needs: the executor seeds hinted words as the initial value of untouched
/// memory, so a recycled block would keep its old contents.  Shaped as a class
/// block when the layout is recycled, so freeing it later puts a block of the
/// right size on its class list.
pub(crate) unsafe fn alloc_untouched(layout: Layout) -> *mut u8 {
    match class_of(layout) {
        Some(log) => {
            let size = 1usize << log;
            sys_alloc_aligned(size, size.min(MAX_CLASS_ALIGN))
        }
        None => sys_alloc_aligned(layout.size(), layout.align()),
    }
}
