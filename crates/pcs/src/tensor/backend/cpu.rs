//! Part of the Ziren backend-generic tensor stack. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use std::{
    alloc::Layout,
    any::Any,
    collections::BTreeMap,
    ptr::{self, NonNull},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, RwLock,
    },
};

use serde::{Deserialize, Serialize};

use crate::tensor::{
    mem::{CopyDirection, CopyError, DeviceMemory},
    AllocError, Allocator,
};

use super::{Backend, GlobalBackend};

pub const GLOBAL_CPU_BACKEND: CpuBackend = CpuBackend;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct CpuBackend;

impl GlobalBackend for CpuBackend {
    fn global() -> &'static Self {
        &GLOBAL_CPU_BACKEND
    }
}

unsafe impl Allocator for CpuBackend {
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        let ptr = std::alloc::alloc(layout);
        Ok(NonNull::slice_from_raw_parts(NonNull::new_unchecked(ptr), layout.size()))
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // A buffer over FOREIGN storage (see `foreign_region_attach`) releases
        // its reference to the region; the global allocator never saw it.
        if FOREIGN_LIVE.load(Ordering::Acquire) != 0 && foreign_release(ptr.as_ptr() as usize) {
            return;
        }
        std::alloc::dealloc(ptr.as_ptr(), layout);
    }
}

/// FOREIGN STORAGE — memory a `Buffer<T, CpuBackend>` points into but does not
/// own: a shared, read-only mapping such as a proving key's traces in
/// `/dev/shm`, mapped by every prover process on the host so that N workers
/// hold ONE copy instead of N.  A region is registered once with a keepalive
/// (the mapping itself, as `Arc<dyn Any>`); every buffer created over it
/// holds a reference, `CpuBackend::deallocate` gives it back, and the
/// mapping drops with the last one.
///
/// The lookup is on the dealloc path of every CPU buffer, so it costs one
/// relaxed atomic load while no region is registered, and a read lock plus a
/// `BTreeMap::range` when one is.
struct ForeignRegion {
    end: usize,
    refs: usize,
    keepalive: Arc<dyn Any + Send + Sync>,
}

static FOREIGN_LIVE: AtomicUsize = AtomicUsize::new(0);
static FOREIGN: LazyLock<RwLock<BTreeMap<usize, ForeignRegion>>> = LazyLock::new(Default::default);

/// Register `[start, start + len)` as foreign storage (or add a reference to
/// a region that already covers it).  Called by `Buffer::from_foreign`.
pub fn foreign_region_attach(start: usize, len: usize, keepalive: Arc<dyn Any + Send + Sync>) {
    let mut map = FOREIGN.write().expect("foreign region registry");
    if let Some((&rs, region)) = map.range_mut(..=start).next_back() {
        if start >= rs && start + len <= region.end {
            region.refs += 1;
            return;
        }
    }
    assert!(
        map.range(start..start + len).next().is_none(),
        "foreign region [{start:#x}, {:#x}) overlaps a registered one",
        start + len
    );
    map.insert(start, ForeignRegion { end: start + len, refs: 1, keepalive });
    FOREIGN_LIVE.fetch_add(1, Ordering::AcqRel);
}

/// Whether `ptr` lies inside a registered foreign region.
pub fn is_foreign(ptr: usize) -> bool {
    if FOREIGN_LIVE.load(Ordering::Acquire) == 0 {
        return false;
    }
    let map = FOREIGN.read().expect("foreign region registry");
    map.range(..=ptr).next_back().is_some_and(|(_, r)| ptr < r.end)
}

/// Release one reference to the region holding `ptr`; the last reference
/// drops the region and its keepalive.  `false` if `ptr` is not foreign.
fn foreign_release(ptr: usize) -> bool {
    let mut map = FOREIGN.write().expect("foreign region registry");
    let Some((&start, region)) = map.range_mut(..=ptr).next_back() else { return false };
    if ptr >= region.end {
        return false;
    }
    region.refs -= 1;
    if region.refs == 0 {
        map.remove(&start);
        FOREIGN_LIVE.fetch_sub(1, Ordering::AcqRel);
    }
    true
}

impl DeviceMemory for CpuBackend {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        _direction: CopyDirection,
    ) -> Result<(), CopyError> {
        src.copy_to_nonoverlapping(dst, size);
        Ok(())
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        dst.write_bytes(value, size);
        Ok(())
    }
}

unsafe impl Backend for CpuBackend {}
