//! Event storage with an optional runtime-provided allocator.
//!
//! CPU builds retain ordinary `Vec`s. With `event-allocator`, GPU runtimes can
//! install a pinned pool before execution; allocations that do not fit the pool
//! use host memory and remain distinguishable at upload time. The wire format
//! is the same sequence format as `Vec` in both configurations.

#[cfg(not(feature = "event-allocator"))]
pub type EventVec<T> = Vec<T>;

#[cfg(feature = "event-allocator")]
pub use allocated::*;

#[cfg(feature = "event-allocator")]
mod allocated {
    use std::{
        alloc::{AllocError, Allocator, Global, Layout},
        fmt,
        ops::{Deref, DerefMut},
        ptr::NonNull,
        sync::OnceLock,
    };

    use serde::{
        de::{SeqAccess, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    };

    /// Backing storage supplied by a runtime, independent of CUDA dependencies.
    ///
    /// # Safety
    /// Successful allocations must be pinned, satisfy the requested layout, and
    /// remain valid until deallocated. The provider must support concurrent calls.
    pub unsafe trait EventMemoryProvider: Send + Sync {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError>;

        /// # Safety
        /// `ptr` and `layout` must describe an allocation from this provider.
        unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);
    }

    static PROVIDER: OnceLock<&'static dyn EventMemoryProvider> = OnceLock::new();

    /// Install the event pool before creating execution records. Existing event
    /// buffers keep their allocator, so installing a pool never changes ownership.
    pub fn install_event_memory_provider(provider: &'static dyn EventMemoryProvider) {
        assert!(PROVIDER.set(provider).is_ok(), "event memory provider already installed");
    }

    #[derive(Clone, Copy, Default)]
    struct Header {
        pinned: bool,
    }

    /// Each vector keeps the provider it was created with. A header on each
    /// allocation records whether that allocation used the pool or the host,
    /// including across growth/shrink operations and pool exhaustion.
    #[derive(Clone, Copy)]
    pub struct EventAllocator {
        provider: Option<&'static dyn EventMemoryProvider>,
    }

    impl Default for EventAllocator {
        fn default() -> Self {
            Self { provider: PROVIDER.get().copied() }
        }
    }

    impl fmt::Debug for EventAllocator {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("EventAllocator")
                .field("pool_enabled", &self.provider.is_some())
                .finish()
        }
    }

    fn allocation_layout(layout: Layout) -> Result<(Layout, usize), AllocError> {
        Layout::new::<Header>().extend(layout).map_err(|_| AllocError)
    }

    unsafe impl Allocator for EventAllocator {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
            let (base_layout, offset) = allocation_layout(layout)?;
            let (base, pinned) = match self.provider.and_then(|p| p.allocate(base_layout).ok()) {
                Some(ptr) => (ptr, true),
                None => (Global.allocate(base_layout)?, false),
            };
            let base = base.cast::<u8>();
            unsafe {
                base.cast::<Header>().as_ptr().write(Header { pinned });
                let ptr = NonNull::new_unchecked(base.as_ptr().add(offset));
                // Report exactly the requested size. A pool may return a larger
                // block, but deallocation must reconstruct the same base layout.
                Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
            }
        }

        unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
            let (base_layout, offset) = allocation_layout(layout).unwrap();
            let base = unsafe { NonNull::new_unchecked(ptr.as_ptr().sub(offset)) };
            let header = unsafe { base.cast::<Header>().as_ptr().read() };
            unsafe {
                if header.pinned {
                    self.provider.unwrap().deallocate(base, base_layout);
                } else {
                    Global.deallocate(base, base_layout);
                }
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EventVec<T>(Vec<T, EventAllocator>);

    impl<T> EventVec<T> {
        pub fn new() -> Self {
            Self(Vec::new_in(EventAllocator::default()))
        }

        pub fn with_capacity(capacity: usize) -> Self {
            Self(Vec::with_capacity_in(capacity, EventAllocator::default()))
        }

        /// Whether the current allocation can be uploaded without staging.
        pub fn is_pinned(&self) -> bool {
            if self.capacity() == 0 || std::mem::size_of::<T>() == 0 {
                return false;
            }
            let (_, offset) = allocation_layout(Layout::new::<T>()).unwrap();
            unsafe { self.as_ptr().cast::<u8>().sub(offset).cast::<Header>().read().pinned }
        }

        pub fn split_off(&mut self, at: usize) -> Self {
            Self(self.0.split_off(at))
        }

        pub fn append(&mut self, other: &mut Self) {
            self.0.append(&mut other.0);
        }
    }

    impl<T> Default for EventVec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T> Deref for EventVec<T> {
        type Target = Vec<T, EventAllocator>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T> DerefMut for EventVec<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<T> AsRef<[T]> for EventVec<T> {
        fn as_ref(&self) -> &[T] {
            &self.0
        }
    }

    impl<T> FromIterator<T> for EventVec<T> {
        fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
            let iter = iter.into_iter();
            let mut result = Self::with_capacity(iter.size_hint().0);
            result.extend(iter);
            result
        }
    }

    impl<T> Extend<T> for EventVec<T> {
        fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
            self.0.extend(iter);
        }
    }

    impl<T> From<Vec<T>> for EventVec<T> {
        fn from(vec: Vec<T>) -> Self {
            vec.into_iter().collect()
        }
    }

    impl<T> IntoIterator for EventVec<T> {
        type Item = T;
        type IntoIter = std::vec::IntoIter<T, EventAllocator>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<'a, T> IntoIterator for &'a EventVec<T> {
        type Item = &'a T;
        type IntoIter = std::slice::Iter<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut EventVec<T> {
        type Item = &'a mut T;
        type IntoIter = std::slice::IterMut<'a, T>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter_mut()
        }
    }

    impl<T: Serialize> Serialize for EventVec<T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.as_slice().serialize(serializer)
        }
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for EventVec<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct EventsVisitor<T>(std::marker::PhantomData<T>);
            impl<'de, T: Deserialize<'de>> Visitor<'de> for EventsVisitor<T> {
                type Value = EventVec<T>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a sequence of execution events")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut events =
                        EventVec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
                    while let Some(event) = seq.next_element()? {
                        events.push(event);
                    }
                    Ok(events)
                }
            }
            deserializer.deserialize_seq(EventsVisitor(std::marker::PhantomData))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

        // CUDA-free backing for allocator bookkeeping tests. These buffers are
        // never passed to a GPU; the flag stands in for a runtime's pinned pool.
        struct TestProvider {
            enabled: AtomicBool,
            live: AtomicUsize,
        }

        unsafe impl EventMemoryProvider for TestProvider {
            fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
                if !self.enabled.load(SeqCst) {
                    return Err(AllocError);
                }
                let ptr = Global.allocate(layout)?;
                self.live.fetch_add(1, SeqCst);
                Ok(ptr)
            }
            unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
                unsafe { Global.deallocate(ptr, layout) };
                self.live.fetch_sub(1, SeqCst);
            }
        }

        fn provider() -> &'static TestProvider {
            Box::leak(Box::new(TestProvider {
                enabled: AtomicBool::new(true),
                live: AtomicUsize::new(0),
            }))
        }

        #[test]
        fn pool_growth_spill_and_return_preserve_data_and_ownership() {
            let pool = provider();
            let mut events =
                EventVec(Vec::with_capacity_in(4, EventAllocator { provider: Some(pool) }));
            events.extend(0u64..4);
            assert!(events.is_pinned());
            assert_eq!(pool.live.load(SeqCst), 1);

            // Exhausting the pool during growth must free the old pool allocation
            // and remember that the new allocation belongs to the host allocator.
            pool.enabled.store(false, SeqCst);
            events.extend(4..100);
            assert!(!events.is_pinned());
            assert_eq!(pool.live.load(SeqCst), 0);
            assert_eq!(events.as_slice(), (0..100).collect::<Vec<u64>>());

            // Shrinking can move a spilled vector back into the pool.
            pool.enabled.store(true, SeqCst);
            events.truncate(3);
            events.shrink_to_fit();
            assert!(events.is_pinned());
            assert_eq!(events.as_slice(), &[0, 1, 2]);
            drop(events);
            assert_eq!(pool.live.load(SeqCst), 0);
        }

        #[test]
        fn clone_split_append_and_alignment_keep_allocators_paired() {
            #[repr(align(64))]
            #[derive(Clone, Debug, PartialEq, Eq)]
            struct Aligned(u64);
            let pool = provider();
            let mut events = EventVec(Vec::new_in(EventAllocator { provider: Some(pool) }));
            events.extend((0..16).map(Aligned));
            assert_eq!(events.as_ptr().align_offset(64), 0);
            let cloned = events.clone();
            let mut tail = events.split_off(5);
            assert!(cloned.is_pinned() && events.is_pinned() && tail.is_pinned());
            events.append(&mut tail);
            assert_eq!(events, cloned);
            drop((events, cloned, tail));
            assert_eq!(pool.live.load(SeqCst), 0);
        }

        #[test]
        fn serialization_matches_vec_and_decodes_both_ways() {
            let ordinary: Vec<u32> = (0..10_000).collect();
            let events: EventVec<u32> = ordinary.clone().into();
            assert!(!events.is_pinned());
            let bytes = bincode::serialize(&ordinary).unwrap();
            assert_eq!(bincode::serialize(&events).unwrap(), bytes);
            let decoded: EventVec<u32> = bincode::deserialize(&bytes).unwrap();
            assert_eq!(decoded.as_slice(), ordinary);
            assert_eq!(bincode::deserialize::<Vec<u32>>(&bytes).unwrap(), ordinary);
            let empty: EventVec<()> = EventVec::new();
            assert!(!empty.is_pinned());
            assert_eq!(
                bincode::serialize(&empty).unwrap(),
                bincode::serialize(&Vec::<()>::new()).unwrap()
            );
        }

        #[test]
        fn concurrent_vectors_return_every_pool_allocation() {
            let pool = provider();
            std::thread::scope(|scope| {
                for _ in 0..8 {
                    scope.spawn(|| {
                        let mut events =
                            EventVec(Vec::new_in(EventAllocator { provider: Some(pool) }));
                        events.extend(0..1024u64);
                        assert!(events.is_pinned());
                        assert_eq!(events.iter().sum::<u64>(), 1023 * 1024 / 2);
                    });
                }
            });
            assert_eq!(pool.live.load(SeqCst), 0);
        }
    }
}
