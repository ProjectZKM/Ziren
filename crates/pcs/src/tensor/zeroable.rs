//! Which element types may be produced by writing bytes rather than by
//! constructing a value.
//!
//! Allocating memory and declaring it initialized is only sound when the byte
//! pattern written is a valid value of the element type. `Copy` is not that
//! property: `bool`, `char`, `NonZeroU8` and every enum are `Copy`, and none of
//! them admits an arbitrary byte pattern. `Copy` says a byte-wise DUPLICATE of
//! an existing valid value is itself valid; it says nothing about a pattern no
//! value ever had.
//!
//! So the two are separate obligations, and only the second needs a marker
//! here: duplication is already expressed by `T: Copy`.

/// Element types for which the all-zero byte pattern is a valid value.
///
/// # Safety
///
/// `[0u8; size_of::<Self>()]` must be a valid `Self`. In particular `Self` may
/// not be a type with a niche that excludes zero (`NonZero*`, `&T`, a `bool`
/// is fine because `0` is `false`, an enum only if a zero discriminant exists),
/// and every field of an aggregate must itself satisfy this.
///
/// Implementors do not additionally promise that ARBITRARY byte patterns are
/// valid — only the zero one — so this licenses zeroing and nothing else.
pub unsafe trait Zeroable: Copy + 'static {}

macro_rules! zeroable_primitives {
    ($($t:ty)*) => { $( unsafe impl Zeroable for $t {} )* };
}

// Integers and floats: every bit pattern is a value, so zero is in particular.
zeroable_primitives! { u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize f32 f64 }

// KoalaBear is a single `u32` field element held below the modulus; the zero
// word is the additive identity, so zeroing yields the zero polynomial rather
// than an out-of-range representative.
unsafe impl Zeroable for p3_koala_bear::KoalaBear {}

// An array is zeroable exactly when its element is: `[T; N]` has no padding
// beyond `T`'s own.
unsafe impl<T: Zeroable, const N: usize> Zeroable for [T; N] {}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    /// Only callable for a `T` that declares the all-zero pattern valid, so
    /// this both exercises the bound and is the operation the bound licenses:
    /// `T: Zeroable` is exactly the promise that `mem::zeroed()` is a valid `T`.
    fn zeroed<T: Zeroable>() -> T {
        unsafe { core::mem::zeroed() }
    }

    /// The property the trait asserts, for the field element that motivates it:
    /// zeroed bytes must read back as the additive identity.
    #[test]
    fn zeroed_bytes_are_the_additive_identity() {
        let z: p3_koala_bear::KoalaBear = zeroed();
        assert_eq!(z, p3_koala_bear::KoalaBear::ZERO);

        let z_array: [p3_koala_bear::KoalaBear; 4] = zeroed();
        assert_eq!(z_array, [p3_koala_bear::KoalaBear::ZERO; 4]);
    }
}
