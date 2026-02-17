use p3_field::Field;

/// Common interface for global lookup digests used by permutation checks.
pub trait GlobalDigest<F: Field>: Copy {
    /// The additive identity digest.
    fn zero() -> Self;

    /// Whether this digest equals the additive identity.
    fn is_zero(&self) -> bool;
}
