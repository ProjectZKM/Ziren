use crate::lookup::LookupKind;

/// A Lookup is a cross-table lookup.
pub struct AirLookup<E> {
    /// The values of the Lookup.
    pub values: Vec<E>,
    /// The multiplicity of the Lookup.
    pub multiplicity: E,
    /// The kind of Lookup.
    pub kind: LookupKind,
}

impl<E> AirLookup<E> {
    /// Create a new [`AirLookup`].
    pub const fn new(values: Vec<E>, multiplicity: E, kind: LookupKind) -> Self {
        Self { values, multiplicity, kind }
    }
}
