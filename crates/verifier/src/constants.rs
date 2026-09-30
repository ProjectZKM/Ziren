/// Gnark (and arkworks) use the 2 most significant bits to encode the flag for a compressed
/// G1 point.
/// https://github.com/Consensys/gnark-crypto/blob/a7d721497f2a98b1f292886bb685fd3c5a90f930/ecc/bn254/marshal.go#L32-L42
pub(crate) const MASK: u8 = 0b11 << 6;

/// The flags for a positive, negative, or infinity compressed point.
pub(crate) const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
pub(crate) const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub(crate) const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompressedPointFlag {
    Positive = COMPRESSED_POSITIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

/// `MASK` keeps the top TWO bits, so a masked byte has four possible values and
/// only three of them name a flag: `0b00` is unassigned.  That byte comes
/// straight off the wire (`deserialize_with_flags` reads `buf[0] & MASK`), so
/// the conversion has to be fallible -- as an infallible `From` it panicked
/// inside a `Result`-returning verifier on a proof anyone can supply.
impl TryFrom<u8> for CompressedPointFlag {
    type Error = crate::error::Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            COMPRESSED_POSITIVE => Ok(CompressedPointFlag::Positive),
            COMPRESSED_NEGATIVE => Ok(CompressedPointFlag::Negative),
            COMPRESSED_INFINITY => Ok(CompressedPointFlag::Infinity),
            _ => Err(crate::error::Error::InvalidData),
        }
    }
}

impl From<CompressedPointFlag> for u8 {
    fn from(value: CompressedPointFlag) -> Self {
        value as u8
    }
}
