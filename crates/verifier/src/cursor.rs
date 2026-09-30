//! A bounds-checked reader for untrusted proof and verifying-key bytes.
//!
//! Every public entry point in this crate takes a caller-supplied `&[u8]` and
//! returns a `Result`, so no parse step may panic. Raw slicing (`buf[a..b]`)
//! does panic, and it is easy to reintroduce: the layouts here are long, and a
//! guard on the first few fields does not protect the reads after it.
//!
//! Reading through a cursor makes the check unavoidable rather than
//! remembered -- there is no way to advance without going through
//! [`Cursor::take`], and lengths parsed out of the buffer are consumed with
//! checked arithmetic so an attacker-controlled count cannot wrap.

use crate::error::Error;

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Consume exactly `n` bytes, or fail if the buffer is too short.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Consume `n` bytes without returning them (padding, reserved regions).
    pub(crate) fn skip(&mut self, n: usize) -> Result<(), Error> {
        self.take(n).map(|_| ())
    }

    pub(crate) fn u32_be(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64_be(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// A length field read out of the buffer itself.
    ///
    /// Rejects any count that could not possibly be backed by the remaining
    /// bytes, so a hostile `u64` cannot drive a multi-gigabyte allocation
    /// before the reads that would have failed anyway.
    pub(crate) fn count(&mut self, elem_size: usize) -> Result<usize, Error> {
        let n = self.u64_be()? as usize;
        let needed = n.checked_mul(elem_size).ok_or(Error::Truncated)?;
        if needed > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}
