//! 2D row-major shape descriptor: [`Dimensions`].
//!
//! Ziren's tensors are always 2D `[rows, cols]` row-major (that is the
//! full extent of what `Mle` / the basefold commit path needs), so we
//! use plain fixed-size `[usize; 2]` arrays rather than an `arrayvec`.
//! `strides` is carried for forward-compatibility (a future device
//! backend / non-contiguous view) but for the contiguous CPU tensors it
//! is always `[cols, 1]`.

/// Row-major 2D shape: `sizes = [rows, cols]` with `strides = [cols, 1]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dimensions {
    sizes: [usize; 2],
    strides: [usize; 2],
}

impl Dimensions {
    /// Build a contiguous row-major `[rows, cols]` shape.
    #[inline]
    pub const fn new(rows: usize, cols: usize) -> Self {
        // Row-major: advancing one row skips `cols` elements; advancing
        // one column skips 1.
        Self { sizes: [rows, cols], strides: [cols, 1] }
    }

    /// The `[rows, cols]` extents.
    #[inline]
    pub const fn sizes(&self) -> [usize; 2] {
        self.sizes
    }

    /// The `[row_stride, col_stride]` strides.
    #[inline]
    pub const fn strides(&self) -> [usize; 2] {
        self.strides
    }

    /// Total number of cells (`rows * cols`).
    #[inline]
    pub const fn total_len(&self) -> usize {
        self.sizes[0] * self.sizes[1]
    }
}
