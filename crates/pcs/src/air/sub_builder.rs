use std::ops::Range;

use p3_air::{AirBuilder, BaseAir, WindowAccess};

/// A sub-window that only exposes a column range from a parent window.
pub struct SubWindow<W: WindowAccess<T>, T> {
    inner: W,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<T>,
}

impl<W: WindowAccess<T>, T> SubWindow<W, T> {
    /// Creates a new [`SubWindow`].
    #[must_use]
    pub fn new(inner: W, column_range: Range<usize>) -> Self {
        Self { inner, column_range, _phantom: std::marker::PhantomData }
    }
}

impl<W: WindowAccess<T> + Clone, T: Clone> Clone for SubWindow<W, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            column_range: self.column_range.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<W: WindowAccess<T>, T: Clone> WindowAccess<T> for SubWindow<W, T> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.column_range.clone()]
    }

    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.column_range.clone()]
    }
}

/// A builder used to eval a sub-air.  This will handle enforcing constraints for a subset of a
/// trace matrix.  E.g. if a particular air needs to be enforced for a subset of the columns of
/// the trace, then the [`SubAirBuilder`] can be used.
pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> {
    inner: &'a mut AB,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> SubAirBuilder<'a, AB, SubAir, T> {
    /// Creates a new [`SubAirBuilder`].
    #[must_use]
    pub fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self { inner, column_range, _phantom: std::marker::PhantomData }
    }
}

/// Implement `AirBuilder` for `SubAirBuilder`.
impl<AB: AirBuilder, SubAir: BaseAir<F>, F> AirBuilder for SubAirBuilder<'_, AB, SubAir, F> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = SubWindow<AB::MainWindow, Self::Var>;
    type PublicVar = AB::PublicVar;

    fn main(&self) -> Self::MainWindow {
        let matrix = self.inner.main();
        SubWindow::new(matrix, self.column_range.clone())
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}
