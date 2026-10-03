//! The query indices a recorded verification drew, with their bits.
//!
//! The verifier holds a query index as an integer, which a traced value
//! cannot be.  So the transcript logs each index with the traced bits it
//! was drawn as, and the two places that use an index, the commitment's
//! path check and the domain's query point, take them from the log in the
//! order they were drawn.  Each checks that the index it was handed is the
//! one it took, so a use out of order is refused, not silently mismatched.

use core::cell::RefCell;

use p3_field::PrimeCharacteristicRing;

use crate::traced::Traced;

/// A logged index.
#[derive(Clone, Debug)]
pub struct Query {
    /// The index.
    pub index: usize,
    /// Its bits, lowest first.
    pub bits: Vec<Traced>,
}

/// The log and the position of each user in it.
#[derive(Default)]
struct Log {
    queries: Vec<Query>,
    merkle: usize,
    point: usize,
}

/// The users of a logged index.
#[derive(Clone, Copy, Debug)]
pub enum User {
    /// The commitment's path check.
    Merkle,
    /// The domain's query point.
    Point,
}

std::thread_local! {
    static LOG: RefCell<Log> = RefCell::new(Log::default());
}

/// Log a drawn index with its bits.
pub fn log(index: usize, bits: Vec<Traced>) {
    LOG.with(|log| log.borrow_mut().queries.push(Query { index, bits }));
}

/// The `width` bits of `index` for `user`, lowest first: the next draw the
/// user has not taken supplies the low bits, and the bits above it are
/// constants.  A stratified query position is a stratum above a drawn
/// offset, and the stratum is fixed by the query's place in the order, so
/// the program may hold it as a constant.
///
/// # Panics
/// Panics if the user has taken every logged draw, or if the next one is
/// not the low bits of `index`: the verifier used an index the transcript
/// did not draw, or used them out of order.
#[must_use]
pub fn take_for(user: User, index: usize, width: usize) -> Vec<Traced> {
    LOG.with(|log| {
        let mut log = log.borrow_mut();
        let position = match user {
            User::Merkle => &mut log.merkle,
            User::Point => &mut log.point,
        };
        let at = *position;
        *position += 1;
        let query = log
            .queries
            .get(at)
            .unwrap_or_else(|| panic!("{user:?} used index {index}, beyond the {at} drawn"));
        let drawn = query.bits.len();
        assert!(drawn <= width, "{user:?} reads {width} bits of a {drawn}-bit draw");
        assert_eq!(
            index & ((1usize << drawn) - 1),
            query.index,
            "{user:?} used index {index} where {} was drawn",
            query.index
        );
        let mut bits = query.bits.clone();
        bits.extend((drawn..width).map(|i| {
            if (index >> i) & 1 == 1 {
                Traced::ONE
            } else {
                Traced::ZERO
            }
        }));
        bits
    })
}

/// Take the whole log, resetting it, and return the drawn indices with how
/// many each user took.
pub fn take() -> (Vec<Query>, usize, usize) {
    LOG.with(|log| {
        let log = core::mem::take(&mut *log.borrow_mut());
        (log.queries, log.merkle, log.point)
    })
}
