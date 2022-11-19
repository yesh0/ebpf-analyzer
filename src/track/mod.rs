//! This modules contains all kinds of structs and traits for tracking values.

use self::{scalar::Scalar, pointer::Pointer};

pub mod pointer;
pub mod scalar;

mod range;
mod tnum;
pub mod pointees;
pub mod comparable;

/// A `Value` implementation
#[derive(Clone, Debug)]
pub enum TrackedValue {
    /// Points, or any other special values
    Pointer(Pointer),
    /// Scalar values
    Scalar(Scalar),
}

impl From<Scalar> for TrackedValue {
    fn from(value: Scalar) -> Self {
        Self::Scalar(value)
    }
}

/// Error during tracking
#[derive(Debug)]
pub enum TrackError {
    /// Deferencing a nullable pointer
    PointerNullable,
    /// Deference out of bound
    PointerOutOfBound,
    /// Reading from a non readable region
    PointeeNotReadable,
    /// Writing to a non writable region
    PointeeNotWritable,
    /// Some pointer operations require a constant offset
    PointerOffsetMalformed,
    /// Some pointer operations require an aligned offset
    PointerOffsetMisaligned,
    /// General pointer error
    InvalidPointer,
    /// Reading / using an uninitialized value
    ValueUninitialzed,
    /// Internal error
    InternalError,
}
