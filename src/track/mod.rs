use self::{scalar::Scalar, pointer::Pointer};

pub mod pointer;
pub mod scalar;

mod range;
mod tnum;
pub mod pointees;
pub mod comparable;

/// A `Value` implementation
#[derive(Clone)]
pub enum TrackedValue {
    /// Points, or any other special values
    Pointer(Pointer),
    /// Scalar values
    Scalar(Scalar),
}

#[derive(Debug)]
pub enum TrackError {
    PointerNullable,
    PointerOutOfBound,
    PointeeNotReadable,
    PointeeNotWritable,
    PointerOffsetMalformed,
    PointerOffsetMisaligned,
    InvalidPointer,
    ValueUninitialzed,
    InternalError,
}
