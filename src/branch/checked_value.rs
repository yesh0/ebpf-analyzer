use core::{cell::UnsafeCell, fmt::Debug, ops::*};

use ebpf_atomic::{Atomic, AtomicError};

use crate::{
    interpreter::value::*,
    track::{scalar::Scalar, TrackedValue},
};

#[derive(Default)]
pub struct CheckedValue(UnsafeCell<Option<TrackedValue>>);

impl CheckedValue {
    fn invalidate(&self) {
        unsafe {
            // Safe since we are single-threaded and only invalidating things
            *self.0.get() = None
        }
    }

    fn mark_as_unknown(&mut self) {
        if let Some(TrackedValue::Scalar(s)) = self.inner_mut() {
            s.mark_as_unknown();
        } else {
            self.invalidate();
        }
    }

    pub(super) fn inner(&self) -> Option<&TrackedValue> {
        unsafe { &*(self.0.get()) }.as_ref()
    }

    pub(super) fn inner_mut(&mut self) -> &mut Option<TrackedValue> {
        self.0.get_mut()
    }
}

impl From<Scalar> for CheckedValue {
    fn from(s: Scalar) -> Self {
        CheckedValue(UnsafeCell::new(Some(TrackedValue::Scalar(s))))
    }
}

impl From<TrackedValue> for CheckedValue {
    fn from(v: TrackedValue) -> Self {
        CheckedValue(UnsafeCell::new(Some(v)))
    }
}

macro_rules! unwrap_or_return {
    ($self:ident, $inners:ident) => {{
        if let (Some(ref mut v1), Some(ref v2)) = $inners {
            (v1, v2)
        } else {
            $self.invalidate();
            return;
        }
    }};
}

macro_rules! unwrap_scalars_or_return {
    ($self:ident, $v1:ident, $v2:ident) => {
        if let (TrackedValue::Scalar(s1), TrackedValue::Scalar(s2)) = ($v1, $v2) {
            (s1, s2)
        } else {
            $self.invalidate();
            return;
        }
    };
}

macro_rules! impl_scalar_only_assign_op {
    ($fn:ident) => {
        fn $fn(&mut self, rhs: &'a Self) {
            let inners = (self.inner_mut(), rhs.inner());
            let (v1, v2) = unwrap_or_return!(self, inners);
            let (s1, s2) = unwrap_scalars_or_return!(self, v1, v2);
            s1.$fn(s2);
        }
    };
}

macro_rules! impl_scalar_only_unknown_op {
    ($fn:ident) => {
        fn $fn(&mut self, rhs: &'a Self) {
            let inners = (self.inner_mut(), rhs.inner());
            let (v1, v2) = unwrap_or_return!(self, inners);
            let (s1, _) = unwrap_scalars_or_return!(self, v1, v2);
            s1.mark_as_unknown();
        }
    };
}

// Type conversion
impl Castable for CheckedValue {
    fn lower_half(&self) -> Self {
        let mut result = self.clone();
        result.lower_half_assign();
        result
    }

    fn lower_half_assign(&mut self) {
        if let Some(TrackedValue::Scalar(ref mut s)) = self.inner_mut() {
            // By marking the upper half unknown, we allow JIT / interpreters to have undefined behavior.
            s.mark_upper_half_unknown();
        } else {
            self.invalidate();
        }
    }

    fn zero_upper_half_assign(&mut self) {
        if let Some(TrackedValue::Scalar(ref mut s)) = self.inner_mut() {
            s.lower_half();
        } else {
            self.invalidate();
        }
    }
}

impl<'a> AddAssign<&'a Self> for CheckedValue {
    impl_scalar_only_assign_op!(add_assign);
}
impl<'a> SubAssign<&'a Self> for CheckedValue {
    // TODO: Support subtracting pointers of the same memory region
    impl_scalar_only_assign_op!(sub_assign);
}
impl<'a> MulAssign<&'a Self> for CheckedValue {
    impl_scalar_only_assign_op!(mul_assign);
}
impl<'a> DivAssign<&'a Self> for CheckedValue {
    impl_scalar_only_unknown_op!(div_assign);
}
impl<'a> RemAssign<&'a Self> for CheckedValue {
    impl_scalar_only_unknown_op!(rem_assign);
}
impl<'a> BitAndAssign<&'a Self> for CheckedValue {
    impl_scalar_only_assign_op!(bitand_assign);
}
impl<'a> BitOrAssign<&'a Self> for CheckedValue {
    impl_scalar_only_assign_op!(bitor_assign);
}
impl<'a> BitXorAssign<&'a Self> for CheckedValue {
    impl_scalar_only_assign_op!(bitxor_assign);
}

macro_rules! impl_checked_shift {
    ($op:ident, $self:ident, $rhs:ident, $width:expr) => {{
        debug_assert!($width == 32 || $width == 64);
        let inners = ($self.inner_mut(), $rhs.inner());
        let (v1, v2) = unwrap_or_return!($self, inners);
        let (s1, s2) = unwrap_scalars_or_return!($self, v1, v2);
        if $width == 32 {
            if let Some(value) = s2.value32() {
                s1.$op::<32>(value as u64);
            } else {
                s1.mark_as_unknown();
            }
        } else {
            if let Some(value) = s2.value64() {
                s1.$op::<64>(value);
            } else {
                s1.mark_as_unknown();
            }
        }
    }};
}

impl<'a> ShiftAssign<&'a Self> for CheckedValue {
    fn signed_shr(&mut self, rhs: &'a Self, width: u8) {
        impl_checked_shift!(ashr, self, rhs, width);
    }

    fn r_shift(&mut self, rhs: &'a Self, width: u8) {
        impl_checked_shift!(shr, self, rhs, width);
    }

    fn l_shift(&mut self, rhs: &'a Self, width: u8) {
        impl_checked_shift!(shl, self, rhs, width);
    }
}

impl NegAssign for CheckedValue {
    fn neg_assign(&mut self) {
        self.mark_as_unknown();
    }
}
impl ByteSwap for CheckedValue {
    fn host_to_le(&mut self, _width: i32) {
        self.mark_as_unknown();
    }

    fn host_to_be(&mut self, _width: i32) {
        self.mark_as_unknown();
    }
}

impl VmScalar for CheckedValue {
    fn constanti32(value: i32) -> Self {
        Self::constant64(value as i64 as u64)
    }

    fn constant64(value: u64) -> Self {
        Scalar::constant64(value as u32 as u64).into()
    }

    fn constantu32(value: u32) -> Self {
        Self::constant64(value as u64)
    }
}

impl Verifiable for CheckedValue {
    fn is_valid(&self) -> bool {
        self.inner().is_some()
    }
}

macro_rules! unwrap_pointer_or_return {
    ($self:ident, $ret:expr) => {
        if let Some(TrackedValue::Pointer(ref p)) = $self.inner() {
            p
        } else {
            $self.invalidate();
            return $ret;
        }
    };
}

impl Dereference for CheckedValue {
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self> {
        let p = unwrap_pointer_or_return!(self, None);
        let mut ptr = p.clone();
        ptr += &Scalar::constant64(offset as i64 as u64);
        match ptr.get((size / 8) as u8) {
            Ok(v) => Some(v.into()),
            Err(_) => {
                self.invalidate();
                None
            }
        }
    }

    unsafe fn set_at(&self, offset: i16, size: usize, value: &Self) -> bool {
        let inner = value.inner();
        let v = match inner {
            Some(ref v) => v,
            None => {
                self.invalidate();
                return false;
            }
        };
        let p = unwrap_pointer_or_return!(self, false);
        let mut ptr = p.clone();
        ptr += &Scalar::constant64(offset as i64 as u64);
        match ptr.set((size / 8) as u8, v) {
            Ok(()) => true,
            Err(_) => {
                self.invalidate();
                false
            }
        }
    }
}

macro_rules! unwrap_scalar_or_return {
    ($self:ident, $ret:expr) => {
        if let Some(TrackedValue::Scalar(ref s)) = $self.inner() {
            s
        } else {
            $self.invalidate();
            return $ret;
        }
    };
}

impl Atomic for CheckedValue {
    fn fetch_add(&self, offset: i16, rhs: &Self, size: usize) -> Result<CheckedValue, AtomicError> {
        if size != 32 && size != 64 {
            return Err(AtomicError::UnsupportedBitness);
        }
        let p = unwrap_pointer_or_return!(self, Err(AtomicError::IllegalAccess));
        let _ = unwrap_scalar_or_return!(rhs, Err(AtomicError::IllegalAccess));
        let mut ptr = p.clone();
        ptr += &Scalar::constant64(offset as i64 as u64);
        if ptr
            .set(size as u8, &TrackedValue::Scalar(Scalar::unknown()))
            .is_err()
        {
            Err(AtomicError::IllegalAccess)
        } else {
            Ok(Scalar::unknown().into())
        }
    }

    fn fetch_or(&self, offset: i16, rhs: &Self, size: usize) -> Result<CheckedValue, AtomicError> {
        self.fetch_add(offset, rhs, size)
    }

    fn fetch_and(&self, offset: i16, rhs: &Self, size: usize) -> Result<CheckedValue, AtomicError> {
        self.fetch_add(offset, rhs, size)
    }

    fn fetch_xor(&self, offset: i16, rhs: &Self, size: usize) -> Result<CheckedValue, AtomicError> {
        self.fetch_add(offset, rhs, size)
    }

    fn swap(&self, offset: i16, rhs: &Self, size: usize) -> Result<CheckedValue, AtomicError> {
        self.fetch_add(offset, rhs, size)
    }

    fn compare_exchange(
        &self,
        offset: i16,
        expected: &Self,
        rhs: &Self,
        size: usize,
    ) -> Result<CheckedValue, AtomicError> {
        let _ = unwrap_scalar_or_return!(expected, Err(AtomicError::IllegalAccess));
        self.fetch_add(offset, rhs, size)
    }
}

impl Clone for CheckedValue {
    fn clone(&self) -> Self {
        Self(UnsafeCell::new(self.inner().cloned()))
    }
}

impl Debug for CheckedValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.inner() {
            Some(TrackedValue::Pointer(p)) => f.write_fmt(format_args!("{:?}", p)),
            Some(TrackedValue::Scalar(s)) => f.write_fmt(format_args!("{:?}", s)),
            None => f.write_str("_"),
        }
    }
}

impl VmValue for CheckedValue {}
