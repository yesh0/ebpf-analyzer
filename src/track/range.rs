use core::ops::{AddAssign, SubAssign, MulAssign};

use num_traits::PrimInt;

pub trait RangeItem: PrimInt {
    type Unsigned: PrimInt;
}
impl RangeItem for u32 {
    type Unsigned = u32;
}
impl RangeItem for i32 {
    type Unsigned = u32;
}
impl RangeItem for u64 {
    type Unsigned = u64;
}
impl RangeItem for i64 {
    type Unsigned = u64;
}

/// A range (inclusive)
#[derive(Clone, Copy)]
pub struct RangePair<Int: RangeItem> {
    pub min: Int,
    pub max: Int,
}

impl<Int: RangeItem> RangePair<Int> {
    /// Returns a range that contains exactly the `value`
    pub fn exact(value: Int) -> RangePair<Int> {
        Self {
            min: value,
            max: value,
        }
    }

    /// Marks that the ranges can contain anything
    pub fn mark_as_unknown(&mut self) {
        self.min = Int::min_value();
        self.max = Int::max_value();
    }

    /// Marks that the range contains exactly the `value`
    pub fn mark_as_known(&mut self, value: Int) {
        *self = Self::exact(value);
    }
}

impl <Int: RangeItem> AddAssign<&Self> for RangePair<Int> {
    /// Sets the current range to a new range such that
    /// for any value `a` in the previous range and another value `b` in the `other` range,
    /// `a + b` always lies in the new range.
    fn add_assign(&mut self, other: &Self) {
        if let Some(new_min) = self.min.checked_add(&other.min) {
            if let Some(new_max) = self.max.checked_add(&other.max) {
                self.min = new_min;
                self.max = new_max;
                return;
            }
        }
        self.mark_as_unknown();
    }
}

impl <Int: RangeItem> SubAssign<&Self> for RangePair<Int> {
    /// Sets the current range to a new range such that
    /// for any value `a` in the previous range and another value `b` in the `other` range,
    /// `a - b` always lies in the new range.
    fn sub_assign(&mut self, other: &Self) {
        if let Some(new_min) = self.min.checked_sub(&other.min) {
            if let Some(new_max) = self.max.checked_sub(&other.max) {
                self.min = new_min;
                self.max = new_max;
                return;
            }
        }
        self.mark_as_unknown();
    }
}

impl <Int: RangeItem> MulAssign<&Self> for RangePair<Int> {
    /// Sets the current range to a new range such that
    /// for any value `a` in the previous range and another value `b` in the `other` range,
    /// `a * b` always lies in the new range.
    fn mul_assign(&mut self, other: &Self) {
        if self.min < Int::min_value() || other.min < Int::min_value() {
            // Dealing with negative number multiplication is hell
            self.mark_as_unknown();
            return;
        }

        if let Some(new_max) = self.max.checked_mul(&other.max) {
            self.max = new_max;
            self.min = self.min * other.max;
            return;
        }
        self.mark_as_unknown();
    }
}

impl<Int: RangeItem> RangePair<Int> {
    pub fn contains(&self, value: Int) -> bool {
        self.min <= value && value <= self.max
    }
}

#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
pub fn range_test() {
    let mut rng = thread_rng();
    for _ in 1..1000000 {
        let i: u32 = rng.gen();
        let j: u32 = rng.gen();

        // Addition
        let mut i_range = RangePair::exact(0);
        i_range.mark_as_known(i);
        i_range += &RangePair::exact(j);
        if let Some(value) = i.checked_add(j) {
            assert!(i_range.contains(value));
            assert!(i_range.min == value);
            assert!(i_range.max == value);
        } else {
            assert!(i_range.min == u32::MIN);
            assert!(i_range.max == u32::MAX);
        }

        // Subtraction
        let mut i_range = RangePair::exact(i);
        i_range -= &RangePair::exact(j);
        if let Some(value) = i.checked_sub(j) {
            assert!(i_range.min == value);
            assert!(i_range.max == value);
        } else {
            assert!(i_range.min == u32::MIN);
            assert!(i_range.max == u32::MAX);
        }

        // Multiplication
        let mut i_range = RangePair::exact(i);
        i_range *= &RangePair::exact(j);
        if let Some(value) = i.checked_mul(j) {
            assert!(i_range.min == value);
            assert!(i_range.max == value);
        } else {
            assert!(i_range.min == u32::MIN);
            assert!(i_range.max == u32::MAX);
        }
    }
}
