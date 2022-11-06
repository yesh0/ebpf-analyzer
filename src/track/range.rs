use core::{ops::{AddAssign, MulAssign, SubAssign}, fmt::{Debug, LowerHex}};

use num_traits::PrimInt;

pub trait RangeItem: PrimInt + LowerHex {
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
        Self::new(value, value)
    }

    /// Creates a range
    pub fn new(start: Int, end: Int) -> RangePair<Int> {
        Self {
            min: start,
            max: end,
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

    pub fn is_valid(&self) -> bool {
        self.min <= self.max
    }

    pub fn is_constant(&self) -> bool {
        self.min == self.max
    }
}

impl<Int: RangeItem> AddAssign<&Self> for RangePair<Int> {
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

impl<Int: RangeItem> SubAssign<&Self> for RangePair<Int> {
    /// Sets the current range to a new range such that
    /// for any value `a` in the previous range and another value `b` in the `other` range,
    /// `a - b` always lies in the new range.
    fn sub_assign(&mut self, other: &Self) {
        if let Some(new_min) = self.min.checked_sub(&other.max) {
            if let Some(new_max) = self.max.checked_sub(&other.min) {
                self.min = new_min;
                self.max = new_max;
                return;
            }
        }
        self.mark_as_unknown();
    }
}

impl<Int: RangeItem> MulAssign<&Self> for RangePair<Int> {
    /// Sets the current range to a new range such that
    /// for any value `a` in the previous range and another value `b` in the `other` range,
    /// `a * b` always lies in the new range.
    fn mul_assign(&mut self, other: &Self) {
        if self.min < Int::zero() || other.min < Int::zero() {
            // Dealing with negative number multiplication is hell
            self.mark_as_unknown();
            return;
        }

        if let Some(new_max) = self.max.checked_mul(&other.max) {
            self.max = new_max;
            self.min = self.min * other.min;
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

impl<Int: RangeItem> Debug for RangePair<Int> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if Int::min_value() == Int::zero() {
            // Unsigned
            f.write_fmt(format_args!("0x{:x}..=0x{:x}", &self.min, &self.max))
        } else {
            if self.min < Int::zero() {
                f.write_fmt(format_args!("-0x{:x}", self.min.to_i64().unwrap().unsigned_abs()))?;
            } else {
                f.write_fmt(format_args!("0x{:x}", self.min))?;
            }
            f.write_str("..=")?;
            if self.max < Int::zero() {
                f.write_fmt(format_args!("-0x{:x}", self.max.to_i64().unwrap().unsigned_abs()))
            } else {
                f.write_fmt(format_args!("0x{:x}", self.max))
            }
        }
    }
}

#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
pub fn range_test() {
    let mut rng = thread_rng();
    for _ in 0..1000000 {
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

#[cfg(test)]
fn test_varied(
    ops: &[(
        fn(&mut RangePair<i32>, y: &RangePair<i32>) -> (),
        fn(i32, i32) -> i32,
    )],
) {
    use alloc::vec::Vec;

    let range_gen = || {
        let mut rng = thread_rng();
        let (i, j) = {
            let i: i32 = rng.gen();
            let j: i32 = rng.gen();
            if i > j {
                (j, i)
            } else {
                (i, j)
            }
        };
        RangePair::new(i, j)
    };

    for _ in 0..10000 {
        let r1 = range_gen();
        let r2 = range_gen();

        let results: Vec<RangePair<i32>> = ops
            .iter()
            .map(|(range_op, _)| {
                let mut result = r1.clone();
                range_op(&mut result, &r2);
                result
            })
            .collect();
        for _ in 0..1000 {
            let mut rng = thread_rng();
            let a = rng.gen_range(r1.min..=r1.max);
            let b = rng.gen_range(r2.min..=r2.max);
            for i in 0..ops.len() {
                let result = results[i];
                let value_op = ops[i].1;
                assert!(result.contains(value_op(a, b)), "{}: ({:?} op {:?}) = {:?}", i, r1, r2, result);
            }
        }
    }
}

#[test]
pub fn test_varied_operants() {
    test_varied(&[
        (|x, y| x.add_assign(y), |x, y| x.wrapping_add(y)),
        (|x, y| x.sub_assign(y), |x, y| x.wrapping_sub(y)),
        (|x, y| x.mul_assign(y), |x, y| x.wrapping_mul(y)),
    ]);
}
