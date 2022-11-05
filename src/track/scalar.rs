use core::ops::{AddAssign, BitAndAssign, BitOrAssign, BitXorAssign, MulAssign, SubAssign};

use super::{range::RangePair, tnum::NumBits};

/// A tracked scalar, recording known bits and possible values
#[derive(Clone)]
pub struct Scalar {
    bits: NumBits,
    irange: RangePair<i64>,
    irange32: RangePair<i32>,
    urange: RangePair<u64>,
    urange32: RangePair<u32>,
}

/// Updates the irange / irange32 field for bit operations
macro_rules! bit_update_irange {
    ($self:ident, $rhs:ident, $irange:ident, $urange:ident, $itype:ident) => {
        if $self.$irange.min < 0 || $rhs.$irange.min < 0 {
            // Just don't mess around signed numbers with bit operations
            $self.$irange.mark_as_unknown();
        } else {
            // Zeroed sign bit ensured
            $self.$irange.min = $self.$urange.min as $itype;
            $self.$irange.max = $self.$urange.max as $itype;
        }
    };
}

impl Scalar {
    fn mark_as_known(&mut self, value: u64) {
        self.irange.mark_as_known(value as i64);
        self.urange.mark_as_known(value);
        self.mark_as_known32(value as u32);
    }

    fn mark_as_known32(&mut self, value: u32) {
        self.irange32.mark_as_known(value as i32);
        self.urange32.mark_as_known(value);
    }

    fn mark_as_unknown(&mut self) {
        self.irange.mark_as_unknown();
        self.irange32.mark_as_unknown();
        self.urange.mark_as_unknown();
        self.urange32.mark_as_unknown();
        self.bits = NumBits::unknown();
    }

    /// Returns `None` if the state invalid, or `Some(true_if_constant)`
    fn is_constant(&self) -> Option<bool> {
        if self.bits.is_constant() {
            if self.irange.is_constant() && self.urange.is_constant() {
                Some(true)
            } else {
                None
            }
        } else {
            if self.irange.is_valid() && self.urange.is_valid() {
                Some(false)
            } else {
                None
            }
        }
    }

    /// Sets `self` as unknown if `rhs` is not constant, returning false
    ///
    /// For operations like `self *= rhs` and `self <<= rhs`,
    /// we require that `rhs` is a constant,
    /// or else things just get complicated.
    fn require_constant(&mut self, rhs: &Self) -> bool {
        if let Some(true) = rhs.is_constant() {
            true
        } else {
            self.mark_as_unknown();
            false
        }
    }

    /// Extracts finer bounds from the bit map if possible
    fn narrow_bounds(&mut self) {
        macro_rules! extract_bounds {
            ($bits:expr, $irange:ident, $urange:ident, $itype:ident, $utype:ident) => {
                self.$irange.min = self.$irange.min.max($bits.smin::<$itype>() as $itype);
                self.$irange.max = self.$irange.max.min($bits.smax::<$itype>() as $itype);
                self.$urange.min = self.$urange.min.max($bits.min() as $utype);
                self.$urange.max = self.$urange.max.min($bits.max() as $utype);
            };
        }
        extract_bounds!(self.bits.lower_half(), irange32, urange32, i32, u32);
        extract_bounds!(self.bits, irange, urange, i64, u64);
    }

    /// Left-shifts
    /// 
    /// Unlike other operations, shift verification depends on the value width,
    /// in that it is undefined behavior to have `shift >= WIDTH`.
    pub fn shl<const WIDTH: u8>(&mut self, shift: u64) {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! adjust_urange {
            ($urange:ident, $utype:ident) => {
                let max = self.$urange.max;

                if shift >= WIDTH as u64 {
                    // Undefined shifts
                    self.$urange.mark_as_unknown();
                } else if max > (1 << (WIDTH as u64 - shift)) {
                    // Some bits are shifted off
                    self.$urange.mark_as_unknown();
                } else {
                    self.$urange.min <<= shift;
                    self.$urange.max <<= shift;
                }
            };
        }

        if WIDTH == 32 {
            adjust_urange!(urange32, u32);
            self.irange32.mark_as_unknown();
            self.irange.mark_as_unknown();
            self.urange.mark_as_unknown();
            self.bits = if shift >= WIDTH as u64 {
                NumBits::unknown()
            } else {
                (self.bits.lower_half() << (shift as u8)).lower_half()
            };
        } else {
            adjust_urange!(urange, u64);
            // Adjusts irange: special case for 32 bit shifts:
            // See comments in __scalar64_min_max_lsh in Linux for details.
            if shift == 32 {
                self.irange.max = if self.irange32.max >= 0 {
                    (self.irange32.max as i64) << 32
                } else {
                    i64::MAX
                };
                self.irange.min = if self.irange32.min >= 0 {
                    (self.irange32.min as i64) << 32
                } else {
                    i64::MIN
                };
            } else {
                self.irange.mark_as_unknown();
            }
            adjust_urange!(urange32, u64);
            self.irange32.mark_as_unknown();
            self.bits = if shift >= WIDTH as u64 {
                NumBits::unknown()
            } else {
                self.bits << (shift as u8)
            };
        }
        self.narrow_bounds();
    }

    /// Updates the irange32 field for bit operations
    fn update_irange32(&mut self, rhs: &Self) {
        bit_update_irange!(self, rhs, irange32, urange32, i32);
    }

    /// Updates the irange32 field for bit operations
    fn update_irange(&mut self, rhs: &Self) {
        bit_update_irange!(self, rhs, irange, urange, i64);
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::constant64(0)
    }
}

impl AddAssign<&Self> for Scalar {
    fn add_assign(&mut self, rhs: &Self) {
        self.bits = self.bits + rhs.bits;
        self.irange += &rhs.irange;
        self.irange32 += &rhs.irange32;
        self.urange += &rhs.urange;
        self.urange32 += &rhs.urange32;
    }
}

impl SubAssign<&Self> for Scalar {
    fn sub_assign(&mut self, rhs: &Self) {
        self.bits = self.bits - rhs.bits;
        self.irange -= &rhs.irange;
        self.irange32 -= &rhs.irange32;
        self.urange -= &rhs.urange;
        self.urange32 -= &rhs.urange32;
    }
}

impl MulAssign<&Self> for Scalar {
    fn mul_assign(&mut self, rhs: &Self) {
        if self.require_constant(rhs) {
            self.bits = self.bits * rhs.bits;
            self.irange *= &rhs.irange;
            self.irange32 *= &rhs.irange32;
            self.urange *= &rhs.urange;
            self.urange32 *= &rhs.urange32;
        }
    }
}

impl BitAndAssign<&Self> for Scalar {
    fn bitand_assign(&mut self, rhs: &Self) {
        self.bits = self.bits & rhs.bits;
        if self.bits.is_constant() {
            self.mark_as_known(self.bits.value());
            return;
        } else {
            let lower = self.bits.lower_half();
            if lower.is_constant() {
                self.mark_as_known32(lower.value() as u32);
            } else {
                // 32-bit processing, skipped if the lower part is constant
                self.urange32.min = lower.min() as u32;
                // (a & b) <= min(a, b)
                self.urange32.max = self.urange32.max.min(rhs.urange32.max);
                self.update_irange32(rhs);
            }
        }
        // 64-bit processing
        self.urange.min = self.bits.min();
        // (a & b) <= min(a, b)
        self.urange.max = self.urange.max.min(rhs.urange.max);
        self.update_irange(rhs);
        self.narrow_bounds();
    }
}

impl BitOrAssign<&Self> for Scalar {
    fn bitor_assign(&mut self, rhs: &Self) {
        if !self.require_constant(rhs) {
            return;
        }

        self.bits = self.bits | rhs.bits;
        if self.bits.is_constant() {
            self.mark_as_known(self.bits.value());
            return;
        } else {
            let lower = self.bits.lower_half();
            if lower.is_constant() {
                self.mark_as_known32(lower.value() as u32);
            } else {
                // 32-bit processing, skipped if the lower part is constant
                // max(a, b) <= (a | b)
                self.urange32.min = self.urange32.min.max(rhs.urange32.min);
                self.urange32.max = lower.max() as u32;
                self.update_irange32(rhs);
            }
        }
        // 64-bit processing
        // max(a, b) <= (a | b)
        self.urange.min = self.urange.min.max(rhs.urange.min);
        self.urange.max = self.bits.max();
        self.update_irange(rhs);
        self.narrow_bounds();
    }
}

impl BitXorAssign<&Self> for Scalar {
    fn bitxor_assign(&mut self, rhs: &Self) {
        if !self.require_constant(rhs) {
            return;
        }

        self.bits = self.bits ^ rhs.bits;
        if self.bits.is_constant() {
            self.mark_as_known(self.bits.value());
            return;
        } else {
            let lower = self.bits.lower_half();
            if lower.is_constant() {
                self.mark_as_known32(lower.value() as u32);
            } else {
                // 32-bit processing, skipped if the lower part is constant
                // max(a, b) <= (a | b)
                self.urange32.min = lower.min() as u32;
                self.urange32.max = lower.max() as u32;
                self.update_irange32(rhs);
            }
        }
        // 64-bit processing
        // max(a, b) <= (a | b)
        self.urange.min = self.bits.min();
        self.urange.max = self.bits.max();
        self.update_irange(rhs);
        self.narrow_bounds();
    }
}

impl Scalar {
    fn constant64(value: u64) -> Self {
        Scalar {
            bits: NumBits::exact(value),
            irange: RangePair::exact(value as i64),
            irange32: RangePair::exact(value as i32),
            urange: RangePair::exact(value),
            urange32: RangePair::exact(value as u32),
        }
    }
}

#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
pub fn known_value_test() {
    let mut rng = thread_rng();
    for _ in 0..1000000 {
        let i = Scalar::constant64(rng.gen());
        let j = Scalar::constant64(rng.gen());

        let mut k = i.clone();
        k += &j;
        assert!(k.bits.contains(i.bits.value().wrapping_add(j.bits.value())));
        assert!(k
            .urange
            .contains(i.bits.value().wrapping_add(j.bits.value())));
        assert!(k
            .irange
            .contains(i.bits.value().wrapping_add(j.bits.value()) as i64));

        let mut k = i.clone();
        k -= &j;
        assert!(k.bits.contains(i.bits.value().wrapping_sub(j.bits.value())));
        assert!(k
            .urange
            .contains(i.bits.value().wrapping_sub(j.bits.value())));
        assert!(k
            .irange
            .contains(i.bits.value().wrapping_sub(j.bits.value()) as i64));

        let mut k = i.clone();
        k *= &j;
        assert!(k.bits.contains(i.bits.value().wrapping_mul(j.bits.value())));
        assert!(k
            .urange
            .contains(i.bits.value().wrapping_mul(j.bits.value())));
        assert!(k
            .irange
            .contains(i.bits.value().wrapping_mul(j.bits.value()) as i64));

        let mut k = i.clone();
        k &= &j;
        assert!(k.bits.contains(i.bits.value() & j.bits.value()));
        assert!(k.urange.contains(i.bits.value() & j.bits.value()));
        assert!(k.irange.contains((i.bits.value() & j.bits.value()) as i64));

        let mut k = i.clone();
        k |= &j;
        assert!(k.bits.contains(i.bits.value() | j.bits.value()));
        assert!(k.urange.contains(i.bits.value() | j.bits.value()));
        assert!(k.irange.contains((i.bits.value() | j.bits.value()) as i64));

        let mut k = i.clone();
        k ^= &j;
        assert!(k.bits.contains(i.bits.value() ^ j.bits.value()));
        assert!(k.urange.contains(i.bits.value() ^ j.bits.value()));
        assert!(k.irange.contains((i.bits.value() ^ j.bits.value()) as i64));
    }
}

#[test]
pub fn test_shl() {
    let mut s = Scalar::constant64(0x2);
    s.shl::<32>(8);
    assert!(s.is_constant().unwrap_or(false));
    assert!(s.urange.is_constant());
    assert!(s.urange.max == 0x2 << 8);
    assert!(s.urange32.is_constant());
    assert!(s.urange32.max == 0x2 << 8);

    s.shl::<32>(70);
    assert!(!s.is_constant().unwrap_or(true));
}
