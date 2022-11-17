use core::{
    fmt::Debug,
    ops::{AddAssign, BitAndAssign, BitOrAssign, BitXorAssign, MulAssign, SubAssign},
};

use num_traits::{AsPrimitive, PrimInt};

use super::{range::RangePair, tnum::NumBits};

/// A tracked scalar, recording known bits and possible values
///
/// Supported operations are all 64-bit by default, and you should
/// want to construct 32-bit ones with [lower_half()] for example.
#[derive(Clone)]
pub struct Scalar {
    pub(super) bits: NumBits,
    pub(super) irange: RangePair<i64>,
    pub(super) irange32: RangePair<i32>,
    pub(super) urange: RangePair<u64>,
    pub(super) urange32: RangePair<u32>,
}

pub trait ShiftAssign<const WIDTH: u8, Rhs = Self> {
    fn shl_assign(&mut self, rhs: Rhs);
    fn shr_assign(&mut self, rhs: Rhs);
    fn ashr_assign(&mut self, rhs: Rhs);
}

macro_rules! impl_shift_assign {
    ($width:expr, $urange:ident) => {
        impl ShiftAssign<$width, &Self> for Scalar {
            fn shl_assign(&mut self, rhs: &Self) {
                if self.require_constant::<$width>(rhs) {
                    self.shl::<$width>(rhs.$urange.max as u64);
                }
            }

            fn shr_assign(&mut self, rhs: &Self) {
                if self.require_constant::<$width>(rhs) {
                    self.shl::<$width>(rhs.$urange.max as u64);
                }
            }

            fn ashr_assign(&mut self, rhs: &Self) {
                if self.require_constant::<$width>(rhs) {
                    self.shl::<$width>(rhs.$urange.max as u64);
                }
            }
        }
    };
}

impl_shift_assign!(32, urange32);
impl_shift_assign!(64, urange);

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

    pub fn mark_as_unknown(&mut self) {
        self.irange.mark_as_unknown();
        self.irange32.mark_as_unknown();
        self.urange.mark_as_unknown();
        self.urange32.mark_as_unknown();
        self.bits = NumBits::unknown();
    }

    pub fn mark_upper_half_unknown(&mut self) {
        self.irange.mark_as_unknown();
        self.urange.mark_as_unknown();
        self.bits = NumBits::pruned(self.bits.mask() | 0xFFFF_FFFF_0000_0000, self.bits.value())
    }

    pub fn value32(&self) -> Option<u32> {
        if self.is_constant::<32>().unwrap_or(false) {
            Some(self.urange32.max)
        } else {
            None
        }
    }

    pub fn value64(&self) -> Option<u64> {
        if self.is_constant::<64>().unwrap_or(false) {
            Some(self.urange.max)
        } else {
            None
        }
    }

    /// Returns `None` if the state invalid, or `Some(true_if_constant)`
    pub fn is_constant<const WIDTH: u8>(&self) -> Option<bool> {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! check_constant {
            ($irange:ident, $urange:ident, $bits:expr) => {
                if $bits.is_constant() {
                    if self.$irange.is_constant() && self.$urange.is_constant() {
                        Some(true)
                    } else {
                        None
                    }
                } else {
                    if self.$irange.is_valid() && self.$urange.is_valid() {
                        Some(false)
                    } else {
                        None
                    }
                }
            };
        }

        if WIDTH == 32 {
            check_constant!(irange32, urange32, self.bits.lower_half())
        } else {
            check_constant!(irange, urange, self.bits)
        }
    }

    /// Sets `self` as unknown if `rhs` is not constant, returning false
    ///
    /// For operations like `self *= rhs` and `self <<= rhs`,
    /// we require that `rhs` is a constant,
    /// or else things just get complicated.
    ///
    /// Note that the implementation of [RangePair] and [NumBits]
    /// actually supports non-constant cases judging from the tests,
    /// but we are limiting their use anyway.
    fn require_constant<const WIDTH: u8>(&mut self, rhs: &Self) -> bool {
        if let Some(true) = rhs.is_constant::<WIDTH>() {
            true
        } else {
            self.mark_as_unknown();
            false
        }
    }

    /// Returns true if irange and irange32 are of the same range
    pub fn is_signed_in_sync(&self) -> Option<(i32, i32)> {
        if self.irange32.min as i64 == self.irange.min
            && self.irange32.max as i64 == self.irange.max
        {
            Some((self.irange32.min, self.irange32.max))
        } else {
            None
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

    /// Deduce info from between `iranges and uranges`
    ///
    /// If we somehow know that the possible values are all of the same sign,
    /// then `iranges` and `uranges` share the same bounds.
    fn sync_sign_bounds(&mut self) {
        macro_rules! sync_range_bounds {
            ($irange:ident, $urange:ident, $itype:ident, $utype:ident) => {
                if self.$irange.min >= 0 || self.$irange.max < 0 {
                    // All possible values are of the same sign,
                    // and signed/unsigned values are directly comparable.
                    let min = self.$urange.min.max(self.$irange.min as $utype);
                    let max = self.$urange.max.min(self.$irange.max as $utype);
                    self.$urange = RangePair::new(min, max);
                    self.$irange = RangePair::new(min as $itype, max as $itype);
                } else {
                    if self.$urange.max as $itype >= 0 {
                        // All positive
                        self.$urange.max = self.$urange.max.min(self.$irange.max as $utype);
                        self.$irange =
                            RangePair::new(self.$urange.min as $itype, self.$urange.max as $itype);
                    } else if (self.$urange.min as $itype) < 0 {
                        // All negative
                        self.$urange.min = self.$urange.min.max(self.$irange.min as $utype);
                        self.$irange =
                            RangePair::new(self.$urange.min as $itype, self.$urange.max as $itype);
                    }
                }
            };
        }
        sync_range_bounds!(irange32, urange32, i32, u32);
        sync_range_bounds!(irange, urange, i64, u64);
    }

    /// Syncs bits using range info
    ///
    /// TODO: Replace `unreachable` with less aggressive error reporting.
    fn sync_bits(&mut self) {
        if let Some(bits) = self
            .bits
            .intersects(NumBits::range(self.urange.min, self.urange.max))
        {
            if let Some(bits32) = self.bits.lower_half().intersects(NumBits::range(
                self.urange32.min as u64,
                self.urange32.max as u64,
            )) {
                self.bits = bits.upper_half() | bits32;
            } else {
                unreachable!(
                    "Ranges and bits are out of sync: {:?} {:?}",
                    self.bits, self.urange32
                );
            }
        } else {
            unreachable!(
                "Ranges and bits are out of sync: {:?} {:?}",
                self.bits, self.urange
            );
        }
    }

    /// Syncs between `iranges`, `uranges` and most importantly `bits`
    ///
    /// This function must be called to sync the sign bit info between
    /// `iranges` and `bits` after changes in the sign bit.
    pub(super) fn sync_bounds(&mut self) {
        self.narrow_bounds();
        self.sync_sign_bounds();
        self.sync_bits();
        self.narrow_bounds();
    }

    /// Left-shifts
    ///
    /// Unlike other operations, shift verification depends on the value width,
    /// in that it is undefined behavior to have `shift >= WIDTH`.
    pub fn shl<const WIDTH: u8>(&mut self, shift: u64) {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! adjust_urange {
            ($urange:ident, $width:expr) => {
                let max = self.$urange.max;

                if shift >= $width as u64 {
                    // Undefined shifts
                    self.$urange.mark_as_unknown();
                } else if max > (1 << ($width as u64 - shift)) {
                    // Some bits are shifted off
                    self.$urange.mark_as_unknown();
                } else {
                    self.$urange.min <<= shift;
                    self.$urange.max <<= shift;
                }
            };
        }

        // 1. Adjusts irange, irange32, urange, urange32;
        // 2. Adjusts bits.
        if WIDTH == 32 {
            self.irange.mark_as_unknown();
            self.irange32.mark_as_unknown();
            self.urange.mark_as_unknown();
            adjust_urange!(urange32, 32);
            self.bits = if shift >= WIDTH as u64 {
                NumBits::unknown()
            } else {
                (self.bits.lower_half() << (shift as u8)).lower_half()
            };
        } else {
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
            self.irange32.mark_as_unknown();
            adjust_urange!(urange, 64);
            adjust_urange!(urange32, 32);
            self.bits = if shift >= WIDTH as u64 {
                NumBits::unknown()
            } else {
                self.bits << (shift as u8)
            };
        }
        self.sync_bounds();
    }

    /// Right-shifts (unsigned)
    ///
    /// See [shl].
    pub fn shr<const WIDTH: u8>(&mut self, shift: u64) {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! update_urange {
            ($urange:ident, $bits:expr) => {
                if shift >= WIDTH as u64 {
                    self.$urange.mark_as_unknown();
                    self.bits = NumBits::unknown();
                } else {
                    self.$urange.min >>= shift;
                    self.$urange.max >>= shift;
                    self.bits = $bits >> shift as u8;
                }
            };
        }

        if WIDTH == 32 {
            self.irange.mark_as_unknown();
            self.irange32.mark_as_unknown();
            self.urange.mark_as_unknown();
            update_urange!(urange32, self.bits.lower_half());
        } else {
            self.irange.mark_as_unknown();
            self.irange32.mark_as_unknown();
            update_urange!(urange, self.bits);
            self.urange32.mark_as_unknown();
        }
        self.sync_bounds();
    }

    /// Right-shifts (sign bit extending)
    ///
    /// See [shl].
    pub fn ashr<const WIDTH: u8>(&mut self, shift: u64) {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! update_irange {
            ($irange:ident) => {
                if shift >= WIDTH as u64 {
                    self.$irange.mark_as_unknown();
                    self.bits = NumBits::unknown();
                } else {
                    self.$irange.min >>= shift;
                    self.$irange.max >>= shift;
                    self.bits = self.bits.ashr::<WIDTH>(shift as u8);
                }
            };
        }

        if WIDTH == 32 {
            update_irange!(irange32);
            self.irange.mark_as_unknown();
            self.urange32.mark_as_unknown();
            self.urange.mark_as_unknown();
        } else {
            self.irange32.mark_as_unknown();
            update_irange!(irange);
            self.urange32.mark_as_unknown();
            self.urange.mark_as_unknown();
        }
        self.sync_bounds();
    }

    pub fn lower_half(&mut self) {
        self.bits = self.bits.lower_half();
        self.irange.mark_as_unknown();
        self.irange.min = 0;
        self.urange.min = self.urange32.min as u64;
        self.urange.max = self.urange32.max as u64;
        self.sync_bounds();
    }

    /// Updates the irange/irange32 field for bit operations (`and`, `or` and `xor`)
    fn update_irange<const WIDTH: u8>(&mut self, rhs: &Self) {
        debug_assert!(WIDTH == 32 || WIDTH == 64);

        macro_rules! bit_update_irange {
            ($self:ident, $rhs:ident, $irange:ident, $urange:ident, $itype:ident) => {
                if $self.$irange.min < 0 || $rhs.$irange.min < 0 {
                    // Just don't mess around signed numbers with bit operations
                    $self.$irange.mark_as_unknown();
                } else {
                    // Zeroed sign bit ensured
                    debug_assert!(
                        $self.$urange.min as $itype >= 0,
                        "0x{:x}: 0x{:x}, 0x{:x}",
                        $self.$urange.min,
                        $self.$irange.min,
                        $rhs.$irange.min
                    );
                    debug_assert!(
                        $self.$urange.max as $itype >= 0,
                        "0x{:x}: 0x{:x}, 0x{:x}",
                        $self.$urange.max,
                        $self.$irange.min,
                        $rhs.$irange.min
                    );
                    $self.$irange.min = $self.$urange.min as $itype;
                    $self.$irange.max = $self.$urange.max as $itype;
                }
            };
        }

        if WIDTH == 32 {
            bit_update_irange!(self, rhs, irange32, urange32, i32);
        } else {
            bit_update_irange!(self, rhs, irange, urange, i64);
        }
    }

    pub fn unknown() -> Scalar {
        let mut result = Scalar::constant64(0);
        result.mark_as_unknown();
        result
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::constant64(0)
    }
}

pub trait NegAssign {
    /// `self = -self`
    fn neg_assign(&mut self);
}

impl NegAssign for Scalar {
    fn neg_assign(&mut self) {
        self.mark_as_unknown();
    }
}

pub trait SwapAssign {
    /// `self = byte/word/dword_swap(self)`
    fn swap_assign(&mut self, width: u8);
}

impl SwapAssign for Scalar {
    fn swap_assign(&mut self, _: u8) {
        self.mark_as_unknown();
    }
}

impl AddAssign<&Self> for Scalar {
    fn add_assign(&mut self, rhs: &Self) {
        self.bits = self.bits + rhs.bits;
        self.irange += &rhs.irange;
        self.irange32 += &rhs.irange32;
        self.urange += &rhs.urange;
        self.urange32 += &rhs.urange32;
        self.sync_bounds();
    }
}

impl SubAssign<&Self> for Scalar {
    fn sub_assign(&mut self, rhs: &Self) {
        self.bits = self.bits - rhs.bits;
        self.irange -= &rhs.irange;
        self.irange32 -= &rhs.irange32;
        self.urange -= &rhs.urange;
        self.urange32 -= &rhs.urange32;
        self.sync_bounds();
    }
}

impl MulAssign<&Self> for Scalar {
    fn mul_assign(&mut self, rhs: &Self) {
        if self.require_constant::<64>(rhs) {
            self.bits = self.bits * rhs.bits;
            self.irange *= &rhs.irange;
            self.irange32 *= &rhs.irange32;
            self.urange *= &rhs.urange;
            self.urange32 *= &rhs.urange32;
            self.sync_bounds();
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
                self.update_irange::<32>(rhs);
            }
        }
        // 64-bit processing
        self.urange.min = self.bits.min();
        // (a & b) <= min(a, b)
        self.urange.max = self.urange.max.min(rhs.urange.max);
        self.update_irange::<64>(rhs);
        self.sync_bounds();
    }
}

impl BitOrAssign<&Self> for Scalar {
    fn bitor_assign(&mut self, rhs: &Self) {
        if !self.require_constant::<64>(rhs) {
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
                self.update_irange::<32>(rhs);
            }
        }
        // 64-bit processing
        // max(a, b) <= (a | b)
        self.urange.min = self.urange.min.max(rhs.urange.min);
        self.urange.max = self.bits.max();
        self.update_irange::<64>(rhs);
        self.sync_bounds();
    }
}

impl BitXorAssign<&Self> for Scalar {
    fn bitxor_assign(&mut self, rhs: &Self) {
        if !self.require_constant::<64>(rhs) {
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
                self.update_irange::<32>(rhs);
            }
        }
        // 64-bit processing
        // max(a, b) <= (a | b)
        self.urange.min = self.bits.min();
        self.urange.max = self.bits.max();
        self.update_irange::<64>(rhs);
        self.sync_bounds();
    }
}

impl Scalar {
    pub fn constant64(value: u64) -> Self {
        Scalar {
            bits: NumBits::exact(value),
            irange: RangePair::exact(value as i64),
            irange32: RangePair::exact(value as i32),
            urange: RangePair::exact(value),
            urange32: RangePair::exact(value as u32),
        }
    }

    pub fn contains<
        Int: PrimInt + AsPrimitive<i64> + AsPrimitive<u64> + AsPrimitive<i32> + AsPrimitive<u32>,
    >(
        &self,
        value: Int,
    ) -> bool {
        let width = Int::zero().count_zeros();
        if width == 32 {
            self.bits
                .lower_half()
                .contains(AsPrimitive::<u32>::as_(value) as u64)
                && if Int::min_value() == Int::zero() {
                    // u32
                    self.urange32.contains(value.as_())
                } else {
                    // i32
                    self.irange32.contains(value.as_())
                }
        } else {
            self.bits.contains(value.as_())
                && (if Int::min_value() == Int::zero() {
                    // u64
                    self.urange.contains(value.as_())
                } else {
                    // i64
                    self.irange.contains(value.as_())
                })
        }
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scalar")
            .field("bits", &self.bits)
            .field("irange", &self.irange)
            .field("irange32", &self.irange32)
            .field("urange", &self.urange)
            .field("urange32", &self.urange32)
            .finish()
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

#[cfg(test)]
pub fn unknown(shift: u8) -> Scalar {
    if shift == 31 {
        Scalar {
            bits: NumBits::pruned(1 << shift, 0),
            irange: RangePair::new(0, 1 << shift),
            irange32: RangePair::new(i32::MIN, 0),
            urange: RangePair::new(0, 1 << shift),
            urange32: RangePair::new(0, 1u32.wrapping_shl(shift as u32)),
        }
    } else {
        Scalar {
            bits: NumBits::pruned(1 << shift, 0),
            irange: RangePair::new(0, 1 << shift),
            irange32: RangePair::new(0, 1i32.wrapping_shl(shift as u32)),
            urange: RangePair::new(0, 1 << shift),
            urange32: RangePair::new(0, 1u32.wrapping_shl(shift as u32)),
        }
    }
}

#[cfg(test)]
fn assert_unknown(s: &Scalar) {
    assert!(s.bits.min() == 0);
    assert!(s.bits.max() == u64::MAX);
    assert!(s.irange.min == i64::MIN);
    assert!(s.irange.max == i64::MAX);
    assert!(s.irange32.min == i32::MIN);
    assert!(s.irange32.max == i32::MAX);
    assert!(s.urange.min == u64::MIN);
    assert!(s.urange.max == u64::MAX);
    assert!(s.urange32.min == u32::MIN);
    assert!(s.urange32.max == u32::MAX);
}

#[test]
pub fn test_unknown() {
    let un = unknown(2);
    let s = Scalar::constant64(1);

    let mut result = s.clone();
    result *= &un;
    assert_unknown(&result);

    let mut result = s.clone();
    result |= &un;
    assert_unknown(&result);

    let mut result = s.clone();
    result ^= &un;
    assert_unknown(&result);

    let mut result = s.clone();
    ShiftAssign::<32, &Scalar>::shl_assign(&mut result, &un);
    assert_unknown(&result);
    let mut result = s.clone();
    ShiftAssign::<32, &Scalar>::shr_assign(&mut result, &un);
    assert_unknown(&result);
    let mut result = s.clone();
    ShiftAssign::<32, &Scalar>::ashr_assign(&mut result, &un);
    assert_unknown(&result);

    let mut result = s.clone();
    ShiftAssign::<64, &Scalar>::shl_assign(&mut result, &un);
    assert_unknown(&result);
    let mut result = s.clone();
    ShiftAssign::<64, &Scalar>::shr_assign(&mut result, &un);
    assert_unknown(&result);
    let mut result = s.clone();
    ShiftAssign::<64, &Scalar>::ashr_assign(&mut result, &un);
    assert_unknown(&result);
}

#[test]
pub fn test_shl() {
    let mut s = Scalar::constant64(0x2);
    s.shl::<32>(8);
    assert!(s.is_constant::<32>().unwrap_or(false));
    assert!(s.urange.is_constant());
    assert!(s.urange.max == 0x2 << 8);
    assert!(s.urange32.is_constant());
    assert!(s.urange32.max == 0x2 << 8);

    s.shl::<32>(70);
    assert!(!s.is_constant::<64>().unwrap_or(true));
}

#[cfg(test)]
fn assert_contains(s: &Scalar, b: &Scalar, value: i32, op: i32, prev: Scalar) {
    assert!(
        s.bits.lower_half().contains(value as u32 as u64),
        "Expecting 0x{:x} in {:?}",
        value,
        s.bits.lower_half()
    );
    assert!(
        s.irange32.contains(value),
        "Assertion failed after #{:}: {:?}({:?}) op {:?} -> {:?}({:?}): 0x{:x}",
        op,
        prev.irange32,
        prev.bits,
        b.irange32,
        s.irange32,
        s.bits,
        value
    );
    assert!(s.contains(value));
}

#[test]
pub fn test_random_ops() {
    for _ in 0..200000 {
        let mut result: i32 = thread_rng().gen();
        let mut a = Scalar::constant64(result as u32 as u64);
        let limit = thread_rng().gen_range(0..100);
        for _ in 0..limit {
            let (b, rhs) = if thread_rng().gen_bool(0.3) {
                let shift = thread_rng().gen_range(0..48);
                (unknown(shift), 1 << shift)
            } else {
                let rhs: u64 = thread_rng().gen();
                (Scalar::constant64(rhs), rhs)
            };

            let op = thread_rng().gen_range(0..10);
            let prev = a.clone();
            match op {
                0 => {
                    a.lower_half();
                }
                1 => {
                    a += &b;
                    result = result.wrapping_add(rhs as i32);
                }
                2 => {
                    a -= &b;
                    result = result.wrapping_sub(rhs as i32);
                }
                3 => {
                    a *= &b;
                    result = result.wrapping_mul(rhs as i32);
                }
                4 => {
                    a &= &b;
                    result &= rhs as i32;
                }
                5 => {
                    a |= &b;
                    result |= rhs as i32;
                }
                6 => {
                    a ^= &b;
                    result ^= rhs as i32;
                }
                7 => {
                    ShiftAssign::<32, &Scalar>::shl_assign(&mut a, &b);
                    result = result.wrapping_shl(rhs.max(u32::MAX as u64) as u32);
                }
                8 => {
                    ShiftAssign::<32, &Scalar>::shr_assign(&mut a, &b);
                    result = (result as u32).wrapping_shr(rhs.max(u32::MAX as u64) as u32) as i32;
                }
                9 => {
                    ShiftAssign::<32, &Scalar>::ashr_assign(&mut a, &b);
                    result = result.wrapping_shr(rhs.max(u32::MAX as u64) as u32);
                }
                _ => {}
            }

            assert_contains(&a, &b, result, op, prev);
        }
    }
}

#[cfg(test)]
extern crate std;

#[test]
pub fn test() {
    //std::println!("{}: {:?}, {:?}, {:?}, {:?}, {:?}: 0x{:x}", op, prev.bits, prev.irange, prev.urange, prev.irange32, prev.urange32, rhs);

    let b = Scalar::constant64(0x964cc655da44d553);

    let mut s = Scalar {
        bits: NumBits::pruned(0xfffffffc00080000, 0),
        irange: RangePair::new(-0x400000000, 0x80000),
        irange32: RangePair::new(0, 0x80000),
        urange: RangePair::new(0, 0xfffffffc00080000),
        urange32: RangePair::new(0, 0x80000),
    };

    s -= &b;
    s.narrow_bounds();
    std::println!("{:?} {:?} {:?}", s.bits, s.irange, s.urange);

    s.sync_sign_bounds();
    std::println!("{:?} {:?} {:?}", s.bits, s.irange, s.urange);
    std::println!(
        "{:?}",
        s.bits
            .intersects(NumBits::range(s.urange.min, s.urange.max))
    );
    s.sync_bits();
    std::println!("{:?} {:?} {:?}", s.bits, s.irange, s.urange);
}
