use super::scalar::Scalar;

pub enum ComparisonResult<T> {
    Always,
    Never,
    Perhaps((T, T)),
}

macro_rules! comparable_ops {
    ($($name:ident),+) => {
        $(
        /// Compares the two values
        ///
        /// Depending on the comparison result, the values are modified accordingly:
        /// - `Always` / `Never`: No modification is made.
        /// - `Perhaps`: `self` and `rhs` are modified in place. Additionally we return
        ///   another pair of results.
        ///   - The first pair `(self, rhs)` ensures that:
        ///     1. The numbers are within their original range;
        ///     2. Further comparison of this kind between them will only yield `Always` or `Perhaps`.
        ///
        ///   - The returned pair ensures:
        ///     1. The numbers are within their original range;
        ///     2. Further comparison of this kind between them will only yield `Never` or `Perhaps`.
        fn $name(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self>;
        )*
    };
}

/// Compares two scalar, yielding all possible results
pub trait Comparable: Sized {
    comparable_ops!(eq, set, lt, le, slt, sle);
}

/// Passing the `le` calls to [RangePair]
///
/// Use `swap` to get a `gt` result.
/// See actual usages below to see what things are swapped.
macro_rules! yield_le {
    ($self:ident, $rhs:ident, $range:ident, $swap:expr) => {
        match $self.$range.le(&mut $rhs.$range) {
            ComparisonResult::Always => {
                if $swap {
                    ComparisonResult::Never
                } else {
                    ComparisonResult::Always
                }
            }
            ComparisonResult::Never => {
                if $swap {
                    ComparisonResult::Always
                } else {
                    ComparisonResult::Never
                }
            }
            ComparisonResult::Perhaps((gt1, gt2)) => {
                let (mut s1, mut s2) = ($self.clone(), $rhs.clone());
                if $swap {
                    s1.$range = $self.$range;
                    s2.$range = $rhs.$range;
                    $self.$range = gt1;
                    $rhs.$range = gt2;
                } else {
                    s1.$range = gt1;
                    s2.$range = gt2;
                }
                $self.sync_bounds();
                $rhs.sync_bounds();
                s1.sync_bounds();
                s2.sync_bounds();
                if $swap {
                    ComparisonResult::Perhaps((s2, s1))
                } else {
                    ComparisonResult::Perhaps((s1, s2))
                }
            }
        }
    };
}

impl Comparable for Scalar {
    fn eq(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        macro_rules! yield_eq {
            ($width:expr, $bits:expr, $rhs_bits:expr, $irange:ident, $urange:ident) => {
                if self.is_constant::<$width>().unwrap_or(false)
                    && rhs.is_constant::<$width>().unwrap_or(false)
                {
                    if $bits.value() == $rhs_bits.value() {
                        ComparisonResult::Always
                    } else {
                        ComparisonResult::Never
                    }
                } else {
                    let icommon = self.$irange.intersects(&rhs.$irange);
                    let ucommon = self.$urange.intersects(&rhs.$urange);
                    if icommon.is_valid() && ucommon.is_valid() {
                        let other = ComparisonResult::Perhaps((self.clone(), rhs.clone()));
                        self.$irange = icommon;
                        rhs.$irange = icommon;
                        self.$urange = ucommon;
                        rhs.$urange = ucommon;
                        self.sync_bounds();
                        rhs.sync_bounds();
                        other
                    } else {
                        // Must not eq
                        ComparisonResult::Never
                    }
                }
            };
        }

        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_eq!(
                32,
                self.bits.lower_half(),
                rhs.bits.lower_half(),
                irange32,
                urange32
            )
        } else {
            yield_eq!(64, self.bits, rhs.bits, irange, urange)
        }
    }

    fn set(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        macro_rules! yield_set {
            ($width:expr, $self_bits:expr, $rhs_bits:expr) => {
                {
                    let sbits = $self_bits;
                    let rbits = $rhs_bits;
                    let result = sbits & rbits;
                    if result.min() == 0 {
                        if result.max() == 0 {
                            // Constant result
                            ComparisonResult::Never
                        } else {
                            if !sbits.is_constant() && rbits.is_constant() {
                                // We can deduce more info for each branch only if either of them is constant
                                let mut other = self.clone();
                                other.bits = other.bits & !rbits;
                                other.sync_bounds();
                                if rbits.value().count_ones() == 1 {
                                    self.bits = self.bits | rbits;
                                    self.sync_bounds();
                                }
                                ComparisonResult::Perhaps((other, rhs.clone()))
                            } else if sbits.is_constant() && !rbits.is_constant() {
                                match rhs.set(self, $width) {
                                    ComparisonResult::Always => ComparisonResult::Always,
                                    ComparisonResult::Never => ComparisonResult::Never,
                                    ComparisonResult::Perhaps((s2, s1)) => ComparisonResult::Perhaps((s1, s2)),
                                }
                            } else {
                                // Nothing constant, unable to deduce anything
                                ComparisonResult::Perhaps((self.clone(), rhs.clone()))
                            }
                        }
                    } else {
                        ComparisonResult::Always
                    }
                }
            };
        }

        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_set!(32, self.bits.lower_half(), rhs.bits.lower_half())
        } else {
            yield_set!(64, self.bits, rhs.bits)
        }
    }

    fn le(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_le!(self, rhs, urange32, false)
        } else {
            yield_le!(self, rhs, urange, false)
        }
    }

    fn lt(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_le!(rhs, self, urange32, true)
        } else {
            yield_le!(rhs, self, urange, true)
        }
    }

    fn sle(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_le!(self, rhs, irange32, false)
        } else {
            yield_le!(self, rhs, irange, false)
        }
    }

    fn slt(&mut self, rhs: &mut Self, width: u8) -> ComparisonResult<Self> {
        debug_assert!(width == 32 || width == 64);
        if width == 32 {
            yield_le!(rhs, self, irange32, true)
        } else {
            yield_le!(rhs, self, irange, true)
        }
    }
}

#[test]
pub fn test_comparing_constants() {
    let (mut s1, mut s2) = (Scalar::constant64(0xFFFF00000001), Scalar::constant64(1));
    assert!(matches!(s1.eq(&mut s2, 32), ComparisonResult::Always));
    assert!(matches!(
        s1.eq(&mut Scalar::constant64(0xFFFF00000002), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(s1.eq(&mut s2, 64), ComparisonResult::Never));
    assert!(matches!(
        s2.eq(&mut Scalar::constant64(1), 64),
        ComparisonResult::Always
    ));

    assert!(matches!(s1.set(&mut s2, 32), ComparisonResult::Always));
    assert!(matches!(s1.set(&mut s2, 64), ComparisonResult::Always));
    assert!(matches!(
        s1.set(&mut Scalar::constant64(0xFFFF00000002), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(
        s1.set(&mut Scalar::constant64(0xFFFF00000002), 64),
        ComparisonResult::Always
    ));
    assert!(matches!(
        s1.set(&mut Scalar::constant64(2), 64),
        ComparisonResult::Never
    ));
}

#[test]
fn test_le_constants() {
    let (mut s1, mut s2) = (Scalar::constant64(0xFFFF00000001), Scalar::constant64(1));

    assert!(matches!(s1.le(&mut s2, 32), ComparisonResult::Always));
    assert!(matches!(s2.le(&mut s1, 32), ComparisonResult::Always));
    assert!(matches!(
        s1.le(&mut Scalar::constant64(2), 32),
        ComparisonResult::Always
    ));
    assert!(matches!(
        s1.le(&mut Scalar::constant64(0), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(s1.le(&mut s2, 64), ComparisonResult::Never));
    assert!(matches!(s2.le(&mut s1, 64), ComparisonResult::Always));
    assert!(matches!(
        s1.le(&mut Scalar::constant64(2), 64),
        ComparisonResult::Never
    ));
    assert!(matches!(
        s2.le(&mut Scalar::constant64(2), 64),
        ComparisonResult::Always
    ));

    assert!(matches!(s1.lt(&mut s2, 32), ComparisonResult::Never));
    assert!(matches!(s2.lt(&mut s1, 32), ComparisonResult::Never));
    assert!(matches!(
        s1.lt(&mut Scalar::constant64(2), 32),
        ComparisonResult::Always
    ));
    assert!(matches!(
        s1.lt(&mut Scalar::constant64(0), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(s1.lt(&mut s2, 64), ComparisonResult::Never));
    assert!(matches!(s2.lt(&mut s1, 64), ComparisonResult::Always));
    assert!(matches!(
        s1.lt(&mut Scalar::constant64(2), 64),
        ComparisonResult::Never
    ));
    assert!(matches!(
        s2.lt(&mut Scalar::constant64(2), 64),
        ComparisonResult::Always
    ));

    assert!(matches!(s1.slt(&mut s2, 32), ComparisonResult::Never));
    assert!(matches!(s2.slt(&mut s1, 32), ComparisonResult::Never));
    assert!(matches!(
        s1.slt(&mut Scalar::constant64(2), 32),
        ComparisonResult::Always
    ));
    assert!(matches!(
        s1.slt(&mut Scalar::constant64(0), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(s1.slt(&mut s2, 64), ComparisonResult::Never));
    assert!(matches!(s2.slt(&mut s1, 64), ComparisonResult::Always));
    assert!(matches!(
        s1.slt(&mut Scalar::constant64(2), 64),
        ComparisonResult::Never
    ));
    assert!(matches!(
        s2.slt(&mut Scalar::constant64(2), 64),
        ComparisonResult::Always
    ));

    assert!(matches!(s1.sle(&mut s2, 32), ComparisonResult::Always));
    assert!(matches!(s2.sle(&mut s1, 32), ComparisonResult::Always));
    assert!(matches!(
        s1.sle(&mut Scalar::constant64(2), 32),
        ComparisonResult::Always
    ));
    assert!(matches!(
        s1.sle(&mut Scalar::constant64(0), 32),
        ComparisonResult::Never
    ));
    assert!(matches!(s1.sle(&mut s2, 64), ComparisonResult::Never));
    assert!(matches!(s2.sle(&mut s1, 64), ComparisonResult::Always));
    assert!(matches!(
        s1.sle(&mut Scalar::constant64(2), 64),
        ComparisonResult::Never
    ));
    assert!(matches!(
        s2.sle(&mut Scalar::constant64(2), 64),
        ComparisonResult::Always
    ));
}

#[cfg(test)]
use super::scalar::unknown;

#[test]
fn test_ranged_scalars() {
    let mut s = unknown(8);
    assert!(s.irange32.max == 0x100);
    assert!(s.irange32.min == 0);
    s.sle(&mut unknown(7), 32);
    // Scalar s is either 0x100 or 0 according to its bit info.
    // If s < 0x80, then it has to be zero.
    assert!(s.is_constant::<32>().unwrap_or(false));

    let mut s = Scalar::unknown();
    s.slt(&mut unknown(7), 32);
    assert!(s.urange32.max == u32::MAX);
    s.lt(&mut unknown(6), 32);
    assert!(s.irange32.min == 0);

    s += &Scalar::constant64(0x100);
    assert!(matches!(s.le(&mut unknown(7), 32), ComparisonResult::Never));
    assert!(matches!(s.lt(&mut unknown(7), 32), ComparisonResult::Never));
    assert!(matches!(s.sle(&mut unknown(7), 32), ComparisonResult::Never));
    assert!(matches!(s.slt(&mut unknown(7), 32), ComparisonResult::Never));
    assert!(matches!(unknown(7).le(&mut s, 32), ComparisonResult::Always));
    assert!(matches!(unknown(7).lt(&mut s, 32), ComparisonResult::Always));
    assert!(matches!(unknown(7).sle(&mut s, 32), ComparisonResult::Always));
    assert!(matches!(unknown(7).slt(&mut s, 32), ComparisonResult::Always));

    assert!(s.irange32.min == 0x100);
    match unknown(8).slt(&mut s, 32) {
        ComparisonResult::Perhaps((s1, s2)) => {
            assert!(s.irange32.min == 0x100);
            assert!(s1.is_constant::<32>().unwrap_or(false));
            assert!(s2.is_constant::<32>().unwrap_or(false));
        }
        ComparisonResult::Always => panic!("A"),
        ComparisonResult::Never => panic!("N"),
    }
}
