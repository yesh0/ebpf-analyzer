use core::{ops::{Add, Sub, Mul, Shl, Shr, BitAnd, BitOr, BitXor, Not}, fmt::Debug};

use num_traits::{Bounded, Signed, AsPrimitive};

/// A masked bit-map of a tracked value
/// 
/// The implementation mostly follows that of Linux.
/// 
/// The algorithm used:
/// - Addition, subtraction, multiplication: https://arxiv.org/abs/2105.05398
/// - Bit operations are trivil.
#[derive(Clone, Copy)]
pub struct NumBits {
    /// A mask: masked bits are unknown
    mask: u64,
    /// Known bits
    value: u64,
}

impl NumBits {
    pub fn value(self) -> u64 {
        self.value
    }

    pub fn mask(self) -> u64 {
        self.mask
    }

    pub fn min(self) -> u64 {
        self.value
    }

    pub fn max(self) -> u64 {
        self.value | self.mask
    }

    pub fn smin<Int: Bounded + Signed + AsPrimitive<u64>>(self) -> u64 {
        let sign_bit = Int::min_value().as_();
        self.value | (self.mask & sign_bit)
    }

    pub fn smax<Int: Bounded + Signed + AsPrimitive<u64>>(self) -> u64 {
        let non_sign_bits = Int::max_value().as_();
        self.value | (self.mask & non_sign_bits)
    }

    /// Tells if the value is known
    pub fn is_constant(self) -> bool {
        self.mask == 0
    }

    /// Returns an unmasked value
    pub fn exact(value: u64) -> Self {
        Self { mask: 0, value }
    }

    /// Creates an instance, ensuring masked bits in `value` are zeroed
    pub fn pruned(mask: u64, value: u64) -> Self {
        Self { mask, value: value & !mask }
    }

    /// Tells whether the bits may match the value
    pub fn contains(self, value: u64) -> bool {
        let known = !self.mask;
        (self.value & known) == (value & known)
    }

    /// Signed right-shifts the value
    pub fn ashr<const WIDTH: u8>(self, shift: u8) -> Self {
        debug_assert!(WIDTH == 32 || WIDTH == 64);
        if WIDTH == 32 {
            Self {
                mask: (self.mask as i32 >> shift) as u32 as u64,
                value: (self.value as i32 >> shift) as u32 as u64,
            }
        } else {
            Self {
                mask: (self.mask as i64 >> shift) as u64,
                value: (self.value as i64 >> shift) as u64,
            }
        }
    }

    /// Extract the common bits such that
    /// `self.contains(n) && rhs.contains(n)` leads to `self.intersects(rhs).contains(n)`
    /// 
    /// However, if `self` and `rhs` disagree on some bits, `None` is returned.
    pub fn intersects(self, rhs: Self) -> Option<Self> {
        let common_mask = !(self.mask | rhs.mask);
        if ((self.value ^ rhs.value) & common_mask) == 0 {
            let value = self.value | rhs.value;
            let mu = self.mask & rhs.mask;
            Some(Self::pruned(mu, value))
        } else {
            None
        }
    }

    /// Casts to the least significant `bytes`
    pub fn cast(self, bytes: u8) -> Self {
        let mask =  (1u64 << (bytes * 8)) - 1;
        Self { mask: self.mask & mask, value: self.value & mask }
    }

    /// Returns the lower half, with the upper half cleared
    pub fn lower_half(self) -> Self {
        self.cast(4)
    }

    /// Returns the upper half, with the lower half cleared
    pub fn upper_half(self) -> Self {
        (self >> 32) << 32
    }

    pub fn unknown() -> NumBits {
        Self { mask: u64::MAX, value: 0 }
    }

    pub fn range(min: u64, max: u64) -> NumBits {
        let chi = min ^ max;
        let bits_in_sync = chi.leading_zeros();
    
        if bits_in_sync == 0 {
            NumBits::unknown()
        } else {
            let mask = (1u64 << (64 - bits_in_sync)) - 1;
            NumBits::pruned(mask, min)
        }
    }
}

impl Shl<u8> for NumBits {
    type Output = NumBits;

    fn shl(self, rhs: u8) -> Self::Output {
        Self { mask: self.mask << rhs, value: self.value << rhs }
    }
}

impl Shr<u8> for NumBits {
    type Output = NumBits;

    /// Unsigned right shift
    fn shr(self, rhs: u8) -> Self::Output {
        Self { mask: self.mask >> rhs, value: self.value >> rhs }
    }
}

impl Add<NumBits> for NumBits {
    type Output = NumBits;

    fn add(self, rhs: NumBits) -> Self::Output {
        let sm = self.mask.wrapping_add(rhs.mask);
        let sv = self.value.wrapping_add(rhs.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | rhs.mask;
        Self::pruned(mu, sv)
    }
}

impl Sub<NumBits> for NumBits {
    type Output = NumBits;

    fn sub(self, rhs: NumBits) -> Self::Output {
        let dv = self.value.wrapping_sub(rhs.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(rhs.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | rhs.mask;
        Self::pruned(mu, dv)
    }
}

impl BitAnd<NumBits> for NumBits {
    type Output = NumBits;

    fn bitand(self, rhs: NumBits) -> Self::Output {
        let alpha = self.value | self.mask;
        let beta = rhs.value | rhs.mask;
        let value = self.value & rhs.value;
        Self { mask: alpha & beta & !value, value }
    }
}

impl BitOr<NumBits> for NumBits {
    type Output = NumBits;

    fn bitor(self, rhs: NumBits) -> Self::Output {
        let value = self.value | rhs.value;
        let mu = self.mask | rhs.mask;
        Self { mask: mu & !value, value }
    }
}

impl BitXor<NumBits> for NumBits {
    type Output = NumBits;

    fn bitxor(self, rhs: NumBits) -> Self::Output {
        let value = self.value ^ rhs.value;
        let mu = self.mask | rhs.mask;
        Self::pruned(mu, value)
    }
}

impl Not for NumBits {
    type Output = NumBits;

    fn not(self) -> Self::Output {
        Self::pruned(self.mask, !self.value)
    }
}

impl Mul<NumBits> for NumBits {
    type Output = NumBits;

    fn mul(mut self, mut rhs: NumBits) -> Self::Output {
        let acc_v = self.value.wrapping_mul(rhs.value);
        let mut acc_m = Self::exact(0);

        while self.value != 0 || self.mask != 0 {
            if (self.value & 1) != 0 {
                acc_m = acc_m.add(Self { mask: rhs.mask, value: 0 });
            } else if (self.mask & 1) != 0 {
                acc_m = acc_m.add(Self { mask: rhs.mask | rhs.value, value: 0 });
            }
            self = self >> 1;
            rhs = rhs << 1;
        }

        Self::exact(acc_v).add(acc_m)
    }
}

impl Debug for NumBits {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("(m:0x{:x},v:0x{:x})", self.mask, self.value))
    }
}

#[cfg(test)]
use rand::{Rng, thread_rng};

#[test]
pub fn track_exact_values() {
    let mut rng = thread_rng();
    for _ in 0..1000000 {
        let i = NumBits::exact(rng.gen());
        let j = NumBits::exact(rng.gen());

        let result = i + j;
        assert!(result.is_constant());
        assert!(result.value == i.value.wrapping_add(j.value));

        let result = i - j;
        assert!(result.is_constant());
        assert!(result.value == i.value.wrapping_sub(j.value));
        
        let result = i * j;
        assert!(result.is_constant());
        assert!(result.value == i.value.wrapping_mul(j.value));
        
        let result = i & j;
        assert!(result.is_constant());
        assert!(result.value == i.value & j.value);
        
        let result = i | j;
        assert!(result.is_constant());
        assert!(result.value == i.value | j.value);
        
        let result = i ^ j;
        assert!(result.is_constant());
        assert!(result.value == i.value ^ j.value);
        
        let shift = j.value as u8 & 63;
        let result = i >> shift;
        assert!(result.is_constant());
        assert!(result.value == i.value >> shift);
        
        let result = i << shift;
        assert!(result.is_constant());
        assert!(result.value == i.value << shift);
        
        let result = i.ashr::<32>(shift & 31);
        assert!(result.is_constant());
        assert!(result.value == (i.value as i32 >> (shift & 31)) as u32 as u64);

        let result = i.ashr::<64>(shift);
        assert!(result.is_constant());
        assert!(result.value == (i.value as i64 >> shift) as u64);

        assert!(i.upper_half().value == i.value & 0xFFFFFFFF00000000);
        assert!(i.lower_half().value == i.value & 0x00000000FFFFFFFF);

        assert!(i.intersects(j).is_some() == (i.value == j.value));
    }
}

#[test]
pub fn track_varied_bits() {
    let gen = |bits: NumBits| -> u64 {
        let random: u64 = thread_rng().gen();
        (bits.mask & random) | (bits.value & !bits.mask)
    };
    let new = || -> NumBits {
        let mask = thread_rng().gen();
        let value: u64 = thread_rng().gen();
        NumBits::pruned(mask, value)
    };

    for _ in 0..1000 {
        let a = new();
        let b = new();
        let result = a + b;
        for _ in 0..1000 {
            let number = gen(a).wrapping_add(gen(b));
            assert!(result.contains(number));
        }
        let result = a - b;
        for _ in 0..1000 {
            let number = gen(a).wrapping_sub(gen(b));
            assert!(result.contains(number));
        }
        let result = a * b;
        for _ in 0..1000 {
            let number = gen(a).wrapping_mul(gen(b));
            assert!(result.contains(number));
        }
        if let Some(result) = a.intersects(b) {
            for _ in 0..1000 {
                let number = gen(result);
                assert!(a.contains(number) && b.contains(number));
            }
        } else {
            let b = NumBits::pruned(a.mask | 0xFFFF, a.value);
            let result = a.intersects(b);
            assert!(result.is_some());
            let result = result.unwrap();
            for _ in 0..500 {
                let number = gen(result);
                assert!(a.contains(number) && b.contains(number));
            }
            let b = NumBits::unknown();
            let result = a.intersects(b);
            assert!(result.is_some());
            let result = result.unwrap();
            for _ in 0..500 {
                let number = gen(result);
                assert!(a.contains(number) && b.contains(number));
            }
        }
    }
}
