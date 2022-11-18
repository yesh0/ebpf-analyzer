use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};
use ebpf_consts::STACK_SIZE;

use crate::track::{scalar::Scalar, TrackError, TrackedValue};

use super::{is_access_in_range, MemoryRegion, SafeClone};

const BIT_MAP_BYTES: usize = STACK_SIZE / 8;

#[derive(Clone, Debug)]
enum StackSlot {
    Value64(TrackedValue),
    Scalar32((Scalar, Scalar)),
}

/// A stack region, tracking aligned values
///
/// ## Storage
/// It lazily allocates space for tracking precise values.
///
/// The bitmap:
/// - `0`: Not readable, either uninitialized or pointer residue
/// - `1`: Initailized, part of a scalar or part of a pointer
///
/// Although it tries to keep values precise,
/// given that we are unaware of the machine endianness (at least not yet),
/// the precision is limited:
/// - Storage slots are 64-bit, keeping two 32-bit ones or (mutual exclusive) a precise 64-bit value.
/// - Any other unaligned read gets unknown values.
/// - Any other unaligned write sets the overlapping values to unknown.
///
/// ## Checks
///
/// - Access must be aligned.
/// - Pointer reads/writes must be aligned and of 64 bits.
/// - Reading uninitialized values is forbidden.
/// - Reading pointer residue is forbidden.
///
/// ## Slot indexing
/// <pre><code>
///     |       <-------      | V3 | V2 | V1 |
///     |  Lazily allocates                  |
/// Region Start                        Frame Pointer
/// </code></pre>
///
/// As stacks grow downwards, we use different names in the code for different "indexing" methods:
/// - `offset`: `[0, 512)`: Offset (in bytes), relative to the start of the region
/// - `index`: `[0, 64)`: Slot index, counted backwards since we allocate them lazily
///   (that is, `index = 0` is where `offset = 504`, and for `index = 63`, `offset = 0`)
/// - `fp`: Frame pointer (`offset = 512`)
#[derive(Clone, Debug)]
pub struct StackRegion {
    id: usize,
    /// The values
    ///
    /// The highest `u64` on the stack is the first value.
    values: Vec<StackSlot>,
    /// The bitmap
    ///
    /// The highest byte on the stack is mapped to the least significant bits in the first byte.
    map: [u8; BIT_MAP_BYTES],
}

impl StackRegion {
    pub fn new() -> StackRegion {
        StackRegion {
            id: 0,
            map: [0; BIT_MAP_BYTES],
            values: Vec::new(),
        }
    }

    /// Maps a on-stack byte offset into bit offset
    fn bitmap_offset(offset: usize) -> (usize, usize) {
        if offset == 0 {
            return (0, 0);
        }
        let (byte, bit) = (offset / 8, offset % 8);
        if bit == 0 {
            (byte - 1, 8)
        } else {
            (byte, bit)
        }
    }

    /// Gets the bit from the bit map
    ///
    /// Returns the bits (as the lowest two bits)
    fn is_readable(&self, start: usize, end: usize) -> bool {
        let (byte_offset, mut bit_offset) = Self::bitmap_offset(start);
        let (end_offset, end_bit_offset) = Self::bitmap_offset(end);
        for i in byte_offset..=end_offset {
            let info = self.map[i];
            let end_bit = if i == end_offset { end_bit_offset } else { 8 };
            for j in bit_offset..end_bit {
                let mask = 1u8 << j;
                if (info & mask) == 0 {
                    return false;
                }
            }
            bit_offset = 0;
        }
        true
    }

    /// Sets the bitmap
    fn mark_as_type(&mut self, start: usize, end: usize, readable: bool) {
        let (byte_offset, mut bit_offset) = Self::bitmap_offset(start);
        let (end_offset, end_bit_offset) = Self::bitmap_offset(end);
        let bit = u8::from(readable);
        for i in byte_offset..=end_offset {
            let mut info = self.map[i];
            let end_bit = if i == end_offset { end_bit_offset } else { 8 };
            for j in bit_offset..end_bit {
                let mask = 1u8 << j;
                info &= !mask;
                info |= bit << j;
            }
            bit_offset = 0;
            self.map[i] = info;
        }
    }

    /// Resizes the stack with unknown values so that `self.values[index]` does not go out of bound
    fn reserve(&mut self, index: usize) {
        if index >= self.values.len() {
            self.values.resize_with(index + 1, || {
                StackSlot::Value64(TrackedValue::Scalar(Scalar::unknown()))
            });
        }
    }

    /// Converts an offset to an index
    fn o2i(offset: usize) -> usize {
        STACK_SIZE / 8 - 1 - offset / 8
    }
}

impl Default for StackRegion {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRegion for StackRegion {
    fn get(&mut self, offset: &Scalar, size: u8) -> Result<TrackedValue, TrackError> {
        let (start, end) = is_access_in_range(offset, size, STACK_SIZE)?;
        if self.is_readable(start, end) {
            // Readable scalar
            if end - start == size as usize {
                // The pointer is precise
                if size == 8 && start % 8 == 0 {
                    let index = Self::o2i(start);
                    match &self.values[index] {
                        StackSlot::Value64(v) => Ok(v.clone()),
                        StackSlot::Scalar32(_) => Ok(TrackedValue::Scalar(Scalar::unknown())),
                    }
                } else if size == 4 && start % 4 == 0 {
                    let index = Self::o2i(start);
                    match &self.values[index] {
                        StackSlot::Value64(_) => Ok(TrackedValue::Scalar(Scalar::unknown())),
                        StackSlot::Scalar32((lower, higher)) => {
                            let mut value = if start % 8 == 0 {
                                lower.clone()
                            } else {
                                higher.clone()
                            };
                            value &= &Scalar::constant64(u32::MAX as u64);
                            Ok(TrackedValue::Scalar(value))
                        }
                    }
                } else {
                    Ok(TrackedValue::Scalar(Scalar::unknown()))
                }
            } else {
                Ok(TrackedValue::Scalar(Scalar::unknown()))
            }
        } else {
            // Pointer or unreadable values
            if end - start == 8 && start % 8 == 0 {
                let index = Self::o2i(start);
                if index < self.values.len() {
                    if let StackSlot::Value64(TrackedValue::Pointer(p)) = &self.values[index] {
                        return Ok(TrackedValue::Pointer(p.clone()))
                    }
                }
            }
            Err(TrackError::PointeeNotReadable)
        }
    }

    fn set(&mut self, offset: &Scalar, size: u8, value: &TrackedValue) -> Result<(), TrackError> {
        let (start, end) = is_access_in_range(offset, size, STACK_SIZE)?;
        if end - start == size as usize {
            // Constant offset
            match value {
                TrackedValue::Pointer(pointer) => {
                    if size == 8 && start % 8 == 0 {
                        let index = Self::o2i(start);
                        self.reserve(index);
                        self.values[index] =
                            StackSlot::Value64(TrackedValue::Pointer(pointer.clone()));
                        self.mark_as_type(start, end, false);
                        Ok(())
                    } else {
                        Err(TrackError::PointerOffsetMisaligned)
                    }
                }
                TrackedValue::Scalar(scalar) => {
                    self.mark_as_type(start, end, true);
                    if size == 8 && start % 8 == 0 {
                        let index = Self::o2i(start);
                        self.reserve(index);
                        self.values[index] =
                            StackSlot::Value64(TrackedValue::Scalar(scalar.clone()));
                    } else if size == 4 && start % 4 == 0 {
                        let index = Self::o2i(start);
                        self.reserve(index);
                        match &mut self.values[index] {
                            StackSlot::Value64(_) => {
                                self.values[index] = if start % 8 == 0 {
                                    StackSlot::Scalar32((scalar.clone(), Scalar::unknown()))
                                } else {
                                    StackSlot::Scalar32((Scalar::unknown(), scalar.clone()))
                                }
                            }
                            StackSlot::Scalar32((ref mut lower, ref mut higher)) => {
                                if start % 8 == 0 {
                                    *lower = scalar.clone();
                                } else {
                                    *higher = scalar.clone();
                                }
                            }
                        }
                    } else {
                        let start_i = Self::o2i(start);
                        let end_i = if end % 8 == 0 {
                            Self::o2i(end) - 1
                        } else {
                            Self::o2i(end)
                        };
                        self.reserve(end_i);
                        for i in start_i..=end_i {
                            self.values[i] =
                                StackSlot::Value64(TrackedValue::Scalar(Scalar::unknown()));
                        }
                    }
                    Ok(())
                }
            }
        } else {
            // Currently only aligned access is permitted
            Err(TrackError::PointerOffsetMisaligned)
        }
    }
}

impl SafeClone for StackRegion {
    fn get_id(&self) -> usize {
        self.id
    }

    fn set_id(&mut self, id: usize) {
        self.id = id
    }

    fn safe_clone(&self) -> super::Pointee {
        let c = self.clone();
        Rc::new(RefCell::new(c))
    }

    fn redirects(&mut self, mapper: &dyn Fn(usize) -> super::Pointee) {
        for ele in &mut self.values {
            if let StackSlot::Value64(TrackedValue::Pointer(p)) = ele {
                p.redirect(mapper(p.get_pointing_to()));
            }
        }
    }
}

#[cfg(test)]
use super::{
    super::pointer::{Pointer, PointerAttributes},
    empty_region::EmptyRegion,
};

#[cfg(test)]
use rand::{thread_rng, Rng};

#[test]
pub fn test_clone() {
    let mut stack = StackRegion::new();
    let offset = Scalar::constant64(512 - 4);
    assert!(stack
        .set(
            &offset,
            4,
            &TrackedValue::Scalar(Scalar::constant64(1))
        )
        .is_ok());
    match stack.get(&offset, 4) {
        Ok(TrackedValue::Scalar(s)) => assert!(s.value64().unwrap() == 1),
        _ => panic!(),
    };
    let clone = stack.safe_clone();
    match clone.borrow_mut().get(&offset, 4) {
        Ok(TrackedValue::Scalar(s)) => assert!(s.value64().unwrap() == 1),
        _ => panic!(),
    };
}

#[test]
pub fn test_stack_access() {
    let mut stack = StackRegion::new();
    for size in [1, 2, 4, 8] {
        for offset in 0..512 {
            assert!(stack.get(&Scalar::constant64(offset), size).is_err());
        }
    }
    assert!(stack
        .set(
            &Scalar::constant64(504),
            8,
            &TrackedValue::Pointer(Pointer::new(
                PointerAttributes::empty(),
                EmptyRegion::instance()
            ))
        )
        .is_ok());
    assert!(stack
        .set(
            &Scalar::constant64(496),
            8,
            &TrackedValue::Scalar(Scalar::constant64(0))
        )
        .is_ok());
    match stack.get(&Scalar::constant64(496), 8) {
        Ok(TrackedValue::Scalar(s)) => assert!(s.is_constant::<64>().unwrap_or(false)),
        _ => panic!(),
    }
    assert!(stack.get(&Scalar::constant64(500), 8).is_err());
    assert!(stack.get(&Scalar::constant64(508), 4).is_err());
    assert!(stack
        .set(
            &Scalar::constant64(504),
            4,
            &TrackedValue::Scalar(Scalar::constant64(0))
        )
        .is_ok());
    assert!(stack.get(&Scalar::constant64(508), 4).is_err());
    assert!(stack.get(&Scalar::constant64(504), 4).is_ok());
}

#[test]
pub fn test_stack_random_access() {
    const UNINIT: u8 = 0;
    const POINTER: u8 = 1;
    const SCALAR: u8 = 2;
    let sizes = [1, 2, 4, 8];
    let mut map: [u8; 512] = [UNINIT; 512];
    let mut stack = StackRegion::new();
    let mut rng = thread_rng();
    for _ in 0..100000 {
        // Randomly sets some fields
        let offset: usize = rng.gen_range(0..(512 / 8));
        for (off, ok) in [(0, true), (4, false)] {
            let pointer = rng.gen_bool(0.5);
            let value = if pointer {
                TrackedValue::Pointer(Pointer::new(
                    PointerAttributes::empty(),
                    EmptyRegion::instance(),
                ))
            } else {
                TrackedValue::Scalar(Scalar::constant64(0))
            };
            if ok || pointer {
                assert!(
                    stack
                        .set(&Scalar::constant64(offset as u64 * 8 + off), 8, &value,)
                        .is_ok()
                        == ok
                );
            }
            if ok {
                let type_info = match &value {
                    TrackedValue::Pointer(_) => POINTER,
                    TrackedValue::Scalar(_) => SCALAR,
                };
                for v in map.iter_mut().skip(offset * 8 + off as usize).take(8) {
                    *v = type_info;
                }
            }
        }

        for _ in 0..10 {
            // Random reads
            let size = sizes[rng.gen_range(0..sizes.len())];
            let offset = rng.gen_range(0..=(512 - size));
            let mut readable = true;
            let mut pointer = false;
            let mut scalar = false;
            for v in map.iter().skip(offset).take(size) {
                match *v {
                    UNINIT => readable = false,
                    POINTER => pointer = true,
                    SCALAR => scalar = true,
                    _ => panic!(),
                }
            }
            let offset = offset as u64;
            let size = size as u8;
            if readable && (pointer != scalar) {
                if pointer {
                    if size == 8 && offset % 8 == 0 {
                        assert!(stack.get(&Scalar::constant64(offset), size).is_ok());
                    } else {
                        assert!(stack.get(&Scalar::constant64(offset), size).is_err());
                    }
                } else {
                    assert!(stack.get(&Scalar::constant64(offset), size).is_ok());
                }
            } else {
                assert!(stack.get(&Scalar::constant64(offset), size).is_err());
            }
        }
    }
}
