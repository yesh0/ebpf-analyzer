use alloc::vec::Vec;

use crate::track::{pointer::Pointer, scalar::Scalar, TrackError, TrackedValue};

use super::{is_access_in_range, PointedValue};

/// A memory region of a struct instance
///
/// It does not support structs larger than `i32::MAX` or those with more than `i8::MAX` pointers.
///
/// The following checks are done:
/// - Reads:
///   - Pointer reads must be aligned
///   - Scalar reads are not checked
/// - Writes:
///   - Writing to a pointer field is forbidden
///   - Scalar writes are not checked
///
/// It contains a byte-map of the region. For each byte:
/// - `N > 0` means that it is part of a pointer of the index `N`
/// - `0` means that it is part of a scalar value
/// - `-1` means that it is read-only
/// - `-2` means that it is write-only
/// 
/// Currently, it represents a struct known at compile time,
/// and requires a `'static` slice representing its structure.
pub struct StructRegion {
    pointers: Vec<Pointer>,
    map: &'static [i8],
}

impl StructRegion {
    pub fn new(pointers: Vec<Pointer>, region_map: &'static [i8]) -> StructRegion {
        StructRegion {
            pointers,
            map: region_map,
        }
    }

    fn is_readable(i: i8) -> bool {
        i == 0 || i == -1
    }

    fn is_writable(i: i8) -> bool {
        i == 0 || i == -2
    }
}

impl PointedValue for StructRegion {
    fn get(&mut self, offset: &Scalar, size: u8) -> Result<TrackedValue, TrackError> {
        let (start, end) = is_access_in_range(offset, size, self.map.len())?;
        if self.map[start] > 0 {
            // Reading a pointer field
            if offset.is_constant::<32>().unwrap_or(false)
                && offset.is_constant::<64>().unwrap_or(false)
            {
                let ptr = self.map[start];
                if (start == 0 || self.map[start - 1] != ptr)
                    && self.map[end - 1] == ptr
                    && (end == self.map.len() || self.map[end] != ptr)
                {
                    return Ok(TrackedValue::Pointer(
                        self.pointers[ptr as usize - 1].clone(),
                    ));
                }
            }
            return Err(TrackError::PointerOffsetMisaligned);
        }

        // Reading some scalar fields
        for i in start..end {
            if !Self::is_readable(self.map[i as usize]) {
                return Err(TrackError::PointerOffsetMisaligned);
            }
        }
        Ok(TrackedValue::Scalar(Scalar::unknown()))
    }

    fn set(&mut self, offset: &Scalar, size: u8, _: &TrackedValue) -> Option<TrackError> {
        match is_access_in_range(offset, size, self.map.len()) {
            Ok((start, end)) => {
                for i in start..end {
                    if !Self::is_writable(self.map[i]) {
                        return Some(TrackError::PointeeNotWritable);
                    }
                }
                None
            }
            Err(err) => Some(err),
        }
    }
}

#[cfg(test)]
const ALL_READABLE_MAP: [i8; 8] = [0, 0, -1, -1, 0, -1, 0, 0];
#[cfg(test)]
const ALL_WRITABLE_MAP: [i8; 8] = [0, 0, -2, -2, 0, -2, 0, 0];

#[test]
pub fn test_readable_writable() {
    let v = TrackedValue::Scalar(Scalar::constant64(0));
    for (map, readable) in [(&ALL_READABLE_MAP, true), (&ALL_WRITABLE_MAP, false)] {
        let mut region = StructRegion::new(Vec::new(), map);
        for i in [1, 2, 4, 8] {
            if readable {
                assert!(region.get(&Scalar::constant64(0), i).is_ok());
            } else {
                assert!(region.set(&Scalar::constant64(0), i, &v).is_none());
            }
        }
        for (offset, size, ok) in [
            (0, 2, true),
            (1, 1, true),
            (4, 1, true),
            (6, 2, true),
            (0, 4, false),
            (2, 2, false),
            (4, 2, false),
            (4, 8, false),
        ] {
            if readable {
                if ok {
                    assert!(region.set(&Scalar::constant64(offset), size, &v).is_none());
                } else {
                    assert!(region.set(&Scalar::constant64(offset), size, &v).is_some());
                }
            } else {
                if ok {
                    assert!(region.get(&Scalar::constant64(offset), size).is_ok());
                } else {
                    assert!(region.get(&Scalar::constant64(offset), size).is_err());
                }
            }
        }
    }
}

#[cfg(test)]
const MAP_WITH_POINTER: [i8; 24] = [
    1, 1, 1, 1, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 3, 3, 3, 3,
];

#[cfg(test)]
use crate::track::{pointees::empty_region::EmptyRegion, pointer::PointerAttributes};

#[cfg(test)]
fn assert_is_only_ok_at_size(region: &mut StructRegion, offset: u64, size: u8, ptr: bool) {
    assert_all_err(region, offset, size - 1);
    let value = TrackedValue::Scalar(Scalar::constant64(0));
    assert!(region.get(&Scalar::constant64(offset), size).is_ok());
    assert!(region.get(&Scalar::constant64(offset), size + 1).is_err());
    assert!(region.get(&Scalar::constant64(offset), size * 2).is_err());
    if ptr {
        assert!(region
            .set(&Scalar::constant64(offset), size, &value)
            .is_some());
    } else {
        assert!(region
            .set(&Scalar::constant64(offset), size, &value)
            .is_none());
    }
    assert!(region
        .set(&Scalar::constant64(offset), size + 1, &value)
        .is_some());
    assert!(region
        .set(&Scalar::constant64(offset), size * 2, &value)
        .is_some());
}

#[cfg(test)]
fn assert_all_err(region: &mut StructRegion, offset: u64, size: u8) {
    let value = TrackedValue::Scalar(Scalar::constant64(0));
    for i in 1..=size {
        assert!(region.get(&Scalar::constant64(offset), i).is_err());
        assert!(region.set(&Scalar::constant64(offset), i, &value).is_some());
    }
}

#[cfg(test)]
fn assert_err_after(region: &mut StructRegion, offset: u64, size: u8) {
    let value = TrackedValue::Scalar(Scalar::constant64(0));
    for i in 1..=size {
        assert!(region.get(&Scalar::constant64(offset), i).is_ok());
        assert!(region.set(&Scalar::constant64(offset), i, &value).is_none());
    }
    assert!(region.get(&Scalar::constant64(offset), size + 1).is_err());
    assert!(region.set(&Scalar::constant64(offset), size + 1, &value).is_some());
}

#[test]
pub fn test_pointer() {
    let instance = EmptyRegion::instance();
    let mut region = StructRegion::new(
        alloc::vec![
            Pointer::new(PointerAttributes::empty(), instance.clone()),
            Pointer::new(PointerAttributes::empty(), EmptyRegion::instance()),
            Pointer::new(PointerAttributes::empty(), EmptyRegion::instance()),
        ],
        &MAP_WITH_POINTER,
    );
    assert_is_only_ok_at_size(&mut region, 0, 4, true);
    assert_all_err(&mut region, 2, 16);
    assert_err_after(&mut region, 4, 4);
    assert_is_only_ok_at_size(&mut region, 8, 8, true);
    assert_all_err(&mut region, 12, 12);
    assert_err_after(&mut region, 16, 4);
    assert_is_only_ok_at_size(&mut region, 20, 4, true);

    match region.get(&Scalar::constant64(0), 4) {
        Ok(TrackedValue::Pointer(pointer)) => pointer.is_pointing_to(instance),
        _ => panic!(),
    };
}
