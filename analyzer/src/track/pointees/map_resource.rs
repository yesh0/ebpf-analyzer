//! A simplistic map resource

use alloc::vec::Vec;

use crate::{
    branch::{checked_value::CheckedValue, id::Id, vm::BranchState},
    spec::proto::{
        ArgumentType, IllegalFunctionCall, ReturnType, StaticFunctionCall, VerifiableCall,
    },
    track::{pointer::Pointer, scalar::Scalar, TrackError, TrackedValue},
};

use super::{
    dyn_region::DynamicRegion, pointed, AnyType, MemoryRegion, Pointee, SafeClone, with_resource,
};

/// The type id for maps
pub const MAP_TYPE_ID: AnyType = -1i32;
/// The type id for map values
pub const MAP_VALUE_TYPE_ID: AnyType = -2i32;

/// A simple map used via helper functions
#[derive(Clone, Debug)]
pub struct SimpleMap {
    id: u32,
    key_size: usize,
    value_size: usize,
    values: Vec<Pointee>,
}

impl SimpleMap {
    /// Creates a map
    ///
    /// Sizes should be in bytes.
    pub fn new(key_size: usize, value_size: usize) -> Self {
        Self {
            id: 0,
            key_size,
            value_size,
            values: Vec::new(),
        }
    }

    /// Returns the key size in bytes
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Returns the value size in bytes
    pub fn value_size(&self) -> usize {
        self.value_size
    }

    /// Returns a region of a map value (nullable, readable, writable, allowing arithmetic)
    pub fn get_value(&mut self, vm: &mut BranchState) -> Pointer {
        let value = pointed(DynamicRegion::new(self.value_size));
        vm.add_external_resource(value.clone());
        self.values.push(value.clone());
        Pointer::rwa(value)
    }

    /// Invalidates all value regions in this map
    pub fn invalidate_values(&mut self, vm: &mut BranchState) {
        while let Some(value) = self.values.pop() {
            vm.remove_external_resource(value.borrow_mut().get_id());
        }
    }
}

impl SafeClone for SimpleMap {
    fn get_id(&self) -> Id {
        self.id
    }

    fn set_id(&mut self, id: Id) {
        self.id = id
    }

    fn safe_clone(&self) -> Pointee {
        pointed(self.clone())
    }

    fn redirects(&mut self, _mapper: &dyn Fn(Id) -> Option<Pointee>) {}
}

impl MemoryRegion for SimpleMap {
    fn get(&mut self, _offset: &Scalar, _size: u8) -> Result<TrackedValue, TrackError> {
        Err(TrackError::PointeeNotReadable)
    }

    fn set(
        &mut self,
        _offset: &Scalar,
        _size: u8,
        _value: &TrackedValue,
    ) -> Result<(), TrackError> {
        Err(TrackError::PointeeNotWritable)
    }

    fn inner(&mut self) -> super::InnerRegion {
        super::InnerRegion::Any((MAP_TYPE_ID, self))
    }
}

/// Retrieves map info from `r1`
fn for_map<T>(
    vm: &mut BranchState,
    action: fn(&mut SimpleMap, &mut BranchState) -> T,
) -> Result<T, IllegalFunctionCall> {
    with_resource(MAP_TYPE_ID, 1, vm, action)
}

/// bpf_map_update_elem
pub struct MapUpdateCall;

impl VerifiableCall<CheckedValue, BranchState> for MapUpdateCall {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        let (key_size, value_size) = for_map(vm, |map, vm| {
            map.invalidate_values(vm);
            (map.key_size, map.value_size)
        })?;
        StaticFunctionCall::new(
            [
                ArgumentType::Any,
                ArgumentType::FixedMemory(key_size),
                ArgumentType::FixedMemory(value_size),
                ArgumentType::Scalar,
                ArgumentType::Any,
            ],
            ReturnType::Scalar,
        )
        .call(vm)
    }
}

/// bpf_map_lookup_elem
pub struct MapLookupCall;

impl VerifiableCall<CheckedValue, BranchState> for MapLookupCall {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        let (key_size, value) = for_map(vm, |map, vm| (map.key_size, map.get_value(vm)))?;
        StaticFunctionCall::new(
            [
                ArgumentType::Any,
                ArgumentType::FixedMemory(key_size),
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::None,
        )
        .call(vm)
        .map(|_| value.into())
    }
}

/// bpf_map_delete_elem
pub struct MapDeleteCall;

impl VerifiableCall<CheckedValue, BranchState> for MapDeleteCall {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        let key_size = for_map(vm, |map, vm| {
            map.invalidate_values(vm);
            map.key_size
        })?;
        StaticFunctionCall::new(
            [
                ArgumentType::Any,
                ArgumentType::FixedMemory(key_size),
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::Scalar,
        )
        .call(vm)
    }
}

#[cfg(test)]
fn get_map_info(vm: &mut BranchState) -> Result<(usize, usize), IllegalFunctionCall> {
    for_map(vm, |map, _| (map.key_size, map.value_size))
}

#[test]
fn test_map_helpers() {
    use alloc::vec::Vec;
    use crate::interpreter::vm::Vm;
    let map = pointed(SimpleMap::new(8, 8));
    let mut vm = BranchState::new(&[], Vec::new());
    vm.add_external_resource(map.clone());

    // Test lookup calls
    let lookup = MapLookupCall {};

    assert!(lookup.call(&mut vm).is_err());

    // Test get_map_info (1)
    assert!(get_map_info(&mut vm).is_err());
    *vm.reg(1) = Pointer::rwa(map.clone()).into();
    assert!(get_map_info(&mut vm).is_err());
    *vm.reg(1) = Pointer::nrwa(map.clone()).into();
    assert!(get_map_info(&mut vm).is_ok());
    assert!(lookup.call(&mut vm).is_err());

    use core::ops::SubAssign;
    *vm.reg(2) = vm.ro_reg(10).clone();
    vm.reg(2).sub_assign(&Scalar::constant64(8).into());
    assert!(lookup.call(&mut vm).is_err());

    use crate::interpreter::value::Dereference;
    assert!(unsafe { vm.reg(2).set_at(0, 8, &Scalar::constant64(0).into()) });
    let result = lookup.call(&mut vm);
    assert!(result.is_ok());
    let mut value = result.unwrap();

    match value.inner_mut() {
        Some(TrackedValue::Pointer(ref mut p)) => {
            p.set_non_null();
        }
        _ => panic!(),
    }

    *vm.reg(0) = value;
    assert!(!vm.is_invalid_resource(0));
    assert!(unsafe { vm.reg(0).set_at(0, 4, &Scalar::constant64(0).into()) });
    assert!(unsafe { vm.reg(0).set_at(0, 8, &Scalar::constant64(0).into()) });
    assert!(!unsafe { vm.reg(0).set_at(0, 16, &Scalar::constant64(0).into()) });
    // No pointer leak is allowed
    assert!(!unsafe { vm.reg(0).set_at(0, 8, &Pointer::rwa(map.clone()).into()) });

    // Test get_map_info (2)
    *vm.reg(1) = vm.reg(0).clone();
    assert!(get_map_info(&mut vm).is_err());
    *vm.reg(1) = Pointer::nrwa(map.clone()).into();

    // Test map update
    let update = MapUpdateCall {};
    assert!(update.call(&mut vm).is_err());

    *vm.reg(3) = vm.ro_reg(10).clone();
    assert!(update.call(&mut vm).is_err());

    vm.reg(3).sub_assign(&Scalar::constant64(16).into());
    assert!(update.call(&mut vm).is_err());

    assert!(unsafe { vm.reg(3).set_at(0, 4, &Scalar::constant64(0).into()) });
    assert!(update.call(&mut vm).is_err());

    *vm.reg(4) = Scalar::constant64(0).into();
    assert!(update.call(&mut vm).is_err());

    assert!(unsafe { vm.reg(3).set_at(4, 4, &Scalar::constant64(0).into()) });
    let result = update.call(&mut vm);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap().inner(),
        Some(TrackedValue::Scalar(_))
    ));

    // Test map delete
    let delete = MapDeleteCall {};
    let result = delete.call(&mut vm);
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap().inner(),
        Some(TrackedValue::Scalar(_))
    ));

    // No pointer leak is allowed
    assert!(unsafe { vm.reg(2).set_at(0, 8, &Pointer::rwa(map).into()) });
    assert!(delete.call(&mut vm).is_err());
}
