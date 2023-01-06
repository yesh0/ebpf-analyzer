//! Loads eBPF programs from object files with Aya

use std::collections::HashMap;

use aya_obj::{Map, Object};

/// Loads eBPF programs from an object file, assigning each map a pseudo-descriptor
pub fn load_programs(path: &str) -> (Object, HashMap<i32, Map>) {
    let mut obj = Object::parse(&std::fs::read(path).unwrap()).unwrap();
    obj.relocate_calls().unwrap();
    let v: Vec<_> = obj
        .maps
        .iter()
        .enumerate()
        .map(|(i, (name, map))| (name.clone(), i as i32 + 1, map.clone()))
        .collect();
    obj.relocate_maps(
        v.iter()
            .map(|(name, fd, map)| (name.as_str(), Some(*fd), map)),
    )
    .unwrap();
    (
        obj,
        v.iter().map(|(_, fd, map)| (*fd, map.clone())).collect(),
    )
}
