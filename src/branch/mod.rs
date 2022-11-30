//! This module wraps up [crate::track] to produce a VM environment
//! to be used with [crate::interpreter] to do verification.

pub mod vm;
pub mod fork;
pub mod checked_value;
pub mod context;
pub mod resource;
pub mod id;
