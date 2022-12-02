//! This module defines trais used by the interpreter:
//! - [VmContext]
//! - [Forker]
//!
//! Also, simplistic implementations are provided for [Wrapping<u64>].

use core::{cell::RefCell, num::Wrapping};

use alloc::rc::Rc;

use super::{
    value::VmValue,
    vm::{UncheckedVm, Vm},
};

/// Execution context for a VM, designed for verifier branch tracking
pub trait VmContext<Value: VmValue, V: Vm<Value>> {
    /// Adds a pending branch to the context, allowing outer caller to keep exploring new branches
    fn add_pending_branch(&mut self, vm: Rc<RefCell<V>>);
}

/// A no-op context for interpreter
#[derive(Default)]
pub struct NoOpContext;

impl<Value: VmValue, V: Vm<Value>> VmContext<Value, V> for NoOpContext {
    fn add_pending_branch(&mut self, _vm: Rc<RefCell<V>>) {}
}

/// A fork, representing a conditional jump
pub struct Fork {
    /// Where a conditional jump instruction jumps to if the condition were `true`
    ///
    /// This is not an offset, and is directly assigned to the PC of the VM.
    pub target: usize,
    /// Where a conditional jump instruction jumps to if the condition were `false`
    ///
    /// This is not an offset, and is directly assigned to the PC of the VM.
    pub fall_through: usize,
}

impl Fork {
    /// Returns a new instance with its `target` and `fall_through` exchanged
    ///
    /// It is used when changing `if (a) { B } else { C }` into `if (!a) { C } else { B }`
    /// to save some coding.
    pub fn flip(&self) -> Fork {
        Fork { target: self.fall_through, fall_through: self.target }
    }
}

/// Generates the operations
///
/// They all have the same signature and I am just too lazy to type all of them.
macro_rules! forker_ops {
    ($($name:ident),+) => {
        $(
        /// Compares dst and src and returns a forked branch if the result is indeterminate
        ///
        /// - `dst` / `src`: `(register_id, register_value)`: Sets `register_id` to `-1` for non register values.
        /// - `fork`: The jump destination and fall-through destination.
        /// - `width`: Either 32 or 64.
        fn $name(&mut self, dst: (i8, &mut Value), src: (i8, &mut Value), fork: Fork, width: u8) -> Option<Rc<RefCell<B>>>;
        )*
    };
}

/// A forker that determines what direction(s) will the fork lead to
///
/// For interpreters, it jumps depending on actual values, returning `None`.
/// For verifiers, it optionally returns `Some` branch if it concludes that both branch can get executed.
///
/// Note that to predict `ge` or `sgt`, just use `lt` or `sle` with the fork inverted.
pub trait Forker<Value: VmValue, B: Vm<Value> + ?Sized> {
    forker_ops!(jeq, jset, jlt, jle, jslt, jsle);
}

macro_rules! fork_it {
    ($self:ident, $dst:ident, $src:ident, $fork:ident, $op:ident, $t:ident) => {{
        *$self.pc() = if ($dst.1.0 as $t).$op(&($src.1.0 as $t)) {
            $fork.target
        } else {
            $fork.fall_through
        };
        None
    }};
}

macro_rules! impl_fork_it {
    ($fn:ident, $op:ident, $t32:ident, $t64:ident) => {
        fn $fn(
            &mut self,
            dst: (i8, &mut Wrapping<u64>),
            src: (i8, &mut Wrapping<u64>),
            fork: Fork,
            width: u8,
        ) -> Option<Rc<RefCell<Self>>> {
            if width == 32 {
                fork_it!(self, dst, src, fork, $op, $t32)
            } else {
                fork_it!(self, dst, src, fork, $op, $t64)
            }
        }
    };
}

impl Forker<Wrapping<u64>, Self> for UncheckedVm<Wrapping<u64>> {
    impl_fork_it!(jeq, eq, u32, u64);
    impl_fork_it!(jlt, lt, u32, u64);
    impl_fork_it!(jle, le, u32, u64);
    impl_fork_it!(jslt, lt, i32, i64);
    impl_fork_it!(jsle, le, i32, i64);

    fn jset(
        &mut self,
        dst: (i8, &mut Wrapping<u64>),
        src: (i8, &mut Wrapping<u64>),
        fork: Fork,
        width: u8,
    ) -> Option<Rc<RefCell<Self>>> {
        if width == 32 {
            *self.pc() = if (dst.1.0 as u32) & (src.1.0 as u32) != 0 {
                fork.target
            } else {
                fork.fall_through
            };
            None
        } else {
            *self.pc() = if dst.1.0 & src.1.0 != 0 {
                fork.target
            } else {
                fork.fall_through
            };
            None
        }
    }
}
