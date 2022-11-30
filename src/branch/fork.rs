//! This module implements the [Forker] for [BranchState].

use core::cell::RefCell;

use alloc::rc::Rc;

use crate::{
    interpreter::{
        context::{Fork, Forker},
        vm::Vm,
    },
    track::{
        comparable::{Comparable, ComparisonResult},
        pointees::InnerRegion,
        scalar,
        TrackedValue::{self, *},
    },
};

use super::{
    checked_value::CheckedValue,
    vm::{Branch, BranchState},
};

impl BranchState {
    /// Unwraps the [TrackedValue]s into scalars or invalidates the VM if there is any pointer
    fn all_scalars<'a>(
        &mut self,
        dst: &'a mut TrackedValue,
        src: &'a mut TrackedValue,
    ) -> Option<(&'a mut scalar::Scalar, &'a mut scalar::Scalar)> {
        if let (Scalar(s1), Scalar(s2)) = (dst, src) {
            Some((s1, s2))
        } else {
            self.invalidate("Pointer comparison not allowed");
            None
        }
    }

    /// Sets the limit for a [crate::track::pointees::dyn_region::DynamicRegion].
    fn fork_pointer_le(
        &mut self,
        dst: &mut TrackedValue,
        src: &mut TrackedValue,
        fork: &Fork,
    ) -> Result<Option<Branch>, ()> {
        if let (Pointer(p1), Pointer(p2)) = (dst, src) {
            if p2.is_end_pointer()
                && !p1.is_end_pointer()
                && p1.non_null()
                && p1.is_pointing_to(p2.get_pointing_to())
            {
                let pointee_ref = p1.get_pointing_region();
                let mut pointee = pointee_ref.borrow_mut();
                if let InnerRegion::Dyn(_) = pointee.inner() {
                    // dropping to allow cloning
                    drop(pointee);
                    // fallthrough
                    let mut branch = self.clone();
                    *branch.pc() = fork.fall_through;
                    // jumps
                    let offset = p1.offset();
                    // borrowing again
                    let mut pointee = pointee_ref.borrow_mut();
                    if let InnerRegion::Dyn(region) = pointee.inner() {
                        region.set_limit(offset);
                    } else {
                        unreachable!();
                    }
                    *self.pc() = fork.target;
                    Ok(Some(Rc::new(RefCell::new(branch))))
                } else {
                    self.invalidate("Only comparison of pointers of dynamic regions is allowed");
                    Err(())
                }
            } else {
                self.invalidate("Only comparison against an end pointer is allowed");
                Err(())
            }
        } else {
            Err(())
        }
    }
}

macro_rules! unwrap_checked_values {
    ($self:ident, $cv1:ident, $cv2:ident) => {
        if let (Some(ref mut v1), Some(ref mut v2)) = ($cv1.inner_mut(), $cv2.inner_mut()) {
            (v1, v2)
        } else {
            $self.invalidate("Invalid operants");
            return None;
        }
    };
}

macro_rules! match_scalar_comparison {
    ($op:ident, $self:ident,
                ($dst_i:ident, $s1:ident), ($src_i:ident, $s2:ident),
                $fork:ident, $width:ident) => {
        match $s1.$op($s2, $width) {
            ComparisonResult::Always => {
                *$self.pc() = $fork.target;
                None
            }
            ComparisonResult::Never => {
                *$self.pc() = $fork.fall_through;
                None
            }
            ComparisonResult::Perhaps((branched1, branched2)) => {
                *$self.pc() = $fork.target;
                // fallthrough
                let mut branch = $self.clone();
                *branch.pc() = $fork.fall_through;
                *branch.reg($dst_i as u8) = branched1.into();
                if $src_i >= 0 {
                    *branch.reg($src_i as u8) = branched2.into();
                }
                Some(Rc::new(RefCell::new(branch)))
            }
        }
    };
}

/// Returns `Ok` if it is a valid pointer comparison
macro_rules! match_pointer_le {
    ($self:ident, $width:ident, $lhs:expr, $rhs:expr, $fork:ident) => {
        if $width == 64u8 {
            if let Ok(ret) = $self.fork_pointer_le($lhs, $rhs, &$fork) {
                return ret;
            }
        }
    };
}

impl Forker<CheckedValue, BranchState> for BranchState {
    fn jeq(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        // Mut borrow workaround
        let pair = unwrap_checked_values!(self, dst, src);
        match pair {
            (Pointer(p1), Pointer(p2)) => {
                if width == 64 && p1.is_pointing_to(p2.get_pointing_to()) {
                    self.invalidate("Pointer comparison not implemented");
                    None
                } else {
                    self.invalidate("Pointer comparison not allowed");
                    None
                }
            }
            (Pointer(ref mut p1), Scalar(s2)) => {
                if width == 64
                    && s2.is_constant::<64>().unwrap_or(false)
                    && s2.is_constant::<32>().unwrap_or(false)
                    && s2.contains(0)
                {
                    // if p1 == 0
                    if p1.non_null() {
                        // p1 != 0: fall through
                        *self.pc() = fork.fall_through;
                        None
                    } else {
                        // p1 != 0: fall through
                        p1.set_non_null();
                        *self.pc() = fork.fall_through;
                        // p1 == 0: jumps
                        let mut branch = self.clone();
                        *branch.pc() = fork.target;
                        if dst_i >= 0 {
                            *branch.reg(dst_i as u8) = scalar::Scalar::constant64(0).into();
                        }
                        Some(Rc::new(RefCell::new(branch)))
                    }
                } else {
                    self.invalidate("Only pointer null checking allowed");
                    None
                }
            }
            (Scalar(_), Pointer(_)) => self.jeq((src_i, src), (dst_i, dst), fork, width),
            (Scalar(s1), Scalar(s2)) => {
                match_scalar_comparison!(eq, self, (dst_i, s1), (src_i, s2), fork, width)
            }
        }
    }

    fn jset(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        let pair = unwrap_checked_values!(self, dst, src);
        let (s1, s2) = self.all_scalars(pair.0, pair.1)?;
        match_scalar_comparison!(set, self, (dst_i, s1), (src_i, s2), fork, width)
    }

    fn jlt(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        let pair = unwrap_checked_values!(self, dst, src);
        // `start + s1 < end` implies `start + s1 <= end` already
        // For simplicity we are not setting the limit to `s1 + 1` but `s1` instead.
        match_pointer_le!(self, width, pair.0, pair.1, fork);
        let (s1, s2) = self.all_scalars(pair.0, pair.1)?;
        match_scalar_comparison!(lt, self, (dst_i, s1), (src_i, s2), fork, width)
    }

    fn jle(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        let pair = unwrap_checked_values!(self, dst, src);
        match_pointer_le!(self, width, pair.0, pair.1, fork);
        let (s1, s2) = self.all_scalars(pair.0, pair.1)?;
        match_scalar_comparison!(le, self, (dst_i, s1), (src_i, s2), fork, width)
    }

    fn jslt(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        let pair = unwrap_checked_values!(self, dst, src);
        let (s1, s2) = self.all_scalars(pair.0, pair.1)?;
        match_scalar_comparison!(slt, self, (dst_i, s1), (src_i, s2), fork, width)
    }

    fn jsle(
        &mut self,
        (dst_i, dst): (i8, &mut CheckedValue),
        (src_i, src): (i8, &mut CheckedValue),
        fork: Fork,
        width: u8,
    ) -> Option<Branch> {
        let pair = unwrap_checked_values!(self, dst, src);
        let (s1, s2) = self.all_scalars(pair.0, pair.1)?;
        match_scalar_comparison!(sle, self, (dst_i, s1), (src_i, s2), fork, width)
    }
}
