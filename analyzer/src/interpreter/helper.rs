//! See [HelperPointer] and [HelperCollection].

use num_traits::ToPrimitive;

/// A callable function, used by [super::vm::UncheckedVm] as helper function pointers
pub type HelperPointer = fn(u64, u64, u64, u64, u64) -> u64;

/// A collection of [HelperPointer]
///
/// We are assuming that one should be providing static bindings.
///
/// Note that, although the array index starts from zero,
/// it is unlikely that any program will ever call that function,
/// since LLVM sees the function (indexed by zero or `null`) as invalid
/// and tends to optimize the whole program away.
pub struct HelperCollection(&'static [HelperPointer]);

impl HelperCollection {
    /// Calls the `helper` function, passing the arguments as is
    ///
    /// Returns `Some(return_value)` if such function is found, or `None` otherwise.
    pub fn call_helper(&self, helper: i32, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> Option<u64> {
        Some((self.0.get(helper.to_usize()?)?)(r1, r2, r3, r4, r5))
    }

    /// Creates a new [HelperCollection]
    ///
    /// The functions are indexed by the slice index.
    pub fn new(helpers: &'static [HelperPointer]) -> HelperCollection {
        HelperCollection(helpers)
    }
}
