use num_traits::ToPrimitive;

pub type HelperPointer = fn(u64, u64, u64, u64, u64) -> u64;

pub struct HelperCollection(&'static [HelperPointer]);

impl HelperCollection {
    pub fn call_helper(&self, helper: i32, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> Option<u64> {
        Some((self.0.get(helper.to_usize()?)?)(r1, r2, r3, r4, r5))
    }

    pub fn new(helpers: &'static [HelperPointer]) -> HelperCollection {
        HelperCollection(helpers)
    }
}