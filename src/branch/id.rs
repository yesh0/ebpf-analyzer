//! Unique id generation

/// Currently the verifier limits the total processed instruction count
/// to a million, so using an `u32` should be safe from overflowing.
pub type Id = u32;

/// An id generator
///
#[derive(Default)]
pub struct IdGen(Id);

impl Iterator for IdGen {
    type Item = Id;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_id())
    }
}

impl IdGen {
    /// Generates the next id
    pub fn next_id(&mut self) -> Id {
        self.0 = self.0.wrapping_add(1);
        self.0
    }
}

#[test]
fn test_id_gen() {
    let mut gen = IdGen::default();
    assert_eq!(gen.0, 0);
    assert!(gen.next().unwrap() == 1);
    assert!(gen.0 == 1);
}
