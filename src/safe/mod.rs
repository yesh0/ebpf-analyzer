/// Safely borrows multiple mutable items from a mutable slice
/// 
/// Internally it uses unsafe code after validating the bounds and checking for duplicate indices.
macro_rules! mut_borrow_items {
    ($self:expr, [$($index:expr),+], $t:ty) => {{
        let indices = [$($index),+];
        let len = $self.len();
        // Checks the the type matches
        let _: &$t = &$self[0];
        if (1..indices.len()).any(|i| indices[i..].contains(&indices[i - 1]))
            || indices.iter().any(|i| *i >= len) {
            None
        } else {
            unsafe {
                Some(($(
                    ($self.get_unchecked_mut($index) as *mut $t).as_mut().unwrap()
                ),+))
            }
        }
    }};
}

use core::cell::UnsafeCell;

pub(crate) use mut_borrow_items;

pub fn safe_ref_unsafe_cell<T>(cell: &'_ UnsafeCell<T>) -> &'_ T {
    unsafe { &*cell.get() }
}

#[test]
pub fn test_reborrowed() {
    let mut list: [i32; 7] = [1, 2, 3, 4, 5, 6, 7];
    assert!(mut_borrow_items!(list, [0, 0], i32).is_none());
    assert!(mut_borrow_items!(list, [9, 0], i32).is_none());
    assert!(mut_borrow_items!(list, [0, 1, 2, 1], i32).is_none());

    let i = 1;
    let j = 2;
    let k = 3;
    if let Some((a, b, c)) = mut_borrow_items!(list, [i, j, k], i32) {
        *a = 11;
        *b = 12;
        *c = 13;
        assert!(list[1] == 11);
        assert!(list[2] == 12);
        assert!(list[3] == 13);
    } else {
        panic!();
    }
}
