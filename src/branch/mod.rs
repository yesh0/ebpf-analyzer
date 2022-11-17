pub mod vm;
pub mod fork;
pub mod checked_value;
pub mod context;

/// Invalidates a immutable reference
/// 
/// This is considered safe since we only invalidate things and never the other way around.
macro_rules! unsafe_invalidate {
    ($self:expr, $t:ty, $content:expr) => {
        *(($self as *const $t as *mut $t).as_mut().unwrap()) = $content;
    };
}

pub(crate) use unsafe_invalidate;
