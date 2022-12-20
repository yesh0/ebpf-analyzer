//! Tracks VM resource usage

use alloc::{collections::VecDeque, vec::Vec};

use super::id::{Id, IdGen};

/// Tracks the allocation of resources
#[derive(Clone, Default)]
pub struct ResourceTracker {
    /// Allocated resources (must be freed)
    resources: VecDeque<Id>,
    /// Externally provided resources (no need to free)
    external: Vec<Id>,
    /// Locks, unused for now
    locked: bool,
}

impl ResourceTracker {
    /// Adds an external resource
    pub fn external(&mut self, ids: &mut IdGen) -> Id {
        let id = ids.next_id();
        self.external.push(id);
        id
    }

    /// Removes an external resource, returning `true` on success
    pub fn invalidate_external(&mut self, id: Id) -> bool {
        if let Some(index) = self.external.iter().position(|i| *i == id) {
            // TODO: Decide if we should use `swap_remove`
            self.external.remove(index);
            true
        } else {
            false
        }
    }

    /// Allocates a resource
    pub fn allocate(&mut self, ids: &mut IdGen) -> Id {
        let id = ids.next_id();
        self.resources.push_back(id);
        id
    }

    /// Deallocates a resource, returning `true` on success
    pub fn deallocate(&mut self, id: Id) -> bool {
        if let Some(index) = self.resources.iter().position(|i| *i == id) {
            // TODO: Decide if we should use `swap_remove`
            self.resources.remove(index);
            true
        } else {
            false
        }
    }

    /// Checks if a certain resource is available
    pub fn contains(&self, id: Id) -> bool {
        self.resources.contains(&id) || self.external.contains(&id)
    }

    /// Locks
    pub fn lock(&mut self) -> bool {
        if self.locked {
            false
        } else {
            self.locked = true;
            true
        }
    }

    /// Unlocks
    pub fn unlock(&mut self) -> bool {
        if self.locked {
            self.locked = false;
            true
        } else {
            false
        }
    }

    /// Checks if the VM is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Returns `true` if all resources are cleaned up
    pub fn is_empty(&self) -> bool {
        !self.locked && self.resources.is_empty()
    }
}

#[test]
fn test_res_tracker() {
    let mut tracker = ResourceTracker::default();
    assert!(!tracker.is_locked());
    assert_eq!(tracker.allocate(&mut IdGen::default()), 1);
    assert!(tracker.contains(1));
    assert!(!tracker.deallocate(0));
    assert!(tracker.deallocate(1));
    assert!(!tracker.contains(1));

    assert!(!tracker.unlock());
    assert!(tracker.lock());
    assert!(tracker.is_locked());
    assert!(!tracker.lock());
    assert!(tracker.unlock());

    assert!(tracker.is_empty());
    assert_eq!(tracker.external(&mut IdGen::default()), 1);
    assert!(tracker.is_empty());
    assert!(tracker.contains(1));
    assert!(tracker.invalidate_external(1));
    assert!(!tracker.contains(1));
    assert!(!tracker.invalidate_external(1));
}
