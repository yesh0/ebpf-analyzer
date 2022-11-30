//! Tracks VM resource usage

use alloc::collections::VecDeque;

use super::id::{Id, IdGen};

/// Tracks the allocation of resources
#[derive(Clone, Default)]
pub struct ResourceTracker {
    resources: VecDeque<Id>,
    locked: bool,
}

impl ResourceTracker {
    /// Allocates a resource
    pub fn allocate(&mut self, ids: &mut IdGen) -> Id {
        let id = ids.next().unwrap();
        self.resources.push_back(id);
        id
    }

    /// Deallocates a resource
    pub fn deallocate(&mut self, id: Id) -> bool {
        if let Some(index) = self.resources.iter().position(|i| *i == id) {
            self.resources.remove(index);
            true
        } else {
            false
        }
    }

    /// Checks if a certain resource is available
    pub fn contains(&self, id: Id) -> bool {
        self.resources.contains(&id)
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
}