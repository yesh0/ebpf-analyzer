#![no_std]

mod algorithm;

use core::{cell::RefCell, pin::Pin};

pub use algorithm::DfsResult;
use alloc::{collections::BTreeMap, rc::Rc};
use pin_weak::rc::PinWeak;

extern crate alloc;

type RcNode = Pin<Rc<RefCell<Node>>>;
type WeakNode = PinWeak<RefCell<Node>>;
type NodeId = u64;

enum Anchor {
    /// (rel, other_node) where self >= other_node + rel
    Node((i64, WeakNode)),
    /// constant, where self >= constant
    Constant(u64),
}

type Edges = BTreeMap<NodeId, Anchor>;

struct Node {
    outgoing: Edges,
    incoming: Edges,
}

impl Node {
    fn new() -> Node {
        Node {
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
        }
    }

    /// Returns the address of this node as an id
    ///
    /// The node must be pinned to have the id fixed.
    fn id(&self) -> NodeId {
        self as *const Self as NodeId
    }
}

/// A Rc to a node representing a number in the graph
///
/// Each edge in the graph represents an inequality like `a >= b + constant`,
/// with the constant as its weight (which may be negative).
///
/// Having an edge connecting to a constant like `a >= constant` is called anchored.
pub struct GraphNode(RcNode);

impl GraphNode {
    /// Constructs an empty node
    pub fn new() -> GraphNode {
        GraphNode(Rc::pin(RefCell::new(Node::new())))
    }

    /// Constructs a node such that `new_node == base + rel`
    pub fn new_from(base: &GraphNode, rel: i64) -> GraphNode {
        let node = GraphNode::new();
        // node >= base + rel
        node.connect_to(base, rel);
        // base >= node - rel
        base.connect_to(&node, -rel);
        node
    }

    /// Returns the id of the inner node
    fn id(&self) -> NodeId {
        self.0.borrow().id()
    }

    fn weak(&self) -> WeakNode {
        PinWeak::downgrade(self.0.clone())
    }

    /// Constructs a `self >= other + weight` linkage
    ///
    /// Existing linkages get merged.
    pub fn connect_to(&self, other: &GraphNode, mut weight: i64) {
        let id = self.id();
        let other_id = other.id();

        if id == other_id {
            return;
        }

        let from_self = &mut self.0.borrow_mut().outgoing;
        let to_other = &mut other.0.borrow_mut().incoming;

        if let Some(Anchor::Node((old_weight, _))) = from_self.remove(&other_id) {
            weight = weight.max(old_weight);
            to_other.remove(&id);
        }

        to_other.insert(id, Anchor::Node((weight, self.weak())));
        from_self.insert(other_id, Anchor::Node((weight, other.weak())));
    }

    /// Constructs a `self >= constant` linkage
    pub fn anchor_to(&self, mut constant: u64) {
        let from_self = &mut self.0.borrow_mut().outgoing;

        if let Some(Anchor::Constant(old)) = from_self.remove(&0) {
            constant = constant.max(old);
        }

        from_self.insert(0, Anchor::Constant(constant));
    }

    /// Constructs a `constant >= self` linkage
    pub fn anchor_from(&self, mut constant: u64) {
        let to_self = &mut self.0.borrow_mut().incoming;

        if let Some(Anchor::Constant(old)) = to_self.remove(&0) {
            constant = constant.min(old);
        }

        to_self.insert(0, Anchor::Constant(constant));
    }

    /// Constructs a `self == constant` linkage
    pub fn anchor(&self, constant: u64) {
        self.anchor_from(constant);
        self.anchor_to(constant);
    }

    pub fn reachable_within(
        &self,
        other: &GraphNode,
        dfs_limit: usize,
        min_cost: i64,
    ) -> DfsResult {
        algorithm::limited_dfs(self, dfs_limit, other, min_cost)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let id = self.id();
        for (_other_id, anchor) in self.outgoing.iter() {
            match anchor {
                Anchor::Node((rel, other_weak)) => {
                    Node::unlink(id, *rel, other_weak, &self.incoming);
                }
                Anchor::Constant(c) => {
                    for (_, anchor) in self.incoming.iter() {
                        if let Anchor::Node((upper_rel, upper)) = anchor {
                            if let Some(up) = upper.upgrade() {
                                GraphNode(up).anchor_to((upper_rel + (*c as i64)) as u64);
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Node {
    fn unlink(id: u64, rel: i64, other_weak: &WeakNode, incoming: &Edges) {
        if let Some(other) = other_weak.upgrade() {
            let mut other_inner = other.borrow_mut();
            other_inner.incoming.remove(&id);
            drop(other_inner);

            for (_, anchor) in incoming.iter() {
                match anchor {
                    Anchor::Node((upper_rel, upper)) => {
                        if let Some(up) = upper.upgrade() {
                            GraphNode(up).connect_to(&GraphNode(other.clone()), upper_rel + rel);
                        }
                    }
                    Anchor::Constant(c) => {
                        GraphNode(other.clone()).anchor_from(*c - rel as u64);
                    }
                }
            }
        }
    }
}
