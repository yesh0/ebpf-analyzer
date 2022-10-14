#![no_std]

mod algorithm;

use core::{pin::Pin, cell::RefCell};

pub use algorithm::DfsResult;
use alloc::{collections::BTreeMap, rc::Rc};
use pin_weak::rc::PinWeak;

extern crate alloc;

type RcNode = Pin<Rc<RefCell<Node>>>;
type WeakNode = PinWeak<RefCell<Node>>;
type NodeId = u64;

enum Anchor {
    Node((i64, WeakNode)),
    Constant(u64),
}

type Edges = BTreeMap<NodeId, Anchor>;

struct Node {
    outgoing: Edges,
    incoming: Edges,
}

impl Node {
    fn new() -> Node {
        Node { outgoing: BTreeMap::new(), incoming: BTreeMap::new() }
    }

    /// Returns the address of this node as an id
    /// 
    /// The node must be pinned to have the id fixed.
    fn id(&self) -> NodeId {
        self as *const Self as NodeId
    }
}

/// A node representing a number in the graph
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

    pub fn reachable_within(&self, other: &GraphNode, dfs_limit: usize, min_cost: i64) -> DfsResult {
        algorithm::limited_dfs(self, dfs_limit, other, min_cost)
    }
}
