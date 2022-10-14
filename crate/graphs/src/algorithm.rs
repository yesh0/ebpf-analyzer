use core::ops::Deref;

use alloc::{collections::btree_map::Iter, vec::Vec};

use crate::{Anchor, Edges, GraphNode, Node, NodeId};

type NodeIter<'a> = Iter<'a, u64, Anchor>;

trait TreeWalker {
    fn get_edges(node: &Node) -> &Edges;
    fn reduce_limit(a: i64, b: i64) -> i64;
    fn init_limit() -> i64;
    fn within_cost(cost_limit: i64, cost: i64) -> bool;
    fn within_limit(limit_limit: i64, limit: i64) -> bool;
    fn merge_const(constant: i64, cost: i64) -> i64;
}

struct ForwardWalker;
impl TreeWalker for ForwardWalker {
    /// Outgoing edges
    fn get_edges(node: &Node) -> &Edges {
        &node.outgoing
    }
    /// `node >= lower_bound` and we try to produce a higher (tighter) bound
    fn reduce_limit(a: i64, b: i64) -> i64 {
        a.max(b)
    }
    /// Lowest lower bound
    fn init_limit() -> i64 {
        i64::MIN
    }
    /// Whether `node >= target + cost` => `node >= target + cost_limit`
    ///
    /// That is, `cost >= cost_limit`.
    fn within_cost(cost_limit: i64, cost: i64) -> bool {
        cost >= cost_limit
    }
    /// Whether `node >= limit >= limit_limit`
    fn within_limit(limit_limit: i64, limit: i64) -> bool {
        limit >= limit_limit
    }
    /// node >= x1 + cost1, x1 >= x2 + cost2, ..., xn == constant:
    /// node >= constant + sum(costs)
    fn merge_const(constant: i64, cost: i64) -> i64 {
        constant + cost
    }
}

struct BackwardWalker;
impl TreeWalker for BackwardWalker {
    /// Incoming edges
    fn get_edges(node: &Node) -> &Edges {
        &node.incoming
    }
    /// `upper_bound >= node` and we try to produce a lower (tighter) bound
    fn reduce_limit(a: i64, b: i64) -> i64 {
        a.min(b)
    }
    /// Highest upper bound
    fn init_limit() -> i64 {
        i64::MAX
    }
    /// Whether `target >= node + cost` => `target >= node + cost_limit`
    ///
    /// That is, `cost >= cost_limit`.
    fn within_cost(cost_limit: i64, cost: i64) -> bool {
        cost >= cost_limit
    }
    /// Whether `limit_limit >= limit >= node`
    fn within_limit(limit_limit: i64, limit: i64) -> bool {
        limit <= limit_limit
    }
    /// node + cost1 <= x1, x1 + cost2 >= x2, ..., xn == constant:
    /// node <= constant - sum(costs)
    fn merge_const(constant: i64, cost: i64) -> i64 {
        constant - cost
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum DfsResult {
    Always,
    Maybe,
    Never,
}

/// Walks through the graph to find a certain node, within a depth limit
///
/// `node >= target + return_value >= target + min_cost`
/// 
/// TODO: Check for integer overflow
pub(crate) fn limited_dfs(
    node: &GraphNode,
    depth_limit: usize,
    target: &GraphNode,
    min_cost: i64,
) -> DfsResult {
    let id = node.id();
    let target_id = target.id();
    if id == target_id {
        if min_cost <= 0 {
            return DfsResult::Always;
        } else {
            return DfsResult::Never;
        }
    }

    match walk_tree::<ForwardWalker>(node, depth_limit, target_id, min_cost, i64::MAX) {
        // node >= target + some_cost >= target + min_cost
        WalkResult::Success => return DfsResult::Always,
        // node >= lower_bound
        WalkResult::Limit(lower_bound) => {
            match walk_tree::<ForwardWalker>(target, depth_limit, id, -min_cost + 1, i64::MAX) {
                // target >= node - min_cost + 1
                // node < node + 1 <= target + min_cost
                WalkResult::Success => DfsResult::Never,
                // target >= lower_bound_t
                WalkResult::Limit(lower_bound_t) => {
                    // We want an upper bound, and we set cost_limit to i64::MAX so that it never succeeds.
                    //
                    // With `node >= lower_bound`, `upper_bound >= target`,
                    // To have `node >= target + min_cost`, `node - target >= min_cost`,
                    // we want `lower_bound - upper_bound >= min_cost`, `upper_bound <= lower_bound - min_cost`.
                    if let Some(bound_limit) = lower_bound.checked_add(-min_cost) {
                        match walk_tree::<BackwardWalker>(
                            target,
                            depth_limit,
                            id,
                            i64::MAX,
                            bound_limit,
                        ) {
                            // It should not
                            WalkResult::Success => DfsResult::Maybe,
                            WalkResult::Limit(upper_bound) => {
                                if upper_bound <= bound_limit {
                                    DfsResult::Always
                                } else {
                                    DfsResult::Maybe
                                }
                            }
                        }
                    } else {
                        // Now we want an upper bound for our node, so that:
                        //
                        // `target >= lower_bound_t >= upper_bound_n - min_cost + 1 >= node - min_cost + 1`
                        // `node < node + 1 <= target + min_cost` -> DfsResult::Never.
                        if let Some(Some(bound_limit)) = lower_bound_t
                            .checked_add(min_cost)
                            .map(|i| i.checked_add(-1))
                        {
                            match walk_tree::<BackwardWalker>(
                                node,
                                depth_limit,
                                target_id,
                                i64::MAX,
                                bound_limit,
                            ) {
                                // It should not
                                WalkResult::Success => DfsResult::Maybe,
                                WalkResult::Limit(upper_bound_n) => if upper_bound_n <= bound_limit {
                                    DfsResult::Never
                                } else {
                                    DfsResult::Maybe
                                },
                            }
                        } else {
                            DfsResult::Maybe
                        }
                    }
                }
            }
        }
    }
}

enum WalkResult {
    Success,
    Limit(i64),
}

fn walk_tree<Walker: TreeWalker>(
    node: &GraphNode,
    depth_limit: usize,
    target_id: NodeId,
    cost_limit: i64,
    limit_limit: i64,
) -> WalkResult {
    // stack: (cost, node_id, iter)
    let mut stack: Vec<(i64, NodeId, NodeIter)> = Vec::new();
    stack.reserve(depth_limit);

    let root = &node.0.borrow();
    let edges = Walker::get_edges(&root);
    stack.push((0, node.id(), edges.iter()));
    drop(root);

    let mut limit = Walker::init_limit();

    while let Some((cost, id, mut iter)) = stack.pop() {
        if let Some((next_id, next)) = iter.next() {
            stack.push((cost, id, iter));

            // Reached target
            if *next_id == target_id {
                if let Anchor::Node((step_cost, _)) = next {
                    let current_cost = *step_cost + cost;
                    if Walker::within_cost(cost_limit, current_cost) {
                        return WalkResult::Success;
                    }
                }
                continue;
            }
            // Constant anchor
            if *next_id == 0 {
                if let Anchor::Constant(c) = next {
                    limit = Walker::reduce_limit(limit, Walker::merge_const(*c as i64, cost));
                    if Walker::within_limit(limit_limit, limit) {
                        return WalkResult::Limit(limit);
                    }
                }
                continue;
            }
            // Continue DFS if we are within limit and not forming a cyclic path
            if stack.iter().all(|(_, id, _)| id != next_id) {
                if stack.len() < depth_limit {
                    if let Anchor::Node((step_cost, next_node)) = next {
                        if let Some(new_rc) = next_node.upgrade() {
                            let node_ref = new_rc.borrow();
                            unsafe {
                                let ptr = node_ref.deref() as *const Node;
                                // Prevent the stack from holding node borrows
                                // We are single-threaded and things are fine inside this function.
                                stack.push((*step_cost + cost, *next_id, (&*ptr).outgoing.iter()));
                            }
                            drop(node_ref);
                        }
                    }
                }
            }
        }
    }

    WalkResult::Limit(limit)
}
