use std::vec::Vec;

use ebpf_graphs::DfsResult;
use ebpf_graphs::GraphNode;

#[test]
fn simple_test() {
    let mut v: Vec<GraphNode> = Vec::new();
    for i in 0..5 {
        v.push(GraphNode::new());
    }

    v[0].connect_to(&v[1], 1);
    v[1].connect_to(&v[2], 1);
    v[2].connect_to(&v[3], 1);
    v[3].connect_to(&v[2], -1);
    v[3].connect_to(&v[4], 1);

    assert_eq!(v[0].reachable_within(&v[4], 100, 3), DfsResult::Always);
    assert_eq!(v[0].reachable_within(&v[4], 100, 4), DfsResult::Always);
    assert_eq!(v[0].reachable_within(&v[4], 100, 5), DfsResult::Maybe);
}

#[test]
fn const_test() {
    let mut v: Vec<GraphNode> = Vec::new();
    for i in 0..5 {
        v.push(GraphNode::new());
    }

    // v0 >= v2 + 5 == 10 + 5 == 15
    v[0].connect_to(&v[1], 1);
    v[1].connect_to(&v[2], 1);
    v[0].connect_to(&v[2], 5);
    v[2].anchor(10);

    // 20 == v3 >= v4 + 5
    // 15 >= v4
    v[3].anchor(20);
    v[3].connect_to(&v[4], 5);

    // v0 >= v4
    assert_eq!(v[0].reachable_within(&v[4], 100, 0), DfsResult::Always);
    // v0 >= v4 ?
    assert_eq!(v[0].reachable_within(&v[4], 100, 1), DfsResult::Maybe);
    // v0 >= v4 - 1
    assert_eq!(v[0].reachable_within(&v[4], 100, -1), DfsResult::Always);
    // v4 >= v0 ?
    assert_eq!(v[4].reachable_within(&v[0], 100, 0), DfsResult::Maybe);
    // v4 >= v0 + 1!
    assert_eq!(v[4].reachable_within(&v[0], 100, 1), DfsResult::Never);
    assert_eq!(v[4].reachable_within(&v[0], 100, 10), DfsResult::Never);
    assert_eq!(v[4].reachable_within(&v[0], 100, 100), DfsResult::Never);
    assert_eq!(v[4].reachable_within(&v[0], 100, -1), DfsResult::Maybe);
}

const O: i64 = i64::MIN;

#[test]
fn dfs_test() {
    let v: Vec<i64> = vec![
        0, 1, 1, 1, 1, 1, 1, 0, 0, O,
        0, 0, 1, 1, 1, 1, 1, 0, 0, 0,
        0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 1, 9, 0, 0, 0, 0, 1,
        0, 0, 0, 1, 9, 0, 0, 0, 0, 0,
    ];
    // N0 >= N9 + 9
    for i in 10..20 {
        assert_reachable_within(
            &v, 10, 0, 9, i, DfsResult::Maybe,
        );
    }
    for i in -10..10 {
        assert_reachable_within(
            &v, 10, 0, 9, i, DfsResult::Always,
        );
    }
    let v: Vec<i64> = vec![
        0, 1, 9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 9, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 9, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 9, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 9, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 9, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 9, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    // N0 >= N9 + 5 * 9
    assert_reachable_within(
        &v, 10, 0, 9, 45, DfsResult::Always,
    );
    assert_reachable_within(
        &v, 10, 0, 9, 46, DfsResult::Maybe,
    );
}

fn assert_reachable_within(v: &Vec<i64>, size: usize, from: usize, to: usize, cost: i64, result: DfsResult) {
    assert_eq!(v.len(), size * size);

    let mut nodes: Vec<GraphNode> = Vec::new();
    for i in 0..size {
        nodes.push(GraphNode::new());
    }

    for i in 0..size {
        for j in 0..size {
            if v[i * size + j] != 0 {
                let rel: i64 = if v[i * size + j] == O {
                    0
                } else {
                    v[i * size + j]
                };
                nodes[i].connect_to(&nodes[j], rel);
            }
        }
    }

    assert_eq!(nodes[from].reachable_within(&nodes[to], 100, cost), result);
}
