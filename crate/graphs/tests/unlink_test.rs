use ebpf_graphs::DfsResult;
use ebpf_graphs::GraphNode;

#[test]
fn unlink_test() {
    let a = GraphNode::new();
    let b = GraphNode::new();
    let c = GraphNode::new();
    let d = GraphNode::new();

    a.connect_to(&b, 2);
    a.anchor(10);
    b.connect_to(&c, 2);
    c.anchor_from(500);
    c.anchor_to(-500i64 as u64);
    c.connect_to(&d, 2);
    a.connect_to(&d, 2);
    a.connect_to(&c, 2);

    drop(b);
    drop(c);

    assert_eq!(a.reachable_within(&d, 100, 6), DfsResult::Always);
    assert_eq!(a.reachable_within(&d, 100, 7), DfsResult::Maybe);
}