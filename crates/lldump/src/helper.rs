/// eBPF helper: NOP
pub fn nop(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    0
}

/// eBPF helper: As is: mostly used to prevent LLVM optimizing things away
pub fn as_is(i: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    i
}

/// eBPF helper: Absolutely not a random number gen
pub fn rand(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() % 416 + 16
}

#[test]
fn test_simple_helpers() {
    assert_eq!(0, nop(0, 0, 0, 0, 0));
    assert!((16..=(16+416)).contains(&rand(0, 0, 0, 0, 0)));
}
