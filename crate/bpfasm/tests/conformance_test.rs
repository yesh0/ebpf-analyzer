// Unfortunately, due to possible cyclic dev-dependency,
// which rust-analyzer / cargo does not seem to support very well,
// we cannot reuse the code in another conformance_test.

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig},
    spec::proto::helpers::BPF_HELPER_GET_SCALAR,
};
use ebpf_aot::compiler::{to_ebpf_function, Compiler, Runtime};
use llvm_util::conformance::for_all_conformance_data;

#[test]
fn test_compiler_conformance() {
    const UNSUPPORTED: &[&str] = &["call-stack", "call_local", "lock", "neg", "stack"];
    // If you are to debug this in an IDE (e.g., VS Code),
    // you might want to change the path to "./tests/conformance".
    // Or probably you can somehow configure the debugger. I dunno.
    for data in for_all_conformance_data("../../tests/conformance").unwrap() {
        if !data.memory.is_empty()
            || !data.error.is_empty()
            || data.name.contains("-fail")
            || UNSUPPORTED
                .iter()
                .any(|unsupported| data.name.contains(unsupported))
        {
            std::println!("Unsupported {}", data.name);
            continue;
        }
        std::println!("Running {}", data.name);
        let info = Analyzer::analyze(
            &data.code,
            &AnalyzerConfig {
                helpers: &[
                    BPF_HELPER_GET_SCALAR,
                    BPF_HELPER_GET_SCALAR,
                    BPF_HELPER_GET_SCALAR,
                    BPF_HELPER_GET_SCALAR,
                    BPF_HELPER_GET_SCALAR,
                    BPF_HELPER_GET_SCALAR,
                ],
                setup: &|_| {},
                processed_instruction_limit: 1_000_000,
                map_fd_collector: &|_| None,
            },
        )
        .unwrap();
        let c = Compiler {};
        let (main, module) = c
            .compile(
                &data.code,
                &info,
                &Runtime {
                    helpers: &[
                        |_, _, _, _, _| 0,
                        |_, _, _, _, _| 0,
                        |_, _, _, _, _| 0,
                        |_, _, _, _, _| 0,
                        |_, _, _, _, _| 0,
                        |_, _, _, _, _| 0,
                    ],
                    map_fd_mapper: &|_| None,
                },
            )
            .unwrap();
        let main_func = unsafe { to_ebpf_function(module.get_finalized_function(main)) };
        if data.name.contains("jeq-imm") {
            std::println!("Prepare");
        }
        assert_eq!(main_func(0, 0, 0, 0, 0), data.returns, "{}", data.name);
    }
}
