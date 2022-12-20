// Unfortunately, due to possible cyclic dev-dependency,
// which rust-analyzer / cargo does not seem to support very well,
// we cannot reuse the code in another conformance_test.

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig},
    interpreter::vm::Vm,
    spec::proto::helpers::BPF_HELPER_GET_SCALAR,
    track::{
        pointees::{dyn_region::DynamicRegion, pointed},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
    },
};
use ebpf_aot::compiler::{to_ebpf_function, Compiler, Runtime};
use llvm_util::conformance::for_all_conformance_data;

#[test]
fn test_compiler_conformance() {
    const UNSUPPORTED: &[&str] = &[
        // Stack and local call support
        "call-stack",
        "call_local",
        "stack",
    ];
    // If you are to debug this in an IDE (e.g., VS Code),
    // you might want to change the path to "./analyzer/tests/conformance".
    // Or probably you can somehow configure the debugger. I dunno.
    for data in for_all_conformance_data("../../analyzer/tests/conformance").unwrap() {
        if !data.error.is_empty()
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
                setup: &|vm| {
                    let mut region = DynamicRegion::default();
                    region.set_upper_limit(data.memory.len());
                    region.set_limit(&Scalar::constant64(data.memory.len() as u64));
                    let pointee = pointed(region);
                    vm.add_external_resource(pointee.clone());
                    *vm.reg(1) = Pointer::new(
                        PointerAttributes::NON_NULL
                            | PointerAttributes::READABLE
                            | PointerAttributes::MUTABLE
                            | PointerAttributes::ARITHMETIC,
                        pointee,
                    )
                    .into();
                    *vm.reg(2) = Scalar::constant64(data.memory.len() as u64).into();
                },
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
        assert_eq!(
            main_func(
                data.memory.as_ptr() as u64,
                data.memory.len() as u64,
                0,
                0,
                0
            ),
            data.returns,
            "{}",
            data.name
        );
    }
}
