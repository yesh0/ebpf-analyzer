//! Tests from https://github.com/vbpf/ebpf-samples/

use core::slice::from_raw_parts;

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, MapInfo},
    spec::proto::helpers::HELPERS, track::{pointees::{dyn_region::DynamicRegion, pointed}, pointer::Pointer}, interpreter::vm::Vm,
};
use ebpf_consts::maps::MapType;
use llvm_util::object::load_programs;

#[test]
fn test_simple() {
    let (obj, maps) = load_programs("./tests/bpf-samples/linux/cpustat_kern.o");
    assert_eq!(obj.programs.len(), 2);
    assert_eq!(maps.len(), 4);
    for (name, program) in obj.programs {
        let code = unsafe {
            from_raw_parts(
                program.function.instructions.as_ptr() as *const u64,
                program.function.instructions.len(),
            )
        };
        Analyzer::analyze(
            code,
            &AnalyzerConfig {
                helpers: HELPERS,
                setup: &|vm| {
                    let region = pointed(DynamicRegion::new(8 + 4 + 4));
                    vm.add_external_resource(region.clone());
                    *vm.reg(1) = Pointer::nrwa(region).into();
                },
                processed_instruction_limit: 100_000,
                map_fd_collector: &|fd| {
                    maps.get(&fd).map(|info| MapInfo {
                        map_type: MapType::Array,
                        max_size: 1,
                        key_size: info.key_size(),
                        value_size: info.value_size(),
                    })
                },
            },
        )
        .map_err(|e| (name, e))
        .unwrap();
    }
}
