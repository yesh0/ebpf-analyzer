use std::{
    cell::RefCell,
    fs,
    io::{self, stderr, Write},
    num::Wrapping,
    path::Path,
    rc::Rc,
};

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig},
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::{
        context::NoOpContext,
        helper::HelperCollection,
        run,
        vm::{UncheckedVm, Vm},
    },
    spec::proto::{StaticFunctionCall, VerifiableCall},
    track::{
        pointees::{dyn_region::DynamicRegion, pointed},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
    },
};
use llvm_util::conformance::{get_conformance_data, ConformanceData};

fn test_with_conformance_data(data: ConformanceData) -> Result<(), ()> {
    let v = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(
        HelperCollection::new(&[
            |_, _, _, _, _| 0,
            |_, _, _, _, _| 0,
            |_, _, _, _, _| 0,
            |_, _, _, _, _| 0,
            |_, _, _, _, _| 0,
            |_, _, _, _, _| 0,
        ]),
    )));
    if data.error.is_empty() {
        println!("Testing {}", data.name);
        let result = analyze_with_conformance_data(&data);
        if data.name.contains("-fail") {
            assert!(result.is_err());
            return Ok(());
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
        v.borrow_mut().reg(0).0 = 0xCAFEu64;
        v.borrow_mut().reg(1).0 = data.memory.as_ptr() as u64;
        v.borrow_mut().reg(2).0 = data.memory.len() as u64;
        run(&data.code, &mut v.borrow_mut(), &mut NoOpContext {});
        if v.borrow_mut().ro_reg(0).0 == data.returns {
            Ok(())
        } else {
            println!(
                "Returned {}, expecting {}",
                v.borrow_mut().ro_reg(0),
                data.returns
            );
            Err(())
        }
    } else {
        stderr()
            .write_fmt(format_args!(
                ">>>>>>> Unsupported: {} {} (with error checking)\n",
                data.name, data.error
            ))
            .expect("stderr write error");
        Ok(())
    }
}

const DEFAULT_HELPER: StaticFunctionCall = StaticFunctionCall::nop();

fn analyze_with_conformance_data(data: &ConformanceData) -> Result<(), ()> {
    const HELPERS: &[&dyn VerifiableCall<CheckedValue, BranchState>; 6] = &[
        &DEFAULT_HELPER,
        &DEFAULT_HELPER,
        &DEFAULT_HELPER,
        &DEFAULT_HELPER,
        &DEFAULT_HELPER,
        &DEFAULT_HELPER,
    ];
    match Analyzer::analyze(
        &data.code,
        &AnalyzerConfig {
            processed_instruction_limit: 1000,
            helpers: HELPERS,
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
        },
    ) {
        Ok(_) => Ok(()),
        Err(ebpf_analyzer::analyzer::VerificationError::IllegalStateChange(branch)) => {
            dbg!(branch);
            Err(())
        }
        Err(e) => {
            dbg!(e);
            Err(())
        }
    }
}

const DATA_DIR: &str = "./tests/conformance";

#[cfg(all(feature = "atomic32", feature = "atomic64"))]
#[test]
fn test_conformance() -> Result<(), io::Error> {
    assert!(cfg!(feature = "atomic32"));
    assert!(cfg!(feature = "atomic64"));

    let mut entries: Vec<_> = fs::read_dir(Path::new(DATA_DIR))?
        .filter(|r| r.is_ok())
        .map(|ok| ok.ok().unwrap())
        .collect();
    entries.sort_unstable_by_key(|a| a.file_name());
    for entry in entries {
        let data = get_conformance_data(entry.path().to_str().unwrap())
            .ok()
            .unwrap();
        assert!(test_with_conformance_data(data).is_ok());
    }
    Ok(())
}
