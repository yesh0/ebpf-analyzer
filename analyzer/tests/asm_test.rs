use std::env;

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, VerificationError},
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::vm::Vm,
    spec::proto::{ArgumentType, ReturnType, StaticFunctionCall, VerifiableCall},
    track::{
        pointees::{dyn_region::DynamicRegion, empty_region::EmptyRegion, pointed},
        pointer::{Pointer, PointerAttributes},
    },
};
use llvm_util::conformance::{assemble, BPF_CONF_RUNNER};

fn test_with_assembly(
    asm: &str,
    helpers: &'static [&'static dyn VerifiableCall<CheckedValue, BranchState>],
    setup: &dyn Fn(&mut BranchState),
    success: bool,
    pc: usize,
) {
    if env::var(BPF_CONF_RUNNER).is_err() {
        env::set_var(
            BPF_CONF_RUNNER,
            "tests/bpf_conformance/build/bin/bpf_conformance_runner",
        );
    }
    let data = assemble(asm);
    match Analyzer::analyze(
        &data.code,
        &AnalyzerConfig {
            helpers,
            setup,
            processed_instruction_limit: 20,
            map_fd_collector: &|_| None,
        },
    ) {
        Ok(_) if success => {}
        Ok(_) => panic!("Expecting error"),
        Err(e) if !success => {
            std::println!("Captured: {e:?}");
            match e {
                VerificationError::IllegalStateChange(branch) => {
                    assert_eq!(*branch.borrow_mut().pc(), pc);
                }
                _ => panic!("Check your assembly"),
            }
        }
        Err(e) => panic!("{e:?}"),
    }
}

const POINTER_HELPERS: &[&'static dyn VerifiableCall<CheckedValue, BranchState>] = &[
    &StaticFunctionCall::nop(),
    &StaticFunctionCall::new(
        [
            ArgumentType::FixedMemory(4),
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ],
        ReturnType::None,
    ),
];

fn test_pointer_checks(asm: &str, success: bool, pc: usize) {
    test_with_assembly(
        asm,
        POINTER_HELPERS,
        &|vm| {
            let region = DynamicRegion::new(8);
            let pointee = pointed(region);
            // Nullable, readable
            *vm.reg(1) = Pointer::new(
                PointerAttributes::READABLE | PointerAttributes::ARITHMETIC,
                pointee.clone(),
            )
            .into();
            // Nullable, writable
            *vm.reg(2) = Pointer::new(PointerAttributes::MUTABLE, pointee.clone()).into();
            // Nullable, arithmetic
            *vm.reg(3) = Pointer::new(
                PointerAttributes::MUTABLE | PointerAttributes::ARITHMETIC,
                pointee.clone(),
            )
            .into();
            // Nullable, end pointer
            *vm.reg(4) = Pointer::new(PointerAttributes::DATA_END, pointee.clone()).into();
            let empty = EmptyRegion::instance();
            vm.add_external_resource(empty.clone());
            vm.add_external_resource(pointee.clone());
            // Another region
            *vm.reg(5) = Pointer::new(
                PointerAttributes::NON_NULL | PointerAttributes::ARITHMETIC,
                empty,
            )
            .into();

            // Nullable, readable
            *vm.reg(6) = Pointer::rwa(pointee).into();
        },
        success,
        pc,
    )
}

#[test]
fn test_pointers() {
    // reading nullable
    test_pointer_checks("ldxdw r0, [r1+0]\nexit", false, 1);
    // reading readable
    test_pointer_checks(
        "mov r0, 0\njeq r1, 0, exit\nldxdw r0, [r1+0]\nexit",
        true,
        0xff,
    );
    // reading unreadable
    test_pointer_checks("jeq r2, 0, exit\nldxdw r0, [r2+0]\nexit", false, 2);

    // writing nullable
    test_pointer_checks("mov r0, 0\nstxdw [r2+0], r0\nexit", false, 2);
    // writing mutable
    test_pointer_checks(
        "mov r0, 0\njeq r2, 0, exit\nstxdw [r2+0], r0\nexit",
        true,
        0xff,
    );
    // writing immutable
    test_pointer_checks(
        "mov r0, 0\njeq r1, 0, exit\nstxdw [r1+0], r0\nexit",
        false,
        3,
    );

    // arithmetic not allowed
    test_pointer_checks("add r1, 1\nexit", false, 1);
    test_pointer_checks("add r2, 1\nexit", false, 1);
    test_pointer_checks("add r3, 1\nexit", false, 1);
    test_pointer_checks("jeq r2, 0, exit\nadd r2, 1\nexit", false, 2);
    // arithmetic allowed
    test_pointer_checks("mov r0, 0\njeq r3, 0, exit\nadd r3, 1\nexit", true, 0xff);
    test_pointer_checks("mov r0, 0\njeq r3, 0, exit\nsub r3, 1\nexit", true, 0xff);
    // others not allowed
    test_pointer_checks("jeq r3, 0, exit\nmul r3, 2\nexit", false, 2);
    test_pointer_checks("jeq r3, 0, exit\nlsh r3, 2\nexit", false, 2);
    // subtracting
    test_pointer_checks("jeq r3, 0, exit\nsub r3, r1\nexit", false, 2);
    test_pointer_checks(
        "mov r0, 0\njeq r3, 0, exit\njeq r1, 0, exit\nsub r3, r1\nexit",
        true,
        0xff,
    );
    test_pointer_checks("jeq r3, 0, exit\nsub r3, r5\nexit", false, 2);

    // data end comparison
    test_pointer_checks("jlt r1, r4, exit\nexit", false, 1);
    test_pointer_checks("jeq r4, 0, exit\njlt r1, r4, exit\nexit", false, 2);
    test_pointer_checks("jeq r1, 0, exit\njlt r1, r4, exit\nexit", false, 2);
    test_pointer_checks(
        "mov r0, 0\njeq r1, 0, exit\njeq r4, 0, exit\njlt r1, r4, exit\nexit",
        true,
        0xff,
    );

    // get_all, set_all
    test_pointer_checks("mov r1, r2\ncall 1\nexit", false, 2);
    test_pointer_checks("jeq r1, 0, exit\ncall 1\nexit", false, 2);
    test_pointer_checks("jeq r2, 0, exit\nmov r1, r2\ncall 1\nexit", false, 3);
    test_pointer_checks(
        "jeq r3, 0, exit\nmov r1, r3\nadd r1, 4\ncall 1\nexit",
        false,
        4,
    );
    test_pointer_checks(
        "jeq r2, 0, exit\nmov r1, r2\nmov r0, 1\nmul r0, 4\nadd r1, r0\ncall 1\nexit",
        false,
        5,
    );
    test_pointer_checks(
        "mov r0, 0\nmov r1, r6\njeq r1, 0, exit\ncall 1\nmov r0, 0\nexit",
        true,
        0xff,
    );
    test_pointer_checks(
        "mov r0, 0\nmov r1, r6\njeq r1, 0, exit\nadd r1, 4\ncall 1\nmov r0, 0\nexit",
        true,
        0xff,
    );
    test_pointer_checks(
        "mov r1, r6\njeq r1, 0, exit\nadd r1, 6\ncall 1\nexit",
        false,
        4,
    );
    test_pointer_checks(
        "mov r1, r6\njeq r1, 0, exit\nadd r1, 8\ncall 1\nexit",
        false,
        4,
    );
}

#[test]
fn test_stack_multi_borrow() {
    test_pointer_checks(
        r#"stxdw [r10-8], r10
stxdw [r10-16], r1
mov r0, 0
div r0, r0
jeq r0, 0, exit
add r0, 1
exit"#,
        true,
        0xff,
    );
}
