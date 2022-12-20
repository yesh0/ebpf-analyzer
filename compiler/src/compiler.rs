//! An eBPF assembler using Cranelift

use alloc::vec::Vec;
use cranelift_codegen::{
    entity::EntityRef,
    ir::{
        condcodes::IntCC, types::*, AbiParam, Block, Endianness, InstBuilder, MemFlags, Signature,
        StackSlotData, StackSlotKind, UserFuncName, AtomicRmwOp,
    },
    Context,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};
use ebpf_analyzer::{
    blocks::{FunctionBlock, ProgramInfo},
    interpreter::helper::HelperPointer,
    spec::Instruction,
};
use ebpf_consts::*;
use ebpf_macros::opcode_match;

/// eBPF assembler config
pub struct Compiler {}

type LinkageModule = JITModule;

/// Runtime environment for the compiled function
pub struct Runtime<'a> {
    /// Helper functions
    pub helpers: &'static [HelperPointer],
    /// Returns a pointer from a map descriptor
    pub map_fd_mapper: &'a dyn Fn(i32) -> Option<u64>,
}

impl Compiler {
    /// Compiles the code
    pub fn compile(
        &self,
        code: &[u64],
        info: &ProgramInfo,
        runtime: &Runtime,
    ) -> Result<(FuncId, LinkageModule), ModuleError> {
        let builder = JITBuilder::new(cranelift_module::default_libcall_names());
        let mut module = JITModule::new(builder.unwrap());

        assert_eq!(info.functions.len(), 1);

        let mut context = Context::new();
        self.function_signature(&mut context);
        let sig = context.func.signature.clone();
        let sig_ref = context.func.import_signature(sig);
        let mut builder_context = FunctionBuilderContext::new();
        let functions = self.functions(info, &mut module, &context.func.signature)?;

        for (i, f) in info.functions.iter().enumerate() {
            let mut builder = FunctionBuilder::new(&mut context.func, &mut builder_context);
            let stack = builder
                .create_sized_stack_slot(StackSlotData::new(StackSlotKind::ExplicitSlot, 512));
            let registers = self.function_registers(&mut builder);

            let mut blocks: Vec<Block> = Vec::new();
            blocks.reserve(f.block_starts.len());
            for _ in 0..f.block_starts.len() {
                blocks.push(builder.create_block());
            }

            let mut mem_flags = MemFlags::new();
            mem_flags.set_notrap();

            for (j, block) in blocks.iter().enumerate() {
                let (start, end) = self.get_block_range(code, info, i, j);
                if j == 0 {
                    builder.append_block_params_for_function_params(*block);
                    builder.switch_to_block(*block);
                    (1..=5).for_each(|k| {
                        let param = builder.block_params(*block)[k - 1];
                        builder.def_var(registers[k], param);
                    });
                    let stack_base = builder.ins().stack_addr(I64, stack, 0);
                    let stack_top = builder.ins().iadd_imm(stack_base, 512);
                    builder.def_var(registers[10], stack_top);
                } else {
                    builder.switch_to_block(*block);
                }
                let mut pc = start;
                let mut jumped = false;
                while pc < end {
                    let insn = Instruction::from_raw(code[pc]);
                    pc += 1;
                    let opcode = insn.opcode;
                    opcode_match! {
                        opcode,
                        // ALU / ALU64: BInary operators
                        [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
                         [
                            // Algebraic
                            BPF_ADD: iadd,
                            BPF_SUB: isub,
                            BPF_MUL: imul,
                            BPF_DIV: udiv,
                            BPF_MOD: urem,
                            // Bitwise
                            BPF_AND: band,
                            BPF_OR : bor,
                            BPF_XOR: bxor,
                            BPF_LSH: ishl,
                            BPF_RSH: ushr,
                            BPF_ARSH: sshr,
                            // Mov
                            BPF_MOV: MOV,
                         ]
                        ] => {
                            let dst_reg = registers[insn.dst_reg() as usize];
                            #?((ALU32))
                                let t = I32;
                            ##
                            #?((ALU64))
                                let t = I64;
                            ##
                            // Allowing dead code
                            let _ = t;

                            #?((K))
                                #?((MOV))
                                    let result = builder.ins().iconst(t, insn.imm as i64);
                                ##
                                #?((__MOV__))
                                    let dst = builder.use_var(dst_reg);
                                    #?((ALU32))
                                        let dst = builder.ins().ireduce(t, dst);
                                    ##

                                    #?((__isub__))
                                        let result = builder.ins().#"{}_imm"2(dst, insn.imm as i64);
                                    ##
                                    #?((isub))
                                        // There is no `isub_imm`
                                        let result = builder.ins().iadd_imm(dst, -(insn.imm as i64));
                                    ##
                                ##
                            ##

                            #?((X))
                                let rhs = builder.use_var(registers[insn.src_reg() as usize]);
                                #?((ALU32))
                                    let rhs = builder.ins().ireduce(I32, rhs);
                                ##

                                // Avoid FPU traps
                                #?((udiv)|(urem))
                                    let is_zero = builder.ins().icmp_imm(IntCC::Equal, rhs, 0);
                                    let one = builder.ins().iconst(t, 1);
                                    let rhs = builder.ins().select(is_zero, one, rhs);
                                ##

                                #?((MOV))
                                    let result = rhs;
                                ##
                                #?((__MOV__))
                                    let dst = builder.use_var(dst_reg);
                                    #?((ALU32))
                                        let dst = builder.ins().ireduce(I32, dst);
                                    ##
                                    let result = builder.ins().#=2(dst, rhs);
                                ##

                                // Make behaviours match the spec
                                #?((udiv))
                                    // zero_division ? 0 : result
                                    let zero = builder.ins().iconst(t, 0);
                                    let result = builder.ins().select(is_zero, zero, result);
                                ##
                                #?((urem))
                                    // zero_division ? dst : result
                                    let result = builder.ins().select(is_zero, dst, result);
                                ##
                            ##

                            #?((ALU32))
                                let result = builder.ins().uextend(I64, result);
                            ##
                            builder.def_var(dst_reg, result);
                        }
                        // ALU / ALU64: Unary operators
                        [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_K: K],
                         [BPF_NEG: neg]] => {
                            let dst_reg = registers[insn.dst_reg() as usize];
                            let value = builder.use_var(dst_reg);
                            let result = builder.ins().ineg(value);
                            #?((ALU32))
                                let result = builder.ins().ireduce(I32, result);
                                let result = builder.ins().uextend(I64, result);
                            ##
                            builder.def_var(dst_reg, result);
                        }
                        // BPF_EXIT: Returns
                        [[BPF_JMP: JMP], [BPF_EXIT: EXIT]] => {
                            let result = builder.use_var(registers[0]);
                            builder.ins().return_(&[result]);
                            jumped = true;
                        }
                        // BPF_CALL: Calls
                        [[BPF_JMP: JMP], [BPF_CALL: CALL]] => {
                            if insn.src_reg() == 0 {
                                let helper = insn.imm;
                                let callee = builder.ins().iconst(
                                    I64, runtime.helpers[helper as usize] as *const
                                    HelperPointer as u64 as i64);
                                let args = &[
                                    builder.use_var(registers[1]),
                                    builder.use_var(registers[2]),
                                    builder.use_var(registers[3]),
                                    builder.use_var(registers[4]),
                                    builder.use_var(registers[5]),
                                ];
                                let inst = builder.ins().call_indirect(sig_ref, callee, args);
                                let result = builder.func.dfg.first_result(inst);
                                builder.def_var(registers[0], result);
                            }
                        }
                        // BPF_JA: Unconditional jump
                        [[BPF_JMP: JMP], [BPF_JA: JA]] => {
                            builder.ins().jump(blocks[f.from[j][0]], &[]);
                            jumped = true;
                        }
                        // JMP32 / JMP: Conditional
                        [[BPF_JMP32: JMP32, BPF_JMP: JMP64], [BPF_X: X, BPF_K: K],
                         [
                            // Unsigned
                            BPF_JEQ: Equal,
                            BPF_JLT: UnsignedLessThan,
                            BPF_JLE: UnsignedLessThanOrEqual,
                            BPF_JSLT: SignedLessThan,
                            BPF_JSLE: SignedLessThanOrEqual,
                            // Inverse
                            BPF_JNE: NotEqual,
                            BPF_JGT: UnsignedGreaterThan,
                            BPF_JGE: UnsignedGreaterThanOrEqual,
                            BPF_JSGT: SignedGreaterThan,
                            BPF_JSGE: SignedGreaterThanOrEqual,
                            // Misc
                            BPF_JSET: JSET,
                         ]
                        ] => {
                            let dst_reg = registers[insn.dst_reg() as usize];
                            let dst = builder.use_var(dst_reg);
                            #?((JMP32))
                                let dst = builder.ins().ireduce(I32, dst);
                            ##

                            #?((K))
                                #?((__JSET__))
                                    let cmp = IntCC::#=2;
                                    let c = builder.ins().icmp_imm(cmp, dst, insn.imm as i64);
                                ##
                                #?((JSET))
                                    let c = builder.ins().band_imm(dst, insn.imm as i64);
                                ##
                            ##
                            #?((X))
                                let rhs = builder.use_var(registers[insn.src_reg() as usize]);
                                #?((JMP32))
                                    let rhs = builder.ins().ireduce(I32, rhs);
                                ##
                                #?((__JSET__))
                                    let cmp = IntCC::#=2;
                                    let c = builder.ins().icmp(cmp, dst, rhs);
                                ##
                                #?((JSET))
                                    let c = builder.ins().band(dst, rhs);
                                ##
                            ##

                            let (to, fall_through) = self.get_branch_info(f, j);
                            builder.ins().brnz(c, blocks[to], &[]);
                            builder.ins().jump(blocks[fall_through], &[]);
                            jumped = true;
                        }
                        [[BPF_LD: LD], [BPF_IMM: IMM], [BPF_DW: DW]] => {
                            let next = code[pc];
                            pc += 1;
                            match insn.src_reg() {
                                BPF_IMM64_IMM => {
                                    let value = insn.imm as u32 as u64 | (next & 0xFFFF_FFFF_0000_0000);
                                    let rhs = builder.ins().iconst(I64, value as i64);
                                    builder.def_var(registers[insn.dst_reg() as usize], rhs);
                                }
                                _ => panic!("Unsupported instruction"),
                            }
                        }
                        [[BPF_LDX: LDX], [BPF_MEM: MEM],
                         [
                            BPF_B: I8,
                            BPF_H: I16,
                            BPF_W: I32,
                            BPF_DW: I64,
                         ]
                        ] => {
                            let t = #=2;
                            let src_reg = registers[insn.src_reg() as usize];
                            let pointer = builder.use_var(src_reg);
                            let value = builder.ins().load(t, mem_flags, pointer, insn.off as i32);
                            #?((__I64__))
                                let value = builder.ins().uextend(I64, value);
                            ##
                            builder.def_var(registers[insn.dst_reg() as usize], value);
                        }
                        [[BPF_STX: STX, BPF_ST: ST], [BPF_MEM: MEM],
                         [
                            BPF_B: I8,
                            BPF_H: I16,
                            BPF_W: I32,
                            BPF_DW: I64,
                         ]
                        ] => {
                            #?((STX))
                                let value = builder.use_var(registers[insn.src_reg() as usize]);
                                #?((__I64__))
                                    let t = #=2;
                                    let value = builder.ins().ireduce(t, value);
                                ##
                            ##
                            #?((ST))
                                let t = #=2;
                                let value = builder.ins().iconst(t, insn.imm as u32 as u64 as i64);
                            ##
                            let pointer = builder.use_var(registers[insn.dst_reg() as usize]);
                            builder.ins().store(mem_flags, value, pointer, insn.off as i32);
                        }
                        // ALU / ALU64: Byte swap
                        [[BPF_ALU: ALU32], [BPF_END: END],
                         [
                            BPF_TO_LE: Little,
                            BPF_TO_BE: Big,
                         ]
                        ] => {
                            let t = match insn.imm {
                                64 => I64,
                                32 => I32,
                                16 => I16,
                                _ => panic!("Unsupported width"),
                            };

                            let dst_reg = registers[insn.dst_reg() as usize];
                            let value = builder.use_var(dst_reg);
                            let value = if t == I64 {
                                value
                            } else {
                                builder.ins().ireduce(t, value)
                            };

                            let target = Endianness::#=2;
                            let result = if target == module.isa().endianness() {
                                value
                            } else {
                                builder.ins().bswap(value)
                            };
                            let result = if t == I64 {
                                result
                            } else {
                                builder.ins().uextend(I64, result)
                            };
                            builder.def_var(dst_reg, result);
                        }
                        [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_W: W]] => {
                            self.push_atomic(insn, &mut builder, &registers, I32);
                        }
                        [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_DW: DW]] => {
                            self.push_atomic(insn, &mut builder, &registers, I64);
                        }
                        _ => {
                            panic!("Unsupported instruction");
                        }
                    }
                }
                if !jumped {
                    builder.ins().jump(blocks[j + 1], &[]);
                }
            }
            builder.seal_all_blocks();
            builder.finalize();

            module.define_function(functions[i], &mut context)?;
            module.clear_context(&mut context);
        }
        module.finalize_definitions()?;
        Ok((functions[0], module))
    }

    fn push_atomic(
        &self,
        insn: Instruction,
        builder: &mut FunctionBuilder,
        registers: &[Variable],
        t: Type,
    ) {
        let atomic_code = insn.imm;
        let mem_flags = MemFlags::new().with_notrap();

        let dst = builder.use_var(registers[insn.dst_reg() as usize]);
        let dst = builder.ins().iadd_imm(dst, insn.off as i64);

        let src_reg = registers[insn.src_reg() as usize];
        let src_value = builder.use_var(src_reg);
        let src = if t == I32 {
            builder.ins().ireduce(I32, src_value)
        } else {
            src_value
        };

        opcode_match! {
            atomic_code as i32,
            [[BPF_ATOMIC_FETCH: FETCH, BPF_ATOMIC_NO_FETCH: NO_FETCH],
             [
                BPF_ATOMIC_ADD: Add,
                BPF_ATOMIC_OR : Or,
                BPF_ATOMIC_AND: And,
                BPF_ATOMIC_XOR: Xor,
                BPF_ATOMIC_XCHG: Xchg,
             ]
            ] => {
                let op = AtomicRmwOp::#=1;
                #?((FETCH))
                    let result = builder.ins().atomic_rmw(t, mem_flags, op, dst, src);
                    let result = if t == I32 {
                        builder.ins().uextend(I64, result)
                    } else {
                        result
                    };
                    builder.def_var(src_reg, result);
                ##
                #?((__FETCH__))
                    builder.ins().atomic_rmw(t, mem_flags, op, dst, src);
                ##
            }
            [[BPF_ATOMIC_FETCH: FETCH], [BPF_ATOMIC_CMPXCHG: CMPXCHG]] => {
                let expected_value = builder.use_var(registers[0]);
                let expected = if t == I32 {
                    builder.ins().ireduce(I32, expected_value)
                } else {
                    expected_value
                };
                let result = builder.ins().atomic_cas(mem_flags, dst, expected, src);
                let result = if t == I32 {
                    builder.ins().uextend(I64, result)
                } else {
                    result
                };
                builder.def_var(registers[0], result);
            }
            _ => panic!("Unsupported atomic operation")
        }
    }

    fn get_branch_info(&self, info: &FunctionBlock, i: usize) -> (usize, usize) {
        let targets = &info.from[i];
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&(i + 1)));
        let to = if targets[0] == i + 1 {
            targets[1]
        } else {
            targets[0]
        };
        (to, i + 1)
    }

    fn functions(
        &self,
        info: &ProgramInfo,
        module: &mut LinkageModule,
        signature: &Signature,
    ) -> Result<Vec<FuncId>, ModuleError> {
        assert_eq!(info.functions.len(), 1);

        let mut functions: Vec<FuncId> = Vec::new();
        functions.reserve(info.functions.len());

        for i in 0..(info.functions.len() as u32) {
            let id = module.declare_function(
                &UserFuncName::user(0, i).to_string(),
                Linkage::Export,
                signature,
            )?;
            functions.push(id);
        }
        Ok(functions)
    }

    fn function_registers(&self, builder: &mut FunctionBuilder) -> [Variable; 11] {
        let registers: [Variable; 11] = [
            Variable::new(0),
            Variable::new(1),
            Variable::new(2),
            Variable::new(3),
            Variable::new(4),
            Variable::new(5),
            Variable::new(6),
            Variable::new(7),
            Variable::new(8),
            Variable::new(9),
            Variable::new(10),
        ];
        for register in registers {
            builder.declare_var(register, I64);
        }
        registers
    }

    fn function_signature(&self, context: &mut Context) {
        let sig = &mut context.func.signature;
        sig.params.clear();
        sig.returns.clear();

        sig.returns.push(AbiParam::new(I64));
        for _ in 0..5 {
            sig.params.push(AbiParam::new(I64));
        }
    }

    fn get_block_range(
        &self,
        code: &[u64],
        info: &ProgramInfo,
        function_i: usize,
        block_i: usize,
    ) -> (usize, usize) {
        let function_end = info
            .functions
            .get(function_i + 1)
            .map(|f| f.block_starts[0])
            .unwrap_or(code.len());
        let block_end = info.functions[function_i]
            .block_starts
            .get(block_i + 1)
            .unwrap_or(&function_end);
        (info.functions[function_i].block_starts[block_i], *block_end)
    }
}

/// Transmutes a pointer to a function of eBPF function signature
///
/// # Safety
/// It uses [core::mem::transmute] under the hood.
pub unsafe fn to_ebpf_function(pointer: *const u8) -> HelperPointer {
    unsafe { core::mem::transmute::<_, HelperPointer>(pointer) }
}

#[cfg(test)]
static mut INJECTED: u64 = 0;

#[cfg(test)]
fn println_tester(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64 {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    std::println!("Hello World: {r1} {r2} {r3} {r4} {r5}");
    unsafe { INJECTED = time.as_millis() as u64 };
    unsafe { INJECTED }
}

#[cfg(test)]
fn nop(_: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    0
}

#[test]
fn test_some() {
    if std::env::var(BPF_CONF_RUNNER).is_err() {
        std::env::set_var(
            BPF_CONF_RUNNER,
            "../analyzer/tests/bpf_conformance/build/bin/bpf_conformance_runner",
        );
    }
    let c = Compiler {};
    let data = llvm_util::conformance::assemble(
        "mov r0, 1
xor r0, r0
add r0, r1
sub r0, r2
add r0, r3
sub r0, r4
add r0, r5
mov r6, r0
call 1
add r0, r6
exit",
    );
    use ebpf_analyzer::interpreter::vm::Vm;
    use llvm_util::conformance::BPF_CONF_RUNNER;
    let (main, module) = c
        .compile(
            &data.code,
            &ebpf_analyzer::analyzer::Analyzer::analyze(
                &data.code,
                &ebpf_analyzer::analyzer::AnalyzerConfig {
                    helpers: &[
                        ebpf_analyzer::spec::proto::helpers::BPF_HELPER_GET_SCALAR,
                        ebpf_analyzer::spec::proto::helpers::BPF_HELPER_GET_SCALAR,
                    ],
                    setup: &|vm| {
                        for i in 1..=5 {
                            *vm.reg(i) = ebpf_analyzer::track::scalar::Scalar::unknown().into();
                        }
                    },
                    processed_instruction_limit: 20,
                    map_fd_collector: &|_| None,
                },
            )
            .unwrap(),
            &Runtime {
                helpers: &[nop, println_tester],
                map_fd_mapper: &|_| None,
            },
        )
        .unwrap();
    let entry = module.get_finalized_function(main);
    let main_fn = unsafe { to_ebpf_function(entry) };

    let mut i = 137u32;
    for _ in 0..1000 {
        i = (i * 37) % 349;
        let j = i as u64;
        assert_eq!(
            main_fn(j * 5, j * 4, j * 3, j * 2, j),
            j * 3 + unsafe { INJECTED }
        );
    }
}
