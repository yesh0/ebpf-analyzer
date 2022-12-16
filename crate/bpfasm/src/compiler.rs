//! An eBPF assembler using Cranelift

use alloc::vec::Vec;
use cranelift_codegen::{
    entity::EntityRef,
    ir::{
        types::*, AbiParam, Block, InstBuilder, Signature, StackSlotData, StackSlotKind,
        UserFuncName,
    },
    Context,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module, ModuleError};
use ebpf_analyzer::{blocks::ProgramInfo, spec::Instruction};
use ebpf_consts::*;
use ebpf_macros::opcode_match;

/// eBPF assembler config
pub struct Compiler<'a> {
    /// Returns a pointer from a map descriptor
    pub map_fd_mapper: &'a dyn Fn(i32) -> Option<u64>,
}

type LinkageModule = JITModule;

impl Compiler<'_> {
    /// Compiles the code
    pub fn compile(
        &self,
        code: &[u64],
        info: &ProgramInfo,
    ) -> Result<(FuncId, LinkageModule), ModuleError> {
        let builder = JITBuilder::new(cranelift_module::default_libcall_names());
        let mut module = JITModule::new(builder.unwrap());

        assert_eq!(info.functions.len(), 1);

        let mut context = Context::new();
        self.function_signature(&mut context);
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
                while pc < end {
                    let insn = Instruction::from_raw(code[pc]);
                    pc += 1;
                    let opcode = insn.opcode;
                    opcode_match! {
                        opcode,
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
                            // Mov
                            BPF_MOV: MOV,
                         ]
                        ] => {
                            let dst_reg = registers[insn.dst_reg() as usize];
                            #?((K))
                                #?((ALU32))
                                    let t = I32;
                                ##
                                #?((ALU64))
                                    let t = I64;
                                ##
                                let rhs = builder.ins().iconst(t, insn.imm as i64);
                            ##
                            #?((X))
                                let rhs = builder.use_var(registers[insn.src_reg() as usize]);
                                #?((ALU32))
                                    let rhs = builder.ins().ireduce(I32, rhs);
                                ##
                            ##

                            #?((__MOV__))
                                let dst = builder.use_var(dst_reg);
                                #?((ALU32))
                                    let dst = builder.ins().ireduce(I32, dst);
                                ##

                                let result = builder.ins().#=2(dst, rhs);
                                #?((ALU32))
                                    let result = builder.ins().uextend(I64, result);
                                ##
                                builder.def_var(dst_reg, result);
                            ##
                            #?((MOV))
                                builder.def_var(dst_reg, rhs);
                            ##
                        }
                        [[BPF_JMP: JMP], [BPF_EXIT: EXIT]] => {
                            let result = builder.use_var(registers[0]);
                            builder.ins().return_(&[result]);
                        }
                        _ => {
                            panic!();
                        }
                    }
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

#[test]
fn test_some() {
    if std::env::var(BPF_CONF_RUNNER).is_err() {
        std::env::set_var(
            BPF_CONF_RUNNER,
            "../../tests/bpf_conformance/build/bin/bpf_conformance_runner",
        );
    }
    let c = Compiler {
        map_fd_mapper: &|_| None,
    };
    let data = llvm_util::conformance::assemble(
        "mov r0, 1
add r0, r1
sub r0, r2
add r0, r3
sub r0, r4
add r0, r5
exit",
    );
    use llvm_util::conformance::BPF_CONF_RUNNER;
    use ebpf_analyzer::interpreter::vm::Vm;
    let (main, module) = c
        .compile(
            &data.code,
            &ebpf_analyzer::analyzer::Analyzer::analyze(
                &data.code,
                &ebpf_analyzer::analyzer::AnalyzerConfig {
                    helpers: Default::default(),
                    setup: &|vm| {
                        for i in 1..=5 {
                            *vm.reg(i) = ebpf_analyzer::track::scalar::Scalar::unknown().into();
                        }
                    },
                    processed_instruction_limit: 10,
                    map_fd_collector: &|_| None,
                },
            )
            .unwrap(),
        )
        .ok()
        .unwrap();
    let entry = module.get_finalized_function(main);
    let main_fn = unsafe { core::mem::transmute::<_, fn(u64, u64, u64, u64, u64) -> u64>(entry) };

    let mut i = 137u32;
    for _ in 0..1000 {
        i = (i * 37) % 349;
        let j = i as u64;
        assert_eq!(main_fn(j * 5, j * 4, j * 3, j * 2, j), j * 3 + 1);
    }
}
