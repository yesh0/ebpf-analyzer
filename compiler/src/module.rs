//! Implements a `no_std` [Module].

use core::ptr::write_unaligned;

use alloc::{boxed::Box, string::ToString, vec::Vec};
use anyhow::anyhow;
use cranelift_codegen::{
    binemit::Reloc::*,
    entity::SecondaryMap,
    ir::{types::I64, AbiParam, Function, Signature},
    isa::{self, CallConv, LookupError, TargetIsa},
    settings::{self, Configurable},
    CodegenError, CompiledCode, Context, MachReloc,
};
use cranelift_module::{
    DataContext, DataId, FuncId, Linkage, Module, ModuleCompiledFunction, ModuleDeclarations,
    ModuleError, ModuleReloc, ModuleResult,
};
use target_lexicon::Triple;

/// Information around the compiled chunk of code
#[derive(Clone)]
struct FunctionDefinition {
    alignment: u32,
    relocations: Vec<ModuleReloc>,
    data: Vec<u8>,
}

impl FunctionDefinition {
    fn from(compiled: &CompiledCode, func: &Function) -> Self {
        let mut definition = Self {
            alignment: compiled.alignment,
            relocations: Vec::new(),
            data: Vec::new(),
        };
        definition
            .data
            .reserve(compiled.buffer.total_size() as usize);
        definition.data.extend(compiled.buffer.data());
        let relocs = compiled.buffer.relocs();
        definition.relocations.reserve(relocs.len());
        for relocation in relocs {
            definition
                .relocations
                .push(ModuleReloc::from_mach_reloc(relocation, func));
        }
        definition
    }
}

/// A [Module] implementation
pub struct BpfModule {
    isa: Box<dyn TargetIsa>,
    declarations: ModuleDeclarations,
    definitions: SecondaryMap<FuncId, Option<FunctionDefinition>>,
    signature: Signature,
    binary: Option<(Vec<u8>, u32)>,
}

impl BpfModule {
    /// Creates a new module according to the host [TargetIsa]
    pub fn new() -> Result<Self, LookupError> {
        let builder = isa::lookup(Triple::host())?;
        let mut flags_builder = settings::builder();
        flags_builder
            .set("is_pic", "true")
            .map_err(|_| LookupError::Unsupported)?;
        flags_builder
            .set("enable_float", "false")
            .map_err(|_| LookupError::Unsupported)?;
        flags_builder
            .set("enable_atomics", "true")
            .map_err(|_| LookupError::Unsupported)?;
        let flags = settings::Flags::new(flags_builder);
        let isa = builder
            .finish(flags)
            .map_err(|_| LookupError::Unsupported)?;
        let value = AbiParam::new(I64);
        Ok(Self {
            isa,
            declarations: ModuleDeclarations::default(),
            definitions: SecondaryMap::new(),
            signature: Signature {
                params: alloc::vec![value, value, value, value, value],
                returns: alloc::vec![value],
                call_conv: CallConv::SystemV,
            },
            binary: None,
        })
    }

    /// Returns the signature for eBPF functions
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Links between defined functions into a raw binary
    ///
    /// Currently no relocation is supported, so only one function is allowed.
    pub(crate) fn finalize_definitions(&mut self) -> ModuleResult<()> {
        let mut data: Vec<u8> = Vec::new();
        let mut size = 0usize;
        let mut max_alignment = 1;
        let mut addresses: SecondaryMap<FuncId, usize> = SecondaryMap::new();
        for (id, _) in self.declarations.get_functions() {
            if let Some(definition) = &self.definitions[id] {
                max_alignment = max_alignment.max(definition.alignment);
                let misaligned = size % definition.alignment as usize;
                if misaligned != 0 {
                    size += definition.alignment as usize - misaligned;
                }
                addresses[id] = size;
                size += definition.data.len();
            } else {
                return Err(ModuleError::Backend(anyhow!("Functions not fully defined")));
            }
        }
        data.reserve(size);
        for (id, _) in self.declarations.get_functions() {
            if let Some(definition) = &self.definitions[id] {
                let misaligned = data.len() % definition.alignment as usize;
                if misaligned != 0 {
                    data.resize((definition.alignment as usize - misaligned) + data.len(), 0);
                }
                let base = data.len();
                data.extend(&definition.data);

                for relocation in &definition.relocations {
                    match relocation.kind {
                        Abs4 => todo!(),
                        Abs8 => todo!(),
                        X86PCRel4 => todo!(),
                        X86CallPCRel4 => {
                            let address = addresses[FuncId::from_name(&relocation.name)];
                            let at = relocation.offset as usize + base;
                            let relative = address.wrapping_sub(at) as i64;
                            let fixed = i32::try_from(relative + relocation.addend).unwrap();
                            unsafe {
                                write_unaligned(data.as_mut_ptr().add(at) as *mut i32, fixed)
                            };
                        }
                        Arm32Call => todo!(),
                        Arm64Call => todo!(),
                        S390xPCRel32Dbl => todo!(),
                        RiscvCall => todo!(),

                        X86CallPLTRel4
                        | X86GOTPCRel4
                        | X86SecRel
                        | S390xPLTRel32Dbl
                        | ElfX86_64TlsGd
                        | MachOX86_64Tlv
                        | S390xTlsGd64
                        | S390xTlsGdCall
                        | Aarch64TlsGdAdrPage21
                        | Aarch64TlsGdAddLo12Nc => {
                            return Err(ModuleError::Compilation(CodegenError::Unsupported(
                                "Unsupported relocation".to_string(),
                            )))
                        }
                    }
                }
            }
        }
        self.binary.replace((data, max_alignment));
        Ok(())
    }

    /// Returns `Some(&code, alignment)` if the function is defined
    pub fn get_finalized_function(&self, main: FuncId) -> Option<(&[u8], u32)> {
        if main.as_u32() == 0 {
            if let Some(ref bin) = self.binary {
                return Some((&bin.0, bin.1));
            }
        }
        None
    }
}

impl Module for BpfModule {
    fn isa(&self) -> &dyn TargetIsa {
        self.isa.as_ref()
    }

    fn declarations(&self) -> &ModuleDeclarations {
        &self.declarations
    }

    fn declare_function(
        &mut self,
        name: &str,
        linkage: Linkage,
        signature: &Signature,
    ) -> ModuleResult<FuncId> {
        if linkage != Linkage::Export {
            return Err(ModuleError::IncompatibleDeclaration(
                "eBPF only supports exported functions".to_string(),
            ));
        }

        if *signature != self.signature {
            return Err(ModuleError::IncompatibleSignature(
                "eBPF functions have a fixed signature".to_string(),
                self.signature.clone(),
                signature.clone(),
            ));
        }

        let (id, _linkage) = self
            .declarations
            .declare_function(name, linkage, &self.signature)?;
        Ok(id)
    }

    fn declare_anonymous_function(&mut self, _signature: &Signature) -> ModuleResult<FuncId> {
        unimplemented!("eBPF does not allow anonymous functions (for now)")
    }

    fn declare_data(
        &mut self,
        _name: &str,
        _linkage: Linkage,
        _writable: bool,
        _tls: bool,
    ) -> ModuleResult<DataId> {
        unimplemented!("eBPF does not support external data")
    }

    fn declare_anonymous_data(&mut self, _writable: bool, _tls: bool) -> ModuleResult<DataId> {
        unimplemented!("eBPF does not support external data")
    }

    fn define_function(
        &mut self,
        func: FuncId,
        ctx: &mut Context,
    ) -> ModuleResult<ModuleCompiledFunction> {
        if self.definitions[func].is_some() {
            return Err(ModuleError::DuplicateDefinition(
                "Function already defined".to_string(),
            ));
        }

        let _ = ctx.compile(self.isa.as_ref())?;
        // Work-around multipe borrows
        let res = ctx.compiled_code().unwrap();
        let definition = FunctionDefinition::from(res, &ctx.func);
        let size = definition.data.len() as u32;
        self.definitions[func] = Some(definition);
        Ok(ModuleCompiledFunction { size })
    }

    fn define_function_bytes(
        &mut self,
        _func_id: FuncId,
        _func: &Function,
        _alignment: u64,
        _bytes: &[u8],
        _relocs: &[MachReloc],
    ) -> ModuleResult<ModuleCompiledFunction> {
        unimplemented!(
            "Not useful unless you want to inline helper functions. Unsupported for now."
        )
    }

    fn define_data(&mut self, _data: DataId, _data_ctx: &DataContext) -> ModuleResult<()> {
        unimplemented!("eBPF does not support external data")
    }
}

#[test]
#[should_panic(expected = "eBPF does not support external data")]
fn test_unimplemented_decl_data() {
    if let Ok(mut m) = BpfModule::new() {
        m.declare_data("name", Linkage::Export, true, true).ok();
    }
}

#[test]
#[should_panic(expected = "eBPF does not allow anonymous functions (for now)")]
fn test_unimplemented_decl_func() {
    if let Ok(mut m) = BpfModule::new() {
        m.declare_anonymous_function(&m.signature.clone()).ok();
    }
}

#[test]
#[should_panic(expected = "eBPF does not support external data")]
fn test_unimplemented_decl_anonymous_data() {
    if let Ok(mut m) = BpfModule::new() {
        m.declare_anonymous_data(true, true).ok();
    }
}

#[test]
#[should_panic(expected = "eBPF does not support external data")]
fn test_unimplemented_def_data() {
    if let Ok(mut m) = BpfModule::new() {
        let i = 0u8;
        m.define_data(DataId::from_u32(0), unsafe {
            (&i as *const u8 as *const DataContext).as_ref().unwrap()
        })
        .ok();
    }
}

#[test]
#[should_panic(
    expected = "Not useful unless you want to inline helper functions. Unsupported for now."
)]
fn test_unimplemented_def_func() {
    if let Ok(mut m) = BpfModule::new() {
        let i = 0u8;
        m.define_function_bytes(
            FuncId::from_u32(0),
            unsafe { (&i as *const u8 as *const Function).as_ref().unwrap() },
            8,
            &[],
            &[],
        )
        .ok();
    }
}
