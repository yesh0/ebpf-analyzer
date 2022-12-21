//! Implements a `no_std` [Module].

use alloc::{boxed::Box, string::ToString, vec::Vec};
use anyhow::anyhow;
use cranelift_codegen::{
    entity::SecondaryMap,
    ir::{types::I64, AbiParam, Function, Signature},
    isa::{self, CallConv, LookupError, TargetIsa},
    settings::{self, Configurable},
    CompiledCode, Context, MachReloc,
};
use cranelift_module::{
    DataContext, DataId, FuncId, Linkage, Module, ModuleCompiledFunction, ModuleDeclarations,
    ModuleError, ModuleResult,
};
use target_lexicon::Triple;

/// Information around the compiled chunk of code
#[derive(Clone)]
struct FunctionDefinition {
    alignment: u32,
    relocations: Vec<MachReloc>,
    data: Vec<u8>,
}

impl From<&CompiledCode> for FunctionDefinition {
    fn from(compiled: &CompiledCode) -> Self {
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
            definition.relocations.push(relocation.clone());
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
        })
    }

    /// Returns the signature for eBPF functions
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Links between defined functions into a raw binary
    ///
    /// Currently no relocation is supported, so only one function is allowed.
    pub(crate) fn finalize_definitions(&self) -> ModuleResult<()> {
        if self.declarations.get_functions().count() != 1 {
            return Err(ModuleError::Backend(anyhow!(
                "Currently multiple functions are not supported"
            )));
        }
        for (id, _) in self.declarations.get_functions() {
            if let Some(definition) = &self.definitions[id] {
                if !definition.relocations.is_empty() {
                    return Err(ModuleError::Backend(anyhow!(
                        "Relocations not supported for now"
                    )));
                }
            } else {
                return Err(ModuleError::Backend(anyhow!("Functions not fully defined")));
            }
        }
        Ok(())
    }

    /// Returns `Some(&code, alignment)` if the function is defined
    pub fn get_finalized_function(&self, main: FuncId) -> Option<(&[u8], u32)> {
        self.definitions[main]
            .as_ref()
            .map(|definition| (&definition.data as &[u8], definition.alignment))
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

        let res = ctx.compile(self.isa.as_ref())?;
        let definition = FunctionDefinition::from(res);
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
