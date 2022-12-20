//! Provides the [opcode_match] macro.

#![forbid(missing_docs)]

mod opcode;
mod parser;
mod generator;
mod block;

use parser::OpcodeMatches;
use proc_macro::TokenStream;
use syn::parse_macro_input;

use crate::generator::generate;

extern crate ebpf_consts;

/// Generates a complex match statement
///
/// ## Format
///
/// ```
/// use ebpf_macros::opcode_match;
/// use ebpf_consts::*;
///
/// let opcode = 0u8;
/// opcode_match! {
///     opcode,
///     // Processed arms: begins with brackets
///     [[BPF_X: x, BPF_K: k], [BPF_ALU: "alu", BPF_ALU64: "alu64"]] => {
///     #?((x)) println!("In V1 branch");             ##
///     #?((k))
///         // Nested macros is not supported.
///         // `println!("{}", #1);` will fail.
///         let branch = #1;
///         println!("In V2 && {} branch", branch); ##
///         println!("Common");
///     }
///     // Unprocessed arms
///     _ => { println!("Unknown code"); }
/// };
/// ```
///
/// - Use `#?((required1, required2)|(condition2)) CODE; ##` to insert conditional code snippets.
/// - Use `#?((__exclusive1__,required2)) CODE; ##` to require `!exclusive1 && required2`.
/// - Use `#0`, `#1`, ... to refer to the alias as a raw code element.
#[proc_macro]
pub fn opcode_match(input: TokenStream) -> TokenStream {
    let matches = parse_macro_input!(input as OpcodeMatches);
    generate(&matches)
}
