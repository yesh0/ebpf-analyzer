//! Provides the [opcode_match!] macro.

#![forbid(missing_docs)]

mod parser;
mod generator;
mod block;

use parser::OpcodeMatches;
use proc_macro::TokenStream;
use syn::parse_macro_input;

use crate::generator::generate;

/// Generates a complex match statement
///
/// # Format
///
/// The basic format is like this:
///
/// ```rust
/// # use opcode_macros::opcode_match;
/// # let opcode = 0u8;
/// # mod namespace {
/// #     pub const A_1: u8 = 0;
/// #     pub const A_2: u8 = 0;
/// #     pub const B_1: u8 = 0;
/// #     pub const B_2: u8 = 0;
/// # }
/// # let result =
/// opcode_match! {
///     opcode as u8 in namespace,
///     [[A_1: a1, A_2: a2], [B_1: b1, B_2: b2]] => {
///         // Code
///         # 1
///     }
///     _ => {
///         // Code
///         # 0
///     }
/// }
/// # ;
/// # assert_eq!(result, 1);
/// ```
///
/// It generates something like this:
///
/// ```rust
/// # let opcode = 0u8;
/// # mod namespace {
/// #     pub const A_1: u8 = 0;
/// #     pub const A_2: u8 = 0;
/// #     pub const B_1: u8 = 0;
/// #     pub const B_2: u8 = 0;
/// # }
/// const A_1_B_1: u8 = namespace::A_1 | namespace::B_1;
/// const A_1_B_2: u8 = namespace::A_1 | namespace::B_2;
/// const A_2_B_1: u8 = namespace::A_2 | namespace::B_1;
/// const A_2_B_2: u8 = namespace::A_2 | namespace::B_2;
/// match opcode {
///     A_1_B_1 => { /* Code */ }
///     A_1_B_2 => { /* Code */ }
///     A_2_B_1 => { /* Code */ }
///     A_2_B_2 => { /* Code */ }
///     _ => { /* Code */ }
/// }
/// ```
///
/// ## Match Arm Headers
///
/// Match arm headers is something like `[[A_1: a1, A_2: a2], [B_1: b1, B_2: b2]]`.
///
/// For example, in eBPF opcodes, `BPF_ALU | BPF_K | BPF_ADD` is an opcode for
/// 32-bit addition with constants, while `BPF_ALU | BPF_K | BPF_SUB` is an opcode
/// for 32-bit subtraction with constants. To match against these opcodes,
/// we use the following code:
///
/// ```rust
/// # use opcode_macros::opcode_match;
/// # use ebpf_consts::*;
/// # let opcode = 0x04u8;
/// # let mut result = 0u64;
/// # let dst = 10u64;
/// # let imm = 10u64;
/// opcode_match! {
///     opcode as u8 in ebpf_consts,
///     [[BPF_ALU: _], [BPF_K: _],
///      [BPF_ADD: add, BPF_SUB: sub]] => {
///         result = dst.#"wrapping_{}"2(imm);
///     }
///     _ => {}
/// }
/// # assert_eq!(result, 20);
/// ```
///
/// We will talk about the templating rules later.
///
/// In the example above, you can also use some other variants:
/// - `[BPF_ADD: "add", BPF_SUB: "sub"]`
/// - `[BPF_ADD: [add], BPF_SUB: [sub]]`
/// - `[BPF_ADD: ["add"], BPF_SUB: ["sub"]]`
/// - `[BPF_ADD: ["add", "extra1"], BPF_SUB: ["sub", "extra2"]]`
///
/// If you want to substitutes parts of the code with symbols like "+",
/// you will need to quote the symbols like `[BPF_ADD: "+"]`.
///
/// ## Code Template
///
/// ### Substitution
///
/// This is not a real life example.
///
/// ```rust
/// # use opcode_macros::opcode_match;
/// # use ebpf_consts::*;
/// # use core::ops::Add;
/// # let opcode = 0u8;
/// opcode_match! {
///     opcode as u8 in ebpf_consts,
///     [
///         // Group 0
///         [BPF_K:   ["const", 1, 2, "Constant Operation"]],
///         // Group 1
///         [BPF_ADD: ["add", 3, 4, "Addition Operation"]],
///     ] => {
///         // Use the first token in group 0 as a string
///         assert_eq!(#0, "const");
///         // Use the fourth token in group 0 as a string
///         assert_eq!(#:3:0, "Constant Operation");
///         assert_eq!(#:0:1, "add");
///         assert_eq!(#:3:1, "Addition Operation");
///
///         // Use raw tokens
///         assert_eq!(#:1:1, "3");
///         assert_eq!(#:1:=1, 3);
///         // 30.add(40) == 70, where #=1 is just #:0:=1
///         let value = 30isize;
///         assert_eq!(value.#=1(40), 70);
///
///         // With in-token substitution: add -> wrapping_add
///         assert_eq!(value.#"wrapping_{}"1(40), 70);
///     }
///     _ => panic!(),
/// }
/// ```
///
/// ### Conditional Blocks
///
/// ```rust
/// use opcode_macros::opcode_match;
/// use ebpf_consts::*;
///
/// # let opcode = BPF_X | BPF_ALU;
/// opcode_match! {
///     opcode as u8 in ebpf_consts,
///     [[BPF_X: x, BPF_K: k], [BPF_ALU: "alu", BPF_ALU64: "alu64"]] => {
///         #?((x))
///             println!("In V1 branch");
///             assert_eq!(#0, "x");                ##
///
///         #?((k))
///             println!("In V2 && {} branch", #1);
///             assert_eq!(#0, "k");                ##
///
///         #?((!"k"))
///             println!("In V2 && {} branch", #1);
///             assert_eq!(#0, "x");                ##
///         println!("Common");
///     }
///     _ => panic!(),
/// };
/// ```
///
/// The grammar is `#?((cond1, cond2)|(cond3|cond4)|...) CODE ##`,
/// making the code only injected if the opcode matches
/// `(cond1 && cond2) || (cond3 && cond4) || ...`.
/// A condition can be negated with an exclamation mark `!cond1`.
///
/// We don't allow nested conditions.
#[proc_macro]
pub fn opcode_match(input: TokenStream) -> TokenStream {
    let matches = parse_macro_input!(input as OpcodeMatches);
    generate(&matches)
}
