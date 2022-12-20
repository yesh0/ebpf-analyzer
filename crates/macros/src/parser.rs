use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    token, Ident, LitStr, Token,
};

use crate::{
    block::{CodeBlock, Replacing},
    opcode::OPCODES,
};

/// The root node
pub struct OpcodeMatches {
    /// Arms in the match statement
    pub matches: Vec<MatchArm>,
    /// The variable name to match against
    pub value: Ident,
    pub value_type: Ident,
}

/// A match arm in the macro
pub struct MatchArm {
    /// The `[[A: a, B: b], [X: x, Y: y]]` part in the arm. Empty if unconditional.
    pub combinations: Vec<Aliases>,
    /// The code blocks following the combination part
    pub code: CodeBlock,
    /// Headers like `#[cfg(...)]`
    pub header: Option<TokenStream>,
}

pub type Alias = String;

/// The aliasing part of the macro, like `BPF_ALU64: ALU64`
pub struct Aliases(pub Vec<(Alias, &'static str)>);

impl Aliases {
    pub fn contains(&self, alias: &str) -> bool {
        self.0.iter().any(|(s, t)| s == alias || *t == alias)
    }
}

/// Reads all code blocks until meeting a top-level bracket
fn until_bracket(input: &ParseStream) -> syn::Result<Vec<Replacing>> {
    let mut blocks: Vec<Replacing> = Vec::new();
    while !input.is_empty() && !input.peek(token::Bracket) && !input.peek(Token!(#)) {
        blocks.push(Replacing::None(
            input
                .step(|c| Ok(c.token_tree().unwrap()))?.to_token_stream(),
        ));
    }
    Ok(blocks)
}

impl Parse for OpcodeMatches {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let value: Ident = input.parse()?;
        let value_type = if !input.peek(Token!(,)) {
            let _: Token!(as) = input.parse()?;
            let t: Ident = input.parse()?;
            t
        } else {
            Ident::new("u8", value.span())
        };
        let _: Token!(,) = input.parse()?;
        let mut arms: Vec<MatchArm> = Vec::new();
        let mut attribute: Option<TokenStream> = None;
        while !input.is_empty() {
            arms.push(if input.peek(token::Bracket) {
                let mut arm: MatchArm = input.parse()?;
                if let Some(attr) = attribute.take() {
                    arm.header.replace(attr);
                }
                arm
            } else if input.peek(Token!(#)) {
                let hash: Token!(#) = input.parse()?;
                let tree = input.step(|c| if let Some(i) = c.token_tree() {
                    Ok(i)
                } else {
                    Err(c.error("Unexpected end"))
                })?;
                let mut s = hash.to_token_stream();
                s.extend(tree.to_token_stream());
                if let Some(mut prev) = attribute.take() {
                    prev.extend(s);
                    attribute.replace(prev);
                } else {
                    attribute.replace(s);
                }
                continue;
            } else {
                let mut code = until_bracket(&input)?;
                if let Some(attr) = attribute.take() {
                    code.insert(0, Replacing::None(attr));
                }
                MatchArm::as_is(CodeBlock(code))
            });
        }
        Ok(OpcodeMatches {
            value,
            value_type,
            matches: arms,
        })
    }
}

impl MatchArm {
    pub fn as_is(code: CodeBlock) -> MatchArm {
        MatchArm {
            combinations: Vec::new(),
            header: None,
            code,
        }
    }
}

impl Parse for MatchArm {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let header;
        bracketed!(header in input);
        let combinations: Punctuated<Aliases, Token!(,)> =
            header.parse_terminated(Aliases::parse)?;
        let combinations = Vec::from_iter(combinations);
        let _: Token!(=>) = input.parse()?;
        let code;
        braced!(code in input);
        let code: CodeBlock = code.parse()?;
        code.validate(&combinations)?;
        Ok(MatchArm {
            combinations,
            header: None,
            code,
        })
    }
}

struct AliasPair(&'static str, Alias);

impl Parse for AliasPair {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let component: Ident = input.parse()?;
        let _: Token!(:) = input.parse()?;
        let alias = if input.peek(Ident) {
            let ident: Ident = input.parse()?;
            ident.to_string()
        } else {
            let s: LitStr = input.parse()?;
            s.value()
        };
        match AliasPair::find_opcode_component(&component) {
            Some(name) => Ok(AliasPair(name, alias)),
            None => Err(syn::Error::new_spanned(component, "No such opcode component found")),
        }
    }
}

impl AliasPair {
    fn find_opcode_component(component: &Ident) -> Option<&'static str> {
        for ele in OPCODES {
            if *component == ele.0 {
                return Some(ele.0);
            }
        }
        None
    }
}

impl Parse for Aliases {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        bracketed!(content in input);
        let aliases: Punctuated<AliasPair, Token!(,)> =
            content.parse_terminated(AliasPair::parse)?;
        let mut result = Aliases(Vec::new());
        for ele in aliases {
            result.0.push((ele.1, ele.0));
        }
        Ok(result)
    }
}

#[test]
fn test_parsers() {
    let s = quote::quote! {
        a as u8,
        #
    };
    assert!(syn::parse2::<OpcodeMatches>(s).is_err());

    let s = quote::quote! {
        a as u8,
        #[cfg(test)]
        #[cfg(no_test)]
        [[BPF_IMM: a]] => {}
    };
    assert!(syn::parse2::<OpcodeMatches>(s).is_ok());

    let s = quote::quote! {
        a as u8,
        #[cfg(test)]
        #[cfg(no_test)]
        0 => {}
        [[BPF_IMM: a]] => {}
    };
    assert!(syn::parse2::<OpcodeMatches>(s).is_ok());

    let s = quote::quote! {
        a as u8,
        #[cfg(test)]
        #[cfg(no_test)]
        0 => {}
        [[A: a]] => {}
    };
    assert!(syn::parse2::<OpcodeMatches>(s).is_err());
}