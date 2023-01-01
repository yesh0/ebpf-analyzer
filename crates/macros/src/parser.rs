use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    token, Ident, LitStr, Token,
};

use crate::block::{CodeBlock, Replacing};

/// The root node
pub struct OpcodeMatches {
    /// Arms in the match statement
    pub matches: Vec<MatchArm>,
    /// The variable name to match against
    pub value: Ident,
    pub value_type: Ident,
    pub namespace: Namespace,
}

/// A match arm in the macro, e.g., `[[CONST: c]] => { 0 }`
pub struct MatchArm {
    /// The `[[A: a, B: b], [X: x, Y: y]]` part in the arm. Empty if unconditional.
    pub combinations: Vec<Aliases>,
    /// The code blocks following the combination part
    pub code: CodeBlock,
    /// Headers like `#[cfg(...)]`
    pub header: Option<TokenStream>,
}

/// Opcode component namespace
#[derive(Default)]
pub struct Namespace {
    pub namespace: TokenStream,
}

pub type Alias = String;
pub type Full = String;

/// The aliasing part of the macro, like `BPF_ALU64: ALU64`
pub struct Aliases(pub Vec<(Alias, Full)>);

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
                .step(|c| Ok(c.token_tree().unwrap()))?
                .to_token_stream(),
        ));
    }
    Ok(blocks)
}

impl OpcodeMatches {
    /// Parses the opcode part, e.g., `opcode as u8 in ebpf_consts`
    fn parse_opcode(input: ParseStream) -> syn::Result<(Ident, Ident, Namespace)> {
        let value: Ident = input.parse()?;
        let value_type = if input.peek(Token!(as)) {
            let _: Token!(as) = input.parse()?;
            let t: Ident = input.parse()?;
            t
        } else {
            Ident::new("u8", value.span())
        };
        let namespace = if input.peek(Token!(in)) {
            let _: Token!(in) = input.parse()?;
            input.parse()?
        } else {
            Namespace::default()
        };
        let _: Token!(,) = input.parse()?;
        Ok((value, value_type, namespace))
    }
}

impl Parse for OpcodeMatches {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let (value, value_type, namespace) = Self::parse_opcode(input)?;
        let mut arms: Vec<MatchArm> = Vec::new();
        let mut attribute: Option<TokenStream> = None;
        while !input.is_empty() {
            arms.push(if input.peek(token::Bracket) {
                // Conditional arms
                let mut arm: MatchArm = input.parse()?;
                if let Some(attr) = attribute.take() {
                    arm.header.replace(attr);
                }
                arm
            } else if input.peek(Token!(#)) {
                // Attributes for that branch, e.g., `#[cfg(test)]`
                let hash: Token!(#) = input.parse()?;
                let tree = input.step(|c| {
                    if let Some(i) = c.token_tree() {
                        Ok(i)
                    } else {
                        Err(c.error("Unexpected end"))
                    }
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
                // Unconditional arms, e.g., `_ => 0,`
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
            namespace,
            matches: arms,
        })
    }
}

impl Parse for Namespace {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let namespace = input.step(|cursor| {
            let mut stream = TokenStream::new();
            let mut rest = *cursor;
            while let Some((tt, next)) = rest.token_tree() {
                match &tt {
                    TokenTree::Punct(punct) if punct.as_char() == ',' => {
                        stream.extend(quote::quote!(::));
                        return Ok((stream, rest));
                    }
                    _ => {
                        stream.extend(tt.to_token_stream());
                        rest = next;
                    }
                }
            }
            Err(cursor.error("No comma found"))
        })?;
        Ok(Self { namespace })
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

struct AliasPair {
    pub full: String,
    pub alias: Alias,
}

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
            Some(full) => Ok(AliasPair { full, alias }),
            None => Err(syn::Error::new_spanned(
                component,
                "No such opcode component found",
            )),
        }
    }
}

impl AliasPair {
    fn find_opcode_component(component: &Ident) -> Option<String> {
        Some(component.to_string())
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
            result.0.push((ele.alias, ele.full.clone()));
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
    assert!(syn::parse2::<OpcodeMatches>(s).is_ok());
}

#[test]
fn test_in() {
    let s = quote::quote! {
        a as u8 in module,
        _ => {}
    };
    assert!(syn::parse2::<OpcodeMatches>(s).is_ok());
}
