use proc_macro2::{Ident, TokenStream, TokenTree};
use quote::ToTokens;
use syn::{
    parenthesized,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    LitInt, LitStr, Token,
};

use crate::parser::Alias;

/// Controls whether a code block is inserted
#[derive(Debug)]
pub struct Conditions {
    pub when: Vec<Vec<Alias>>,
}

impl Conditions {
    pub fn is_empty(&self) -> bool {
        self.when.is_empty()
    }

    pub fn matches(&self, enabled: &[String]) -> bool {
        self.is_empty()
            || self
                .when
                .iter()
                .any(|condition| condition.iter().all(|required| enabled.contains(required)))
    }
}

struct IdentOrLitStr(String);

impl Parse for IdentOrLitStr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(if input.peek(syn::Ident) {
            let ident: Ident = input.parse()?;
            IdentOrLitStr(ident.to_string())
        } else {
            let str: LitStr = input.parse()?;
            IdentOrLitStr(str.value())
        })
    }
}

impl Parse for Conditions {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let conditions;
        parenthesized!(conditions in input);
        let conds: Punctuated<Punctuated<IdentOrLitStr, Token!(,)>, Token!(|)> = conditions
            .parse_terminated(|input| {
                let content;
                parenthesized!(content in input);
                let aliases: Punctuated<IdentOrLitStr, Token!(,)> =
                    content.parse_terminated(IdentOrLitStr::parse)?;
                Ok(aliases)
            })?;
        Ok(Conditions {
            when: Vec::from_iter(
                conds
                    .iter()
                    .map(|aliases| Vec::from_iter(aliases.iter().map(|i| i.0.clone()))),
            ),
        })
    }
}

/// A code block processing element
#[derive(Debug)]
pub enum Replacing {
    /// The tokens should be inserted as is
    None(TokenStream),
    /// The `##` token
    End,
    /// A conditional block
    Nested(Conditions, CodeBlock),
    /// A `#0`, `#1` token, to be replaced with a string
    WithString(usize),
    /// A `#=0`, `#=1` token, to be replaced with a ident or puncts
    WithRaw(usize),
}

/// Reads tokens, stopping before a '#' punct
fn parse_trees(code: &ParseStream) -> syn::Result<TokenStream> {
    code.step(|cursor| {
        let mut rest = *cursor;
        let mut stream = TokenStream::new();
        while let Some((tt, next)) = rest.token_tree() {
            if let TokenTree::Punct(punct) = &tt {
                if punct.as_char() == '#' {
                    break;
                }
            }
            stream.extend(tt.to_token_stream());
            rest = next;
        }
        Ok((stream, rest))
    })
}

impl Parse for Replacing {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(if input.peek(Token!(#)) {
            let hash: Token!(#) = input.parse()?;
            if input.peek(Token!(?)) {
                // Nested Conditional CodeBlock
                let _: Token!(?) = input.parse()?;
                let conditions: Conditions = input.parse()?;
                Replacing::Nested(conditions, input.parse()?)
            } else if input.peek(Token!(=)) || input.peek(LitInt) {
                // Reference
                let raw = input.peek(Token!(=));
                if raw {
                    let _: Token!(=) = input.parse()?;
                }
                let number: LitInt = input.parse()?;
                if raw {
                    Replacing::WithRaw(number.base10_parse::<usize>()?)
                } else {
                    Replacing::WithString(number.base10_parse::<usize>()?)
                }
            } else if input.peek(Token!(#)) {
                // End
                let _: Token!(#) = input.parse()?;
                Replacing::End
            } else {
                // Unprocessed hash
                Replacing::None(hash.to_token_stream())
            }
        } else {
            Replacing::None(parse_trees(&input)?)
        })
    }
}

/// A code block
#[derive(Debug)]
pub struct CodeBlock(pub Vec<Replacing>);

impl Parse for CodeBlock {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut blocks: Vec<Replacing> = Vec::new();
        while !input.is_empty() {
            let node: Replacing = input.parse()?;
            if let Replacing::End = node {
                break;
            }
            blocks.push(node);
        }
        Ok(CodeBlock(blocks))
    }
}
