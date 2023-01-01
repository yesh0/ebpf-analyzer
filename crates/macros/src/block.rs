use proc_macro2::{Delimiter, Ident, Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::{
    braced, bracketed, parenthesized,
    parse::{Parse, ParseBuffer, ParseStream},
    punctuated::Punctuated,
    token, LitInt, LitStr, Token,
};

use crate::parser::Aliases;

/// Controls whether a code block is inserted
pub struct Conditions {
    pub when: Vec<Vec<Predicate>>,
    pub position: Span,
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
                .any(|condition| condition_matches(condition, enabled))
    }
}

fn condition_matches(condition: &[Predicate], enabled: &[String]) -> bool {
    condition.iter().all(|cond| {
        if cond.negated {
            !enabled.contains(&cond.name)
        } else {
            enabled.contains(&cond.name)
        }
    })
}

#[derive(Clone)]
pub struct Predicate {
    pub name: String,
    pub negated: bool,
}

impl Parse for Predicate {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let negated = input.peek(Token!(!));
        if negated {
            let _: Token!(!) = input.parse()?;
        }
        Ok(Predicate {
            negated,
            name: if input.peek(syn::Ident) {
                let ident: Ident = input.parse()?;
                ident.to_string()
            } else {
                let str: LitStr = input.parse()?;
                str.value()
            },
        })
    }
}

impl Parse for Conditions {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let conditions;
        parenthesized!(conditions in input);
        let position = conditions.span();
        let conds: Punctuated<Punctuated<Predicate, Token!(,)>, Token!(|)> = conditions
            .parse_terminated(|input| {
                let content;
                parenthesized!(content in input);
                let aliases: Punctuated<Predicate, Token!(,)> =
                    content.parse_terminated(Predicate::parse)?;
                Ok(aliases)
            })?;
        Ok(Conditions {
            when: Vec::from_iter(
                conds
                    .iter()
                    .map(|aliases| aliases.iter().cloned().collect()),
            ),
            position,
        })
    }
}

/// A code block processing element
pub enum Replacing {
    /// The tokens should be inserted as is
    None(TokenStream),
    /// The `##` token
    End,
    /// A conditional block
    Nested(Conditions, CodeBlock),
    /// A `#0`, `#1` token, to be replaced with a string
    WithString {
        /// The alias group index
        ///
        /// - `0` selects `[1, 2, 3]` from `[[BPF_K: [1, 2, 3]]]`.
        group: usize,
        /// The alias element index
        ///
        /// - `1` in Group 0 selects `2` from `[[BPF_K: [1, 2, 3]]]`.
        element: isize,
    },
    /// A `#=0`, `#=1` token, to be replaced with a ident or puncts. See [Replacing::WithString].
    WithRaw { group: usize, element: isize },
    /// A `#"...{}..."0` token, to be formatted with an ident. See [Replacing::WithString].
    WithFormatted {
        group: usize,
        element: isize,
        /// The format string
        format: String,
    },
    /// A groupsed block, e.g., `( #=2 )`
    Grouped(Delimiter, CodeBlock),
}

/// Reads tokens, stopping before a '#' punct
fn parse_trees(code: &ParseStream) -> syn::Result<TokenStream> {
    code.step(|cursor| {
        let mut rest = *cursor;
        let mut stream = TokenStream::new();
        while let Some((tt, next)) = rest.token_tree() {
            match tt {
                TokenTree::Group(_) => break,
                TokenTree::Punct(punct) if punct.as_char() == '#' => break,
                _ => {
                    stream.extend(tt.to_token_stream());
                    rest = next;
                }
            }
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
            } else if input.peek(Token!(=))
                || input.peek(Token!(:))
                || input.peek(LitInt)
                || input.peek(LitStr)
            {
                // Reference
                let element = if input.peek(Token!(:)) {
                    let _: Token!(:) = input.parse()?;
                    let i: LitInt = input.parse()?;
                    let number = i.base10_parse::<isize>()?;
                    let _: Token!(:) = input.parse()?;
                    number
                } else {
                    0
                };
                let raw = input.peek(Token!(=));
                if raw {
                    let _: Token!(=) = input.parse()?;
                }
                let formatted = if input.peek(LitStr) {
                    input.parse::<LitStr>().ok()
                } else {
                    None
                };
                let group = input.parse::<LitInt>()?.base10_parse::<usize>()?;
                if raw {
                    Replacing::WithRaw { group, element }
                } else if let Some(format_str) = formatted {
                    Replacing::WithFormatted {
                        group,
                        element,
                        format: format_str.value(),
                    }
                } else {
                    Replacing::WithString { group, element }
                }
            } else if input.peek(Token!(#)) {
                // End
                let _: Token!(#) = input.parse()?;
                Replacing::End
            } else {
                // Unprocessed hash
                Replacing::None(hash.to_token_stream())
            }
        } else if let Some((delimiter, stream)) = grouped(input)? {
            Replacing::Grouped(delimiter, stream.parse()?)
        } else {
            Replacing::None(parse_trees(&input)?)
        })
    }
}

fn grouped(input: ParseStream) -> syn::Result<Option<(Delimiter, ParseBuffer)>> {
    let content;
    Ok(if input.peek(token::Brace) {
        braced!(content in input);
        Some((Delimiter::Brace, content))
    } else if input.peek(token::Bracket) {
        bracketed!(content in input);
        Some((Delimiter::Bracket, content))
    } else if input.peek(token::Paren) {
        parenthesized!(content in input);
        Some((Delimiter::Parenthesis, content))
    } else {
        return Ok(None);
    })
}

/// A code block
pub struct CodeBlock(pub Vec<Replacing>);

impl CodeBlock {
    /// Checks whether all conditions are alright
    pub fn validate(&self, combinations: &[Aliases]) -> syn::Result<()> {
        for block in &self.0 {
            if let Replacing::Nested(conditions, nested) = block {
                nested.validate(combinations)?;
                if let Some(alias) = conditions
                    .when
                    .iter()
                    .flat_map(|condition| condition.iter())
                    .find(|alias| {
                        combinations
                            .iter()
                            .all(|combination| !combination.contains(&alias.name))
                    })
                {
                    return Err(syn::Error::new(
                        conditions.position,
                        "Undeclared condition: ".to_string() + &alias.name,
                    ));
                }
            }
        }
        Ok(())
    }
}

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
