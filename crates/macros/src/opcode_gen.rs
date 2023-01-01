use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Token,
};

use crate::parser::Namespace;

pub struct OpcodeGen {
    pub prefix: String,
    pub opcode_type: Ident,
    pub namespace: TokenStream2,
    pub blocks: Vec<Vec<Vec<String>>>,
}

impl Parse for OpcodeGen {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let _: Token!(for) = input.parse()?;
        let prefix = if input.peek(Token!(*)) {
            String::default()
        } else {
            let ident: Ident = input.parse()?;
            ident.to_string()
        };
        let _: Token!(*) = input.parse()?;
        let _: Token!(in) = input.parse()?;
        let namespace: Namespace = input.parse()?;
        let _: Token!(as) = input.parse()?;
        let opcode_type: Ident = input.parse()?;
        let inner;
        braced!(inner in input);
        let mut blocks: Vec<Vec<Vec<String>>> = Vec::new();
        while !inner.is_empty() {
            let content;
            bracketed!(content in inner);
            let to_be_combined: Punctuated<Punctuated<Ident, Token!(,)>, Token!(,)> = content
                .parse_terminated(|buffer| {
                    let array;
                    bracketed!(array in buffer);
                    array.parse_terminated(Ident::parse)
                })?;
            blocks.push(
                to_be_combined
                    .iter()
                    .map(|punctuated| punctuated.iter().map(|ident| ident.to_string()).collect())
                    .collect(),
            );
            if blocks.is_empty()
                || blocks
                    .iter()
                    .any(|block| block.is_empty() || block.iter().any(|row| row.is_empty()))
            {
                return Err(inner.error("Empty construct"));
            }
        }
        Ok(Self {
            prefix,
            namespace: namespace.namespace,
            opcode_type,
            blocks,
        })
    }
}

impl OpcodeGen {
    pub fn generate(&self) -> TokenStream {
        let mut stream = TokenStream2::new();
        let mut indices = Vec::new();
        for to_be_combined in &self.blocks {
            indices.clear();
            indices.resize(to_be_combined.len(), 0);
            loop {
                let mut name = self.prefix.trim_end_matches('_').to_owned();
                let mut doc = String::from("Opcode combined from");
                for component in indices.iter().enumerate().map(|(row, index)| {
                    doc += " [";
                    doc += &self.namespace.to_string();
                    doc += &to_be_combined[row][*index];
                    doc += "]";
                    to_be_combined[row][*index].trim_start_matches(&self.prefix)
                }) {
                    name += "_";
                    name += component;
                }
                let t = &self.opcode_type;
                let combination = indices.iter().enumerate().map(|(row, index)| {
                    let mut qualified = self.namespace.clone();
                    qualified.extend(
                        Ident::new(&to_be_combined[row][*index], Span::call_site())
                            .to_token_stream(),
                    );
                    qualified
                });
                let name = Ident::new(&name, Span::call_site());
                stream.extend(quote::quote! {
                    #[doc = #doc]
                    pub const #name: #t = #(#combination)|*;
                });

                *indices.last_mut().unwrap() += 1;
                let mut carry = false;
                for (row, index) in indices.iter_mut().enumerate().rev() {
                    if carry {
                        *index += 1;
                        carry = false;
                    }
                    if *index < to_be_combined[row].len() {
                        break;
                    }
                    *index = 0;
                    carry = true;
                }
                if carry {
                    break;
                }
            }
        }
        stream.into()
    }
}
