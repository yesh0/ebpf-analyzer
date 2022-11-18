use std::str::FromStr;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Literal, Punct, Spacing, Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens, TokenStreamExt};

use crate::{
    block::{CodeBlock, Replacing},
    parser::{Alias, Aliases, OpcodeMatches},
};

/// Generates a match statement from a parsed `OpcodeMatches`
pub fn generate(matches: &OpcodeMatches) -> TokenStream {
    let value = matches.value.clone();
    let mut branches = TokenStream2::default();
    let mut consts = TokenStream2::default();
    for arm in &matches.matches {
        if arm.combinations.is_empty() {
            construct_code(&Vec::new(), &Vec::new(), &arm.code, &mut branches);
        } else {
            add_all_combinations(
                &arm.combinations,
                &arm.code,
                &mut branches,
                &mut consts,
                &arm.header,
                &matches.value_type,
            );
        }
    }
    consts.extend(quote! {
        match #value {
            #branches
        }
    });

    consts.into()
}

struct ConstName(String);
struct Component(&'static str);

impl ToTokens for ConstName {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        tokens.append(Ident::new(self.0.as_str(), Span::call_site()))
    }
}

impl ToTokens for Component {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        tokens.append(Ident::new(self.0, Span::call_site()))
    }
}

fn add_all_combinations(
    combinations: &[Aliases],
    code: &CodeBlock,
    branches: &mut TokenStream2,
    consts: &mut TokenStream2,
    header: &Option<TokenStream2>,
    value_type: &Ident,
) {
    let mut current: Vec<usize> = Vec::new();
    current.resize(combinations.len(), 0);
    let mut aliases: Vec<Alias> = Vec::new();
    let mut enabled: Vec<String> = Vec::new();
    let mut components: Vec<Component> = Vec::new();
    loop {
        aliases.clear();
        enabled.clear();
        components.clear();
        for (i, ele) in current.iter().enumerate() {
            let alias = &combinations[i].0[*ele];
            aliases.push(alias.0.clone());
            components.push(Component(alias.1));
            enabled.push(alias.0.clone());
            enabled.push(alias.1.to_string());
        }
        let mut match_code = TokenStream2::default();
        construct_code(&aliases, &enabled, code, &mut match_code);
        let const_name = get_const_name(&components);
        consts.extend(quote! {
            const #const_name : #value_type = #(#components)|*;
        });
        if let Some(header) = header {
            branches.extend(quote! {
                #header
                #const_name => { #match_code }
            });
        } else {
            branches.extend(quote! {
                #const_name => { #match_code }
            });
        }
        if !increment(&mut current, combinations) {
            break;
        }
    }
}

fn get_const_name(components: &[Component]) -> ConstName {
    let v: Vec<&str> = components.iter().map(|c| c.0).collect();
    ConstName(v.join("_"))
}

fn construct_code(
    aliases: &[String],
    enabled: &[String],
    code: &CodeBlock,
    output: &mut TokenStream2,
) {
    for block in &code.0 {
        match block {
            Replacing::End => panic!("Unexpected token"),
            Replacing::None(stream) => {
                output.extend(stream.clone());
            }
            Replacing::WithString(i) => {
                if aliases.len() <= *i {
                    panic!("#{} out of range!", i);
                }
                let symbol = &aliases[*i];
                output.extend(Literal::string(symbol.as_str()).to_token_stream());
            }
            Replacing::WithRaw(i) => {
                if aliases.len() <= *i {
                    panic!("#{} out of range!", i);
                }
                let symbol = &aliases[*i];
                if let Ok(tokens) = TokenStream2::from_str(symbol) {
                    output.extend(tokens);
                } else if char::is_alphabetic(symbol.chars().next().unwrap()) {
                    output
                        .extend(Ident::new(symbol.as_str(), Span::call_site()).to_token_stream());
                } else {
                    let joining = &symbol[0..symbol.len() - 1];
                    for c in joining.chars() {
                        output.extend(Punct::new(c, Spacing::Joint).to_token_stream());
                    }
                    output.extend(
                        Punct::new(symbol.chars().last().unwrap(), Spacing::Joint)
                            .to_token_stream(),
                    );
                }
            }
            Replacing::Nested(conditions, code) => {
                if conditions.matches(enabled) {
                    construct_code(aliases, enabled, code, output);
                }
            }
        }
    }
}

fn increment(current: &mut Vec<usize>, combinations: &[Aliases]) -> bool {
    for i in (0..current.len()).rev() {
        current[i] += 1;
        if current[i] < combinations[i].0.len() {
            break;
        } else if i == 0 {
            return false;
        } else {
            current[i] = 0;
        }
    }
    true
}
