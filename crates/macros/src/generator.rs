use std::str::FromStr;

use proc_macro::TokenStream;
use proc_macro2::{Group, Ident, Literal, Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens, TokenStreamExt};

use crate::{
    block::{CodeBlock, Replacing},
    parser::{Alias, Aliases, Full, Namespace, OpcodeMatches},
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
                &matches.namespace,
            );
        }
    }
    consts.extend(quote! {
        match #value {
            #branches
        }
    });

    quote!({ #consts }).into()
}

struct ConstName(String, Option<TokenStream2>);
struct Component {
    pub name: Full,
    pub namespace: TokenStream2,
}

impl ToTokens for ConstName {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        if let Some(prefix) = &self.1 {
            prefix.to_tokens(tokens);
        }
        tokens.append(Ident::new(self.0.as_str(), Span::call_site()))
    }
}

impl ToTokens for Component {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        self.namespace.to_tokens(tokens);
        tokens.append(Ident::new(&self.name, Span::call_site()))
    }
}

fn add_all_combinations(
    combinations: &[Aliases],
    code: &CodeBlock,
    branches: &mut TokenStream2,
    consts: &mut TokenStream2,
    header: &Option<TokenStream2>,
    value_type: &Ident,
    namespace: &Namespace,
) {
    let mut current: Vec<usize> = Vec::new();
    current.resize(combinations.len(), 0);
    let mut aliases: Vec<&[Alias]> = Vec::new();
    let mut enabled: Vec<String> = Vec::new();
    let mut components: Vec<Component> = Vec::new();
    loop {
        aliases.clear();
        enabled.clear();
        components.clear();
        for (i, ele) in current.iter().enumerate() {
            let alias = &combinations[i].0[*ele];
            aliases.push(&alias.0);
            components.push(Component {
                name: alias.1.clone(),
                namespace: namespace.namespace.clone(),
            });
            enabled.extend(alias.0.iter().cloned());
            enabled.push(alias.1.to_string());
        }
        enabled.sort_unstable();
        enabled.dedup();
        let mut match_code = TokenStream2::default();
        construct_code(&aliases, &enabled, code, &mut match_code);
        let const_name = if components.len() > 1 {
            let const_name = get_const_name(&components);
            consts.extend(quote! {
                const #const_name : #value_type = #(#components)|*;
            });
            const_name
        } else {
            ConstName(components[0].name.clone(), Some(namespace.namespace.clone()))
        };
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
    let v: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
    ConstName(v.join("_"), None)
}

fn construct_code(
    aliases: &[&[String]],
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
            Replacing::WithString { group, element } => {
                if aliases.len() <= *group {
                    panic!("#{group} out of range!");
                }
                let symbol = &aliases[*group][*element as usize];
                output.extend(Literal::string(symbol.as_str()).to_token_stream());
            }
            Replacing::WithRaw { group, element } => {
                if aliases.len() <= *group {
                    panic!("#{group} out of range!");
                }
                let symbol = &aliases[*group][*element as usize];
                match TokenStream2::from_str(symbol) {
                    Ok(tokens) => output.extend(tokens),
                    Err(err) => panic!("{err:?}"),
                }
            }
            Replacing::WithFormatted {
                group,
                element,
                format,
            } => {
                if aliases.len() <= *group {
                    panic!("#{group} out of range!");
                }
                let symbol = &aliases[*group][*element as usize];
                match TokenStream2::from_str(&format.replace("{}", symbol)) {
                    Ok(tokens) => output.extend(tokens),
                    Err(err) => panic!("{err:?}"),
                }
            }
            Replacing::Nested(conditions, code) => {
                if conditions.matches(enabled) {
                    construct_code(aliases, enabled, code, output);
                }
            }
            Replacing::Grouped(delimiter, code) => {
                let mut stream = TokenStream2::new();
                construct_code(aliases, enabled, code, &mut stream);
                Group::new(*delimiter, stream).to_tokens(output);
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

#[test]
#[should_panic]
fn test_panic() {
    construct_code(
        &[],
        &[],
        &CodeBlock(vec![Replacing::End]),
        &mut TokenStream2::new(),
    );
}

#[test]
#[should_panic]
fn test_str_oor() {
    construct_code(
        &[],
        &[],
        &CodeBlock(vec![Replacing::WithString {
            group: 1,
            element: 0,
        }]),
        &mut TokenStream2::new(),
    );
}

#[test]
#[should_panic]
fn test_raw_oor() {
    construct_code(
        &[],
        &[],
        &CodeBlock(vec![Replacing::WithRaw {
            group: 1,
            element: 0,
        }]),
        &mut TokenStream2::new(),
    );
}

#[test]
#[should_panic = "LexError"]
fn test_raw_malformed() {
    construct_code(
        &[&["(((".to_owned()]],
        &[],
        &CodeBlock(vec![Replacing::WithRaw {
            group: 0,
            element: 0,
        }]),
        &mut TokenStream2::new(),
    );
}
