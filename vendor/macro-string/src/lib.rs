//! [![github]](https://github.com/dtolnay/macro-string)&ensp;[![crates-io]](https://crates.io/crates/macro-string)&ensp;[![docs-rs]](https://docs.rs/macro-string)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! <br>
//!
//! This crate is a helper library for procedural macros to perform eager
//! evaluation of standard library string macros like `concat!` and `env!` in
//! macro input.
//!
//! <table><tr><td>
//! <b>Supported macros:</b>
//! <code>concat!</code>,
//! <code>env!</code>,
//! <code>include!</code>,
//! <code>include_str!</code>,
//! <code>stringify!</code>
//! </td></tr></table>
//!
//! For example, to implement a macro such as the following:
//!
//! ```
//! # macro_rules! include_json {
//! #     ($path:expr) => { $path };
//! # }
//! #
//! // Parses JSON at compile time and expands to a serde_json::Value.
//! let j = include_json!(concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json"));
//! ```
//!
//! the implementation of `include_json!` will need to parse and eagerly
//! evaluate the two macro calls within its input tokens.
//!
//! ```
//! # extern crate proc_macro;
//! #
//! use macro_string::MacroString;
//! use proc_macro::TokenStream;
//! use proc_macro2::Span;
//! use std::fs;
//! use syn::parse_macro_input;
//!
//! # const _: &str = stringify! {
//! #[proc_macro]
//! # };
//! pub fn include_json(input: TokenStream) -> TokenStream {
//!     let MacroString(path) = parse_macro_input!(input);
//!
//!     let content = match fs::read(&path) {
//!         Ok(content) => content,
//!         Err(err) => {
//!             return TokenStream::from(syn::Error::new(Span::call_site(), err).to_compile_error());
//!         }
//!     };
//!
//!     let json: serde_json::Value = match serde_json::from_slice(&content) {
//!         Ok(json) => json,
//!         Err(err) => {
//!             return TokenStream::from(syn::Error::new(Span::call_site(), err).to_compile_error());
//!         }
//!     };
//!
//!     /*TODO: print serde_json::Value to TokenStream*/
//!     # unimplemented!()
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/macro-string/0.1.4")]

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use syn::parse::{Error, Parse, ParseBuffer, ParseStream, Parser, Result};
use syn::punctuated::Punctuated;
use syn::token::{Brace, Bracket, Paren};
use syn::{
    braced, bracketed, parenthesized, Ident, LitBool, LitChar, LitFloat, LitInt, LitStr, Token,
};

mod kw {
    syn::custom_keyword!(concat);
    syn::custom_keyword!(env);
    syn::custom_keyword!(include);
    syn::custom_keyword!(include_str);
    syn::custom_keyword!(stringify);
}

pub struct MacroString(pub String);

impl Parse for MacroString {
    fn parse(input: ParseStream) -> Result<Self> {
        let expr = input.call(Expr::parse_strict)?;
        let value = expr.eval()?;
        Ok(MacroString(value))
    }
}

enum Expr {
    LitStr(LitStr),
    LitChar(LitChar),
    LitInt(LitInt),
    LitFloat(LitFloat),
    LitBool(LitBool),
    Concat(Concat),
    Env(Env),
    Include(Include),
    IncludeStr(IncludeStr),
    Stringify(Stringify),
}

impl Expr {
    fn eval(&self) -> Result<String> {
        match self {
            Expr::LitStr(lit) => Ok(lit.value()),
            Expr::LitChar(lit) => Ok(lit.value().to_string()),
            Expr::LitInt(lit) => Ok(lit.base10_digits().to_owned()),
            Expr::LitFloat(lit) => Ok(lit.base10_digits().to_owned()),
            Expr::LitBool(lit) => Ok(lit.value.to_string()),
            Expr::Concat(expr) => {
                let mut concat = String::new();
                for arg in &expr.args {
                    concat += &arg.eval()?;
                }
                Ok(concat)
            }
            Expr::Env(expr) => {
                let key = expr.arg.eval()?;
                match env::var(&key) {
                    Ok(value) => Ok(value),
                    Err(err) => Err(Error::new_spanned(expr, err)),
                }
            }
            Expr::Include(expr) => {
                let path = expr.arg.eval()?;
                let content = fs_read(&expr, &path)?;
                let inner = Expr::parse_strict.parse_str(&content)?;
                inner.eval()
            }
            Expr::IncludeStr(expr) => {
                let path = expr.arg.eval()?;
                fs_read(&expr, &path)
            }
            Expr::Stringify(expr) => Ok(expr.tokens.to_string()),
        }
    }
}

fn fs_read(span: &dyn ToTokens, path: impl AsRef<Path>) -> Result<String> {
    let mut path = path.as_ref();
    if path.is_relative() {
        let name = span.to_token_stream().into_iter().next().unwrap();
        return Err(Error::new_spanned(
            span,
            format!("a relative path is not supported here; use `{name}!(concat!(env!(\"CARGO_MANIFEST_DIR\"), ...))`"),
        ));
    }

    // Make Windows verbatim paths work even with mixed path separators, which
    // can happen when a path is produced using `concat!`.
    let path_buf: PathBuf;
    if let Some(Component::Prefix(prefix)) = path.components().next() {
        if prefix.kind().is_verbatim() {
            path_buf = path.components().collect();
            path = &path_buf;
        }
    }

    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(err) => Err(Error::new_spanned(
            span,
            format!("{} {}", err, path.display()),
        )),
    }
}

struct Concat {
    name: kw::concat,
    bang_token: Token![!],
    delimiter: MacroDelimiter,
    args: Punctuated<Expr, Token![,]>,
}

struct Env {
    name: kw::env,
    bang_token: Token![!],
    delimiter: MacroDelimiter,
    arg: Box<Expr>,
    trailing_comma: Option<Token![,]>,
}

struct Include {
    name: kw::include,
    bang_token: Token![!],
    delimiter: MacroDelimiter,
    arg: Box<Expr>,
    trailing_comma: Option<Token![,]>,
}

struct IncludeStr {
    name: kw::include_str,
    bang_token: Token![!],
    delimiter: MacroDelimiter,
    arg: Box<Expr>,
    trailing_comma: Option<Token![,]>,
}

struct Stringify {
    name: kw::stringify,
    bang_token: Token![!],
    delimiter: MacroDelimiter,
    tokens: TokenStream,
}

enum MacroDelimiter {
    Paren(Paren),
    Brace(Brace),
    Bracket(Bracket),
}

impl Expr {
    fn parse_strict(input: ParseStream) -> Result<Self> {
        Self::parse(input, false)
    }

    fn parse_any(input: ParseStream) -> Result<Self> {
        Self::parse(input, true)
    }

    fn parse(input: ParseStream, allow_nonstring_literals: bool) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            if !lit.suffix().is_empty() {
                return Err(Error::new(
                    lit.span(),
                    "unexpected suffix on string literal",
                ));
            }
            Ok(Expr::LitStr(lit))
        } else if allow_nonstring_literals && input.peek(LitChar) {
            let lit: LitChar = input.parse()?;
            if !lit.suffix().is_empty() {
                return Err(Error::new(lit.span(), "unexpected suffix on char literal"));
            }
            Ok(Expr::LitChar(lit))
        } else if allow_nonstring_literals && input.peek(LitInt) {
            let lit: LitInt = input.parse()?;
            match lit.suffix() {
                "" | "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "f16" | "f32" | "f64" | "f128" => {}
                _ => {
                    return Err(Error::new(
                        lit.span(),
                        "unexpected suffix on integer literal",
                    ));
                }
            }
            Ok(Expr::LitInt(lit))
        } else if allow_nonstring_literals && input.peek(LitFloat) {
            let lit: LitFloat = input.parse()?;
            match lit.suffix() {
                "" | "f16" | "f32" | "f64" | "f128" => {}
                _ => return Err(Error::new(lit.span(), "unexpected suffix on float literal")),
            }
            Ok(Expr::LitFloat(lit))
        } else if allow_nonstring_literals && input.peek(LitBool) {
            input.parse().map(Expr::LitBool)
        } else if lookahead.peek(kw::concat) {
            input.parse().map(Expr::Concat)
        } else if lookahead.peek(kw::env) {
            input.parse().map(Expr::Env)
        } else if lookahead.peek(kw::include) {
            input.parse().map(Expr::Include)
        } else if lookahead.peek(kw::include_str) {
            input.parse().map(Expr::IncludeStr)
        } else if lookahead.peek(kw::stringify) {
            input.parse().map(Expr::Stringify)
        } else if input.peek(Ident) && input.peek2(Token![!]) && input.peek3(Paren) {
            let ident: Ident = input.parse()?;
            let bang_token: Token![!] = input.parse()?;
            let unsupported = quote!(#ident #bang_token);
            Err(Error::new_spanned(
                unsupported,
                "unsupported macro, expected one of: `concat!`, `env!`, `include!`, `include_str!`, `stringify!`",
            ))
        } else {
            Err(lookahead.error())
        }
    }
}

impl ToTokens for Expr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Expr::LitStr(expr) => expr.to_tokens(tokens),
            Expr::LitChar(expr) => expr.to_tokens(tokens),
            Expr::LitInt(expr) => expr.to_tokens(tokens),
            Expr::LitFloat(expr) => expr.to_tokens(tokens),
            Expr::LitBool(expr) => expr.to_tokens(tokens),
            Expr::Concat(expr) => expr.to_tokens(tokens),
            Expr::Env(expr) => expr.to_tokens(tokens),
            Expr::Include(expr) => expr.to_tokens(tokens),
            Expr::IncludeStr(expr) => expr.to_tokens(tokens),
            Expr::Stringify(expr) => expr.to_tokens(tokens),
        }
    }
}

macro_rules! macro_delimiter {
    ($var:ident in $input:ident) => {{
        let (delim, content) = $input.call(macro_delimiter)?;
        $var = content;
        delim
    }};
}

fn macro_delimiter(input: ParseStream) -> Result<(MacroDelimiter, ParseBuffer)> {
    let content;
    let lookahead = input.lookahead1();
    let delim = if input.peek(Paren) {
        MacroDelimiter::Paren(parenthesized!(content in input))
    } else if input.peek(Brace) {
        MacroDelimiter::Brace(braced!(content in input))
    } else if input.peek(Bracket) {
        MacroDelimiter::Bracket(bracketed!(content in input))
    } else {
        return Err(lookahead.error());
    };
    Ok((delim, content))
}

impl MacroDelimiter {
    fn surround<F>(&self, tokens: &mut TokenStream, f: F)
    where
        F: FnOnce(&mut TokenStream),
    {
        match self {
            MacroDelimiter::Paren(delimiter) => delimiter.surround(tokens, f),
            MacroDelimiter::Brace(delimiter) => delimiter.surround(tokens, f),
            MacroDelimiter::Bracket(delimiter) => delimiter.surround(tokens, f),
        }
    }
}

impl Parse for Concat {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        Ok(Concat {
            name: input.parse()?,
            bang_token: input.parse()?,
            delimiter: macro_delimiter!(content in input),
            args: Punctuated::parse_terminated_with(&content, Expr::parse_any)?,
        })
    }
}

impl ToTokens for Concat {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.bang_token.to_tokens(tokens);
        self.delimiter
            .surround(tokens, |tokens| self.args.to_tokens(tokens));
    }
}

impl Parse for Env {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        Ok(Env {
            name: input.parse()?,
            bang_token: input.parse()?,
            delimiter: macro_delimiter!(content in input),
            arg: Expr::parse_strict(&content).map(Box::new)?,
            trailing_comma: content.parse()?,
        })
    }
}

impl ToTokens for Env {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.bang_token.to_tokens(tokens);
        self.delimiter.surround(tokens, |tokens| {
            self.arg.to_tokens(tokens);
            self.trailing_comma.to_tokens(tokens);
        });
    }
}

impl Parse for Include {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        Ok(Include {
            name: input.parse()?,
            bang_token: input.parse()?,
            delimiter: macro_delimiter!(content in input),
            arg: Expr::parse_strict(&content).map(Box::new)?,
            trailing_comma: content.parse()?,
        })
    }
}

impl ToTokens for Include {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.bang_token.to_tokens(tokens);
        self.delimiter.surround(tokens, |tokens| {
            self.arg.to_tokens(tokens);
            self.trailing_comma.to_tokens(tokens);
        });
    }
}

impl Parse for IncludeStr {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        Ok(IncludeStr {
            name: input.parse()?,
            bang_token: input.parse()?,
            delimiter: macro_delimiter!(content in input),
            arg: Expr::parse_strict(&content).map(Box::new)?,
            trailing_comma: content.parse()?,
        })
    }
}

impl ToTokens for IncludeStr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.bang_token.to_tokens(tokens);
        self.delimiter.surround(tokens, |tokens| {
            self.arg.to_tokens(tokens);
            self.trailing_comma.to_tokens(tokens);
        });
    }
}

impl Parse for Stringify {
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        Ok(Stringify {
            name: input.parse()?,
            bang_token: input.parse()?,
            delimiter: macro_delimiter!(content in input),
            tokens: content.parse()?,
        })
    }
}

impl ToTokens for Stringify {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.bang_token.to_tokens(tokens);
        self.delimiter
            .surround(tokens, |tokens| self.tokens.to_tokens(tokens));
    }
}
