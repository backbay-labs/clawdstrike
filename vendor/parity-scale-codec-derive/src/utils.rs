// Copyright 2018-2020 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Various internal utils.
//!
//! NOTE: attributes finder must be checked using check_attribute first,
//! otherwise the macro can panic.

use std::str::FromStr;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
	parse::Parse, punctuated::Punctuated, spanned::Spanned, token, Attribute, Data, DataEnum,
	DeriveInput, Expr, ExprLit, Field, Fields, FieldsNamed, FieldsUnnamed, Lit, Meta,
	MetaNameValue, Path, Variant,
};

fn find_meta_item<'a, F, R, I, M>(mut itr: I, mut pred: F) -> Option<R>
where
	F: FnMut(M) -> Option<R> + Clone,
	I: Iterator<Item = &'a Attribute>,
	M: Parse,
{
	itr.find_map(|attr| {
		attr.path().is_ident("codec").then(|| pred(attr.parse_args().ok()?)).flatten()
	})
}

pub fn const_eval_check_variant_indexes(
	recurse_variant_indices: impl Iterator<Item = (syn::Ident, TokenStream)>,
	crate_path: &syn::Path,
) -> TokenStream {
	let mut recurse_indices = vec![];
	for (ident, index) in recurse_variant_indices {
		let ident_str = ident.to_string();
		// We convert to usize, index should fit in usize.
		recurse_indices.push(quote_spanned! { ident.span() =>
			(
				(#index) as ::core::primitive::usize,
				#ident_str
			)
		});
	}
	let len = recurse_indices.len();

	if len == 0 {
		return quote! {};
	}

	quote! {
		#[automatically_derived]
		const _: () = {
			#[allow(clippy::unnecessary_cast)]
			#[allow(clippy::cast_possible_truncation)]
			const indices: [(usize, &'static str); #len] = [#( #recurse_indices ,)*];

			const fn search_for_invalid_index(array: &[(usize, &'static str); #len]) -> (bool, usize) {
				let mut i = 0;
				while i < #len {
					if array[i].0 > 255 {
						return (true, i);
					}

					i += 1;
				}

				(false, 0)
			}

			const INVALID_INDEX: (bool, usize) = search_for_invalid_index(&indices);

			if INVALID_INDEX.0 {
				let msg = #crate_path::__private::concatcp!(
					"Found variant `",
					indices[INVALID_INDEX.1].1,
					"` with invalid index: `",
					indices[INVALID_INDEX.1].0,
					"`. Max supported index is 255.",
				);
				::core::panic!("{}", msg);
			}

			// Returns if there is duplicate, and if there is some the duplicate indexes.
			const fn duplicate_info(array: &[(usize, &'static str); #len]) -> (bool, usize, usize) {
				let len = #len;
				let mut i = 0usize;
				while i < len {
						let mut j = i + 1;
						while j < len {
								if array[i].0 == array[j].0 {
									return (true, i, j);
								}
								j += 1;
						}
						i += 1;
				}
				(false, 0, 0)
			}

			const DUP_INFO: (bool, usize, usize) = duplicate_info(&indices);

			if DUP_INFO.0 {
				let msg = #crate_path::__private::concatcp!(
					"Found variants that have duplicate indexes. Both `",
					indices[DUP_INFO.1].1,
					"` and `",
					indices[DUP_INFO.2].1,
					"` have the index `",
					indices[DUP_INFO.1].0,
					"`. Use different indexes for each variant."
				);

				::core::panic!("{}", msg);
			}
		};
	}
}

/// Look for a `#[scale(index = $int)]` attribute on a variant. If no attribute
/// is found, fall back to the discriminant or just the variant index.
pub fn variant_index(v: &Variant, i: usize) -> TokenStream {
	// first look for an attribute
	let index = find_meta_item(v.attrs.iter(), |meta| {
		if let Meta::NameValue(ref nv) = meta {
			if nv.path.is_ident("index") {
				if let Expr::Lit(ExprLit { lit: Lit::Int(ref v), .. }) = nv.value {
					let byte = v
						.base10_parse::<usize>()
						.expect("Internal error, index attribute must have been checked");
					return Some(byte);
				}
			}
		}

		None
	});

	// then fallback to discriminant or just index
	index.map(|i| quote! { #i }).unwrap_or_else(|| {
		v.discriminant
			.as_ref()
			.map(|(_, expr)| quote! { #expr })
			.unwrap_or_else(|| quote! { #i })
	})
}

/// Look for a `#[codec(encoded_as = "SomeType")]` outer attribute on the given
/// `Field`.
pub fn get_encoded_as_type(field: &Field) -> Option<TokenStream> {
	find_meta_item(field.attrs.iter(), |meta| {
		if let Meta::NameValue(ref nv) = meta {
			if nv.path.is_ident("encoded_as") {
				if let Expr::Lit(ExprLit { lit: Lit::Str(ref s), .. }) = nv.value {
					return Some(
						TokenStream::from_str(&s.value())
							.expect("Internal error, encoded_as attribute must have been checked"),
					);
				}
			}
		}

		None
	})
}

/// Look for a `#[codec(compact)]` outer attribute on the given `Field`. If the attribute is found,
/// return the compact type associated with the field type.
pub fn get_compact_type(field: &Field, crate_path: &syn::Path) -> Option<TokenStream> {
	find_meta_item(field.attrs.iter(), |meta| {
		if let Meta::Path(ref path) = meta {
			if path.is_ident("compact") {
				let field_type = &field.ty;
				return Some(quote! {<#field_type as #crate_path::HasCompact>::Type});
			}
		}

		None
	})
}

/// Look for a `#[codec(compact)]` outer attribute on the given `Field`.
pub fn is_compact(field: &Field) -> bool {
	get_compact_type(field, &parse_quote!(::crate)).is_some()
}

/// Look for a `#[codec(skip)]` in the given attributes.
pub fn should_skip(attrs: &[Attribute]) -> bool {
	find_meta_item(attrs.iter(), |meta| {
		if let Meta::Path(ref path) = meta {
			if path.is_ident("skip") {
				return Some(path.span());
			}
		}

		None
	})
	.is_some()
}

/// Look for a `#[codec(dumb_trait_bound)]`in the given attributes.
pub fn has_dumb_trait_bound(attrs: &[Attribute]) -> bool {
	find_meta_item(attrs.iter(), |meta| {
		if let Meta::Path(ref path) = meta {
			if path.is_ident("dumb_trait_bound") {
				return Some(());
			}
		}

		None
	})
	.is_some()
}

/// Generate the crate access for the crate using 2018 syntax.
fn crate_access() -> syn::Result<proc_macro2::Ident> {
	use proc_macro2::{Ident, Span};
	use proc_macro_crate::{crate_name, FoundCrate};
	const DEF_CRATE: &str = "parity-scale-codec";
	match crate_name(DEF_CRATE) {
		Ok(FoundCrate::Itself) => {
			let name = DEF_CRATE.to_string().replace('-', "_");
			Ok(syn::Ident::new(&name, Span::call_site()))
		},
		Ok(FoundCrate::Name(name)) => Ok(Ident::new(&name, Span::call_site())),
		Err(e) => Err(syn::Error::new(Span::call_site(), e)),
	}
}

/// This struct matches `crate = ...` where the ellipsis is a `Path`.
struct CratePath {
	_crate_token: Token![crate],
	_eq_token: Token![=],
	path: Path,
}

impl Parse for CratePath {
	fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
		Ok(CratePath {
			_crate_token: input.parse()?,
			_eq_token: input.parse()?,
			path: input.parse()?,
		})
	}
}

impl From<CratePath> for Path {
	fn from(CratePath { path, .. }: CratePath) -> Self {
		path
	}
}

/// Match `#[codec(crate = ...)]` and return the `...` if it is a `Path`.
fn codec_crate_path_inner(attr: &Attribute) -> Option<Path> {
	// match `#[codec ...]`
	attr.path()
		.is_ident("codec")
		.then(|| {
			// match `#[codec(crate = ...)]` and return the `...`
			attr.parse_args::<CratePath>().map(Into::into).ok()
		})
		.flatten()
}

/// Match `#[codec(crate = ...)]` and return the ellipsis as a `Path`.
///
/// If not found, returns the default crate access pattern.
///
/// If multiple items match the pattern, all but the first are ignored.
pub fn codec_crate_path(attrs: &[Attribute]) -> syn::Result<Path> {
	match attrs.iter().find_map(codec_crate_path_inner) {
		Some(path) => Ok(path),
		None => crate_access().map(|ident| parse_quote!(::#ident)),
	}
}

/// Parse `name(T: Bound, N: Bound)` or `name(skip_type_params(T, N))` as a custom trait bound.
pub enum CustomTraitBound<N> {
	SpecifiedBounds {
		_name: N,
		_paren_token: token::Paren,
		bounds: Punctuated<syn::WherePredicate, Token![,]>,
	},
	SkipTypeParams {
		_name: N,
		_paren_token_1: token::Paren,
		_skip_type_params: skip_type_params,
		_paren_token_2: token::Paren,
		type_names: Punctuated<syn::Ident, Token![,]>,
	},
}

impl<N: Parse> Parse for CustomTraitBound<N> {
	fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
		let mut content;
		let _name: N = input.parse()?;
		let _paren_token = syn::parenthesized!(content in input);
		if content.peek(skip_type_params) {
			Ok(Self::SkipTypeParams {
				_name,
				_paren_token_1: _paren_token,
				_skip_type_params: content.parse::<skip_type_params>()?,
				_paren_token_2: syn::parenthesized!(content in content),
				type_names: content.parse_terminated(syn::Ident::parse, Token![,])?,
			})
		} else {
			Ok(Self::SpecifiedBounds {
				_name,
				_paren_token,
				bounds: content.parse_terminated(syn::WherePredicate::parse, Token![,])?,
			})
		}
	}
}

syn::custom_keyword!(encode_bound);
syn::custom_keyword!(decode_bound);
syn::custom_keyword!(decode_with_mem_tracking_bound);
syn::custom_keyword!(mel_bound);
syn::custom_keyword!(skip_type_params);

/// Look for a `#[codec(decode_bound(T: Decode))]` in the given attributes.
///
/// If found, it should be used as trait bounds when deriving the `Decode` trait.
pub fn custom_decode_trait_bound(attrs: &[Attribute]) -> Option<CustomTraitBound<decode_bound>> {
	find_meta_item(attrs.iter(), Some)
}

/// Look for a `#[codec(decode_with_mem_tracking_bound(T: Decode))]` in the given attributes.
///
/// If found, it should be used as trait bounds when deriving the `Decode` trait.
pub fn custom_decode_with_mem_tracking_trait_bound(
	attrs: &[Attribute],
) -> Option<CustomTraitBound<decode_with_mem_tracking_bound>> {
	find_meta_item(attrs.iter(), Some)
}

/// Look for a `#[codec(encode_bound(T: Encode))]` in the given attributes.
///
/// If found, it should be used as trait bounds when deriving the `Encode` trait.
pub fn custom_encode_trait_bound(attrs: &[Attribute]) -> Option<CustomTraitBound<encode_bound>> {
	find_meta_item(attrs.iter(), Some)
}

/// Look for a `#[codec(mel_bound(T: MaxEncodedLen))]` in the given attributes.
///
/// If found, it should be used as the trait bounds when deriving the `MaxEncodedLen` trait.
#[cfg(feature = "max-encoded-len")]
pub fn custom_mel_trait_bound(attrs: &[Attribute]) -> Option<CustomTraitBound<mel_bound>> {
	find_meta_item(attrs.iter(), Some)
}

/// Given a set of named fields, return an iterator of `Field` where all fields
/// marked `#[codec(skip)]` are filtered out.
pub fn filter_skip_named(fields: &syn::FieldsNamed) -> impl Iterator<Item = &Field> {
	fields.named.iter().filter(|f| !should_skip(&f.attrs))
}

/// Given a set of unnamed fields, return an iterator of `(index, Field)` where all fields
/// marked `#[codec(skip)]` are filtered out.
pub fn filter_skip_unnamed(fields: &syn::FieldsUnnamed) -> impl Iterator<Item = (usize, &Field)> {
	fields.unnamed.iter().enumerate().filter(|(_, f)| !should_skip(&f.attrs))
}

/// Ensure attributes are correctly applied. This *must* be called before using
/// any of the attribute finder methods or the macro may panic if it encounters
/// misapplied attributes.
///
/// The top level can have the following attributes:
///
/// * `#[codec(dumb_trait_bound)]`
/// * `#[codec(encode_bound(T: Encode))]`
/// * `#[codec(decode_bound(T: Decode))]`
/// * `#[codec(mel_bound(T: MaxEncodedLen))]`
/// * `#[codec(crate = path::to::crate)]
///
/// Fields can have the following attributes:
///
/// * `#[codec(skip)]`
/// * `#[codec(compact)]`
/// * `#[codec(encoded_as = "$EncodeAs")]` with $EncodedAs a valid TokenStream
///
/// Variants can have the following attributes:
///
/// * `#[codec(skip)]`
/// * `#[codec(index = $int)]`
pub fn check_attributes(input: &DeriveInput) -> syn::Result<()> {
	for attr in &input.attrs {
		check_top_attribute(attr)?;
	}

	match input.data {
		Data::Struct(ref data) => match &data.fields {
			| Fields::Named(FieldsNamed { named: fields, .. }) |
			Fields::Unnamed(FieldsUnnamed { unnamed: fields, .. }) =>
				for field in fields {
					for attr in &field.attrs {
						check_field_attribute(attr)?;
					}
				},
			Fields::Unit => (),
		},
		Data::Enum(ref data) =>
			for variant in data.variants.iter() {
				for attr in &variant.attrs {
					check_variant_attribute(attr)?;
				}
				for field in &variant.fields {
					for attr in &field.attrs {
						check_field_attribute(attr)?;
					}
				}
			},
		Data::Union(_) => (),
	}
	Ok(())
}

// Check if the attribute is `#[allow(..)]`, `#[deny(..)]`, `#[forbid(..)]` or `#[warn(..)]`.
pub fn is_lint_attribute(attr: &Attribute) -> bool {
	attr.path().is_ident("allow") ||
		attr.path().is_ident("deny") ||
		attr.path().is_ident("forbid") ||
		attr.path().is_ident("warn")
}

// Ensure a field is decorated only with the following attributes:
// * `#[codec(skip)]`
// * `#[codec(compact)]`
// * `#[codec(encoded_as = "$EncodeAs")]` with $EncodedAs a valid TokenStream
fn check_field_attribute(attr: &Attribute) -> syn::Result<()> {
	let field_error = "Invalid attribute on field, only `#[codec(skip)]`, `#[codec(compact)]` and \
		`#[codec(encoded_as = \"$EncodeAs\")]` are accepted.";

	if attr.path().is_ident("codec") {
		let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
		if nested.len() != 1 {
			return Err(syn::Error::new(attr.meta.span(), field_error));
		}
		match nested.first().expect("Just checked that there is one item; qed") {
			Meta::Path(path) if path.get_ident().map_or(false, |i| i == "skip") => Ok(()),

			Meta::Path(path) if path.get_ident().map_or(false, |i| i == "compact") => Ok(()),

			Meta::NameValue(MetaNameValue {
				path,
				value: Expr::Lit(ExprLit { lit: Lit::Str(lit_str), .. }),
				..
			}) if path.get_ident().map_or(false, |i| i == "encoded_as") =>
				TokenStream::from_str(&lit_str.value())
					.map(|_| ())
					.map_err(|_e| syn::Error::new(lit_str.span(), "Invalid token stream")),

			elt => Err(syn::Error::new(elt.span(), field_error)),
		}
	} else {
		Ok(())
	}
}

// Ensure a field is decorated only with the following attributes:
// * `#[codec(skip)]`
// * `#[codec(index = $int)]`
fn check_variant_attribute(attr: &Attribute) -> syn::Result<()> {
	let variant_error = "Invalid attribute on variant, only `#[codec(skip)]` and \
		`#[codec(index = $u8)]` are accepted.";

	if attr.path().is_ident("codec") {
		let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
		if nested.len() != 1 {
			return Err(syn::Error::new(attr.meta.span(), variant_error));
		}
		match nested.first().expect("Just checked that there is one item; qed") {
			Meta::Path(path) if path.get_ident().map_or(false, |i| i == "skip") => Ok(()),

			Meta::NameValue(MetaNameValue {
				path,
				value: Expr::Lit(ExprLit { lit: Lit::Int(_), .. }),
				..
			}) if path.get_ident().map_or(false, |i| i == "index") => Ok(()),

			elt => Err(syn::Error::new(elt.span(), variant_error)),
		}
	} else {
		Ok(())
	}
}

// Only `#[codec(dumb_trait_bound)]` is accepted as top attribute
fn check_top_attribute(attr: &Attribute) -> syn::Result<()> {
	let top_error = "Invalid attribute: only `#[codec(dumb_trait_bound)]`, \
		`#[codec(crate = path::to::crate)]`, `#[codec(encode_bound(T: Encode))]`, \
		`#[codec(decode_bound(T: Decode))]`, \
		`#[codec(decode_with_mem_tracking_bound(T: DecodeWithMemTracking))]` or \
		`#[codec(mel_bound(T: MaxEncodedLen))]` are accepted as top attribute";
	if attr.path().is_ident("codec") &&
		attr.parse_args::<CustomTraitBound<encode_bound>>().is_err() &&
		attr.parse_args::<CustomTraitBound<decode_bound>>().is_err() &&
		attr.parse_args::<CustomTraitBound<decode_with_mem_tracking_bound>>().is_err() &&
		attr.parse_args::<CustomTraitBound<mel_bound>>().is_err() &&
		codec_crate_path_inner(attr).is_none()
	{
		let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
		if nested.len() != 1 {
			return Err(syn::Error::new(attr.meta.span(), top_error));
		}
		match nested.first().expect("Just checked that there is one item; qed") {
			Meta::Path(path) if path.get_ident().map_or(false, |i| i == "dumb_trait_bound") =>
				Ok(()),

			elt => Err(syn::Error::new(elt.span(), top_error)),
		}
	} else {
		Ok(())
	}
}

/// Checks whether the given attributes contain a `#[repr(transparent)]`.
pub fn is_transparent(attrs: &[syn::Attribute]) -> bool {
	attrs.iter().any(|attr| {
		if !attr.path().is_ident("repr") {
			return false;
		}
		let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
		else {
			return false;
		};
		nested.iter().any(|n| matches!(n, Meta::Path(p) if p.is_ident("transparent")))
	})
}

pub fn try_get_variants(data: &DataEnum) -> Result<Vec<&Variant>, syn::Error> {
	let data_variants: Vec<_> =
		data.variants.iter().filter(|variant| !should_skip(&variant.attrs)).collect();

	if data_variants.len() > 256 {
		return Err(syn::Error::new(
			data.variants.span(),
			"Currently only enums with at most 256 variants are encodable/decodable.",
		));
	}

	Ok(data_variants)
}
