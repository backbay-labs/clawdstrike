// Copyright 2017, 2018 Parity Technologies
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

use std::str::from_utf8;

use proc_macro2::{Ident, Span, TokenStream};
use syn::{punctuated::Punctuated, spanned::Spanned, token::Comma, Data, Error, Field, Fields};

use crate::utils::{self, const_eval_check_variant_indexes};

type FieldsList = Punctuated<Field, Comma>;

// Encode a single field by using using_encoded, must not have skip attribute
fn encode_single_field(
	field: &Field,
	field_name: TokenStream,
	crate_path: &syn::Path,
) -> TokenStream {
	let encoded_as = utils::get_encoded_as_type(field);
	let compact = utils::get_compact_type(field, crate_path);

	if utils::should_skip(&field.attrs) {
		return Error::new(
			Span::call_site(),
			"Internal error: cannot encode single field optimisation if skipped",
		)
		.to_compile_error();
	}

	if encoded_as.is_some() && compact.is_some() {
		return Error::new(
			Span::call_site(),
			"`encoded_as` and `compact` can not be used at the same time!",
		)
		.to_compile_error();
	}

	let final_field_variable = if let Some(compact) = compact {
		let field_type = &field.ty;
		quote_spanned! {
			field.span() => {
				<#compact as #crate_path::EncodeAsRef<'_, #field_type>>::RefType::from(#field_name)
			}
		}
	} else if let Some(encoded_as) = encoded_as {
		let field_type = &field.ty;
		quote_spanned! {
			field.span() => {
				<#encoded_as as
				#crate_path::EncodeAsRef<'_, #field_type>>::RefType::from(#field_name)
			}
		}
	} else {
		quote_spanned! { field.span() =>
			#field_name
		}
	};

	// This may have different hygiene than the field span
	let i_self = quote! { self };

	quote_spanned! { field.span() =>
			fn size_hint(&#i_self) -> usize {
				#crate_path::Encode::size_hint(&#final_field_variable)
			}

			fn encode_to<__CodecOutputEdqy: #crate_path::Output + ?::core::marker::Sized>(
				&#i_self,
				__codec_dest_edqy: &mut __CodecOutputEdqy
			) {
				#crate_path::Encode::encode_to(&#final_field_variable, __codec_dest_edqy)
			}

			fn encode(&#i_self) -> #crate_path::alloc::vec::Vec<::core::primitive::u8> {
				#crate_path::Encode::encode(&#final_field_variable)
			}

			fn using_encoded<
				__CodecOutputReturn,
				__CodecUsingEncodedCallback: ::core::ops::FnOnce(
					&[::core::primitive::u8]
				) -> __CodecOutputReturn
			>(&#i_self, f: __CodecUsingEncodedCallback) -> __CodecOutputReturn
			{
				#crate_path::Encode::using_encoded(&#final_field_variable, f)
			}
	}
}

enum FieldAttribute<'a> {
	None(&'a Field),
	Compact(&'a Field),
	EncodedAs { field: &'a Field, encoded_as: &'a TokenStream },
	Skip,
}

fn iterate_over_fields<F, H, J>(
	fields: &FieldsList,
	field_name: F,
	field_handler: H,
	field_joiner: J,
) -> TokenStream
where
	F: Fn(usize, &Option<Ident>) -> TokenStream,
	H: Fn(TokenStream, FieldAttribute) -> TokenStream,
	J: Fn(&mut dyn Iterator<Item = TokenStream>) -> TokenStream,
{
	let mut recurse = fields.iter().enumerate().map(|(i, f)| {
		let field = field_name(i, &f.ident);
		let encoded_as = utils::get_encoded_as_type(f);
		let compact = utils::is_compact(f);
		let skip = utils::should_skip(&f.attrs);

		if encoded_as.is_some() as u8 + compact as u8 + skip as u8 > 1 {
			return Error::new(
				f.span(),
				"`encoded_as`, `compact` and `skip` can only be used one at a time!",
			)
			.to_compile_error();
		}

		// Based on the seen attribute, we call a handler that generates code for a specific
		// attribute type.
		if compact {
			field_handler(field, FieldAttribute::Compact(f))
		} else if let Some(ref encoded_as) = encoded_as {
			field_handler(field, FieldAttribute::EncodedAs { field: f, encoded_as })
		} else if skip {
			field_handler(field, FieldAttribute::Skip)
		} else {
			field_handler(field, FieldAttribute::None(f))
		}
	});

	field_joiner(&mut recurse)
}

fn encode_fields<F>(
	dest: &TokenStream,
	fields: &FieldsList,
	field_name: F,
	crate_path: &syn::Path,
) -> TokenStream
where
	F: Fn(usize, &Option<Ident>) -> TokenStream,
{
	iterate_over_fields(
		fields,
		field_name,
		|field, field_attribute| match field_attribute {
			FieldAttribute::None(f) => quote_spanned! { f.span() =>
				#crate_path::Encode::encode_to(#field, #dest);
			},
			FieldAttribute::Compact(f) => {
				let field_type = &f.ty;
				quote_spanned! {
					f.span() => {
						#crate_path::Encode::encode_to(
							&<
								<#field_type as #crate_path::HasCompact>::Type as
								#crate_path::EncodeAsRef<'_, #field_type>
							>::RefType::from(#field),
							#dest,
						);
					}
				}
			},
			FieldAttribute::EncodedAs { field: f, encoded_as } => {
				let field_type = &f.ty;
				quote_spanned! {
					f.span() => {
						#crate_path::Encode::encode_to(
							&<
								#encoded_as as
								#crate_path::EncodeAsRef<'_, #field_type>
							>::RefType::from(#field),
							#dest,
						);
					}
				}
			},
			FieldAttribute::Skip => quote! {
				let _ = #field;
			},
		},
		|recurse| {
			quote! {
				#( #recurse )*
			}
		},
	)
}

fn size_hint_fields<F>(fields: &FieldsList, field_name: F, crate_path: &syn::Path) -> TokenStream
where
	F: Fn(usize, &Option<Ident>) -> TokenStream,
{
	iterate_over_fields(
		fields,
		field_name,
		|field, field_attribute| match field_attribute {
			FieldAttribute::None(f) => quote_spanned! { f.span() =>
				.saturating_add(#crate_path::Encode::size_hint(#field))
			},
			FieldAttribute::Compact(f) => {
				let field_type = &f.ty;
				quote_spanned! {
					f.span() => .saturating_add(#crate_path::Encode::size_hint(
						&<
							<#field_type as #crate_path::HasCompact>::Type as
							#crate_path::EncodeAsRef<'_, #field_type>
						>::RefType::from(#field),
					))
				}
			},
			FieldAttribute::EncodedAs { field: f, encoded_as } => {
				let field_type = &f.ty;
				quote_spanned! {
					f.span() => .saturating_add(#crate_path::Encode::size_hint(
						&<
							#encoded_as as
							#crate_path::EncodeAsRef<'_, #field_type>
						>::RefType::from(#field),
					))
				}
			},
			FieldAttribute::Skip => quote!(),
		},
		|recurse| {
			quote! {
				0_usize #( #recurse )*
			}
		},
	)
}

fn try_impl_encode_single_field_optimisation(
	data: &Data,
	crate_path: &syn::Path,
) -> Option<TokenStream> {
	match *data {
		Data::Struct(ref data) => match data.fields {
			Fields::Named(ref fields) if utils::filter_skip_named(fields).count() == 1 => {
				let field = utils::filter_skip_named(fields).next().unwrap();
				let name = &field.ident;
				Some(encode_single_field(field, quote!(&self.#name), crate_path))
			},
			Fields::Unnamed(ref fields) if utils::filter_skip_unnamed(fields).count() == 1 => {
				let (id, field) = utils::filter_skip_unnamed(fields).next().unwrap();
				let id = syn::Index::from(id);

				Some(encode_single_field(field, quote!(&self.#id), crate_path))
			},
			_ => None,
		},
		_ => None,
	}
}

fn impl_encode(data: &Data, type_name: &Ident, crate_path: &syn::Path) -> TokenStream {
	let self_ = quote!(self);
	let dest = &quote!(__codec_dest_edqy);
	let [hinting, encoding] = match *data {
		Data::Struct(ref data) => match data.fields {
			Fields::Named(ref fields) => {
				let fields = &fields.named;
				let field_name = |_, name: &Option<Ident>| quote!(&#self_.#name);

				let hinting = size_hint_fields(fields, field_name, crate_path);
				let encoding = encode_fields(dest, fields, field_name, crate_path);

				[hinting, encoding]
			},
			Fields::Unnamed(ref fields) => {
				let fields = &fields.unnamed;
				let field_name = |i, _: &Option<Ident>| {
					let i = syn::Index::from(i);
					quote!(&#self_.#i)
				};

				let hinting = size_hint_fields(fields, field_name, crate_path);
				let encoding = encode_fields(dest, fields, field_name, crate_path);

				[hinting, encoding]
			},
			Fields::Unit => [quote! { 0_usize }, quote!()],
		},
		Data::Enum(ref data) => {
			let variants = match utils::try_get_variants(data) {
				Ok(variants) => variants,
				Err(e) => return e.to_compile_error(),
			};

			// If the enum has no variants, we don't need to encode anything.
			if variants.is_empty() {
				return quote!();
			}

			let recurse = variants.iter().enumerate().map(|(i, f)| {
				let name = &f.ident;
				let index = utils::variant_index(f, i);

				match f.fields {
					Fields::Named(ref fields) => {
						let fields = &fields.named;
						let field_name = |_, ident: &Option<Ident>| quote!(#ident);

						let names = fields.iter().enumerate().map(|(i, f)| field_name(i, &f.ident));

						let field_name = |a, b: &Option<Ident>| field_name(a, b);

						let size_hint_fields = size_hint_fields(fields, field_name, crate_path);
						let encode_fields = encode_fields(dest, fields, field_name, crate_path);

						let hinting_names = names.clone();
						let hinting = quote_spanned! { f.span() =>
							#type_name :: #name { #( ref #hinting_names, )* } => {
								#size_hint_fields
							}
						};

						let encoding_names = names.clone();
						let encoding = quote_spanned! { f.span() =>
							#type_name :: #name { #( ref #encoding_names, )* } => {
								#[allow(clippy::unnecessary_cast)]
								#dest.push_byte((#index) as ::core::primitive::u8);
								#encode_fields
							}
						};

						(hinting, encoding, index, name.clone())
					},
					Fields::Unnamed(ref fields) => {
						let fields = &fields.unnamed;
						let field_name = |i, _: &Option<Ident>| {
							let data = stringify(i as u8);
							let ident = from_utf8(&data).expect("We never go beyond ASCII");
							let ident = Ident::new(ident, Span::call_site());
							quote!(#ident)
						};

						let names = fields.iter().enumerate().map(|(i, f)| field_name(i, &f.ident));

						let field_name = |a, b: &Option<Ident>| field_name(a, b);

						let size_hint_fields = size_hint_fields(fields, field_name, crate_path);
						let encode_fields = encode_fields(dest, fields, field_name, crate_path);

						let hinting_names = names.clone();
						let hinting = quote_spanned! { f.span() =>
							#type_name :: #name ( #( ref #hinting_names, )* ) => {
								#size_hint_fields
							}
						};

						let encoding_names = names.clone();
						let encoding = quote_spanned! { f.span() =>
							#type_name :: #name ( #( ref #encoding_names, )* ) => {
								#[allow(clippy::unnecessary_cast)]
								#dest.push_byte((#index) as ::core::primitive::u8);
								#encode_fields
							}
						};

						(hinting, encoding, index, name.clone())
					},
					Fields::Unit => {
						let hinting = quote_spanned! { f.span() =>
							#type_name :: #name => {
								0_usize
							}
						};

						let encoding = quote_spanned! { f.span() =>
							#type_name :: #name => {
								#[allow(clippy::unnecessary_cast)]
								#[allow(clippy::cast_possible_truncation)]
								#dest.push_byte((#index) as ::core::primitive::u8);
							}
						};

						(hinting, encoding, index, name.clone())
					},
				}
			});

			let recurse_hinting = recurse.clone().map(|(hinting, _, _, _)| hinting);
			let recurse_encoding = recurse.clone().map(|(_, encoding, _, _)| encoding);
			let recurse_variant_indices = recurse.clone().map(|(_, _, index, name)| (name, index));

			let hinting = quote! {
				// The variant index uses 1 byte.
				1_usize + match *#self_ {
					#( #recurse_hinting )*,
					_ => 0_usize,
				}
			};

			let const_eval_check =
				const_eval_check_variant_indexes(recurse_variant_indices, crate_path);

			let encoding = quote! {
				#const_eval_check
				match *#self_ {
					#( #recurse_encoding )*,
					_ => (),
				}
			};

			[hinting, encoding]
		},
		Data::Union(ref data) =>
			return Error::new(data.union_token.span(), "Union types are not supported.")
				.to_compile_error(),
	};
	quote! {
		fn size_hint(&#self_) -> usize {
			#hinting
		}

		fn encode_to<__CodecOutputEdqy: #crate_path::Output + ?::core::marker::Sized>(
			&#self_,
			#dest: &mut __CodecOutputEdqy
		) {
			#encoding
		}
	}
}

pub fn quote(data: &Data, type_name: &Ident, crate_path: &syn::Path) -> TokenStream {
	if let Some(implementation) = try_impl_encode_single_field_optimisation(data, crate_path) {
		implementation
	} else {
		impl_encode(data, type_name, crate_path)
	}
}

pub fn stringify(id: u8) -> [u8; 2] {
	const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
	let len = CHARS.len() as u8;
	let symbol = |id: u8| CHARS[(id % len) as usize];
	let a = symbol(id);
	let b = symbol(id / len);

	[a, b]
}
