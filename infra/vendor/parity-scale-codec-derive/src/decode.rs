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

use crate::utils;
use proc_macro2::{Ident, Span, TokenStream};
use quote::ToTokens;
use std::iter;
use syn::{spanned::Spanned, Data, Error, Field, Fields};

/// Generate function block for function `Decode::decode`.
///
/// * data: data info of the type,
/// * type_name: name of the type,
/// * type_generics: the generics of the type in turbofish format, without bounds, e.g. `::<T, I>`
/// * input: the variable name for the argument of function `decode`.
pub fn quote(
	data: &Data,
	type_name: &Ident,
	type_generics: &TokenStream,
	input: &TokenStream,
	crate_path: &syn::Path,
) -> TokenStream {
	match *data {
		Data::Struct(ref data) => create_instance(
			quote! { #type_name #type_generics },
			&type_name.to_string(),
			input,
			&data.fields,
			crate_path,
		),
		Data::Enum(ref data) => {
			let variants = match utils::try_get_variants(data) {
				Ok(variants) => variants,
				Err(e) => return e.to_compile_error(),
			};

			let recurse = variants.iter().enumerate().map(|(i, v)| {
				let name = &v.ident;
				let index = utils::variant_index(v, i);

				let create = create_instance(
					quote! { #type_name :: #name #type_generics },
					&format!("{}::{}", type_name, name),
					input,
					&v.fields,
					crate_path,
				);

				quote_spanned! { v.span() =>
					#[allow(clippy::unnecessary_cast)]
					#[allow(clippy::cast_possible_truncation)]
					__codec_x_edqy if __codec_x_edqy == (#index) as ::core::primitive::u8 => {
						// NOTE: This lambda is necessary to work around an upstream bug
						// where each extra branch results in excessive stack usage:
						//   https://github.com/rust-lang/rust/issues/34283
						#[allow(clippy::redundant_closure_call)]
						return (move || {
							#create
						})();
					},
				}
			});
			let recurse_indices = variants
				.iter()
				.enumerate()
				.map(|(i, v)| (v.ident.clone(), utils::variant_index(v, i)));

			let const_eval_check =
				utils::const_eval_check_variant_indexes(recurse_indices, crate_path);

			let read_byte_err_msg =
				format!("Could not decode `{type_name}`, failed to read variant byte");
			let invalid_variant_err_msg =
				format!("Could not decode `{type_name}`, variant doesn't exist");
			quote! {
				#const_eval_check
				match #input.read_byte()
					.map_err(|e| e.chain(#read_byte_err_msg))?
				{
					#( #recurse )*
					_ => {
						#[allow(clippy::redundant_closure_call)]
						return (move || {
							::core::result::Result::Err(
								<_ as ::core::convert::Into<_>>::into(#invalid_variant_err_msg)
							)
						})();
					},
				}
			}
		},
		Data::Union(_) =>
			Error::new(Span::call_site(), "Union types are not supported.").to_compile_error(),
	}
}

pub fn quote_decode_into(
	data: &Data,
	crate_path: &syn::Path,
	input: &TokenStream,
	attrs: &[syn::Attribute],
) -> Option<TokenStream> {
	// Make sure the type is `#[repr(transparent)]`, as this guarantees that
	// there can be only one field that is not zero-sized.
	if !crate::utils::is_transparent(attrs) {
		return None;
	}

	let fields = match data {
		Data::Struct(syn::DataStruct {
			fields:
				Fields::Named(syn::FieldsNamed { named: fields, .. }) |
				Fields::Unnamed(syn::FieldsUnnamed { unnamed: fields, .. }),
			..
		}) => fields,
		_ => return None,
	};

	if fields.is_empty() {
		return None;
	}

	// Bail if there are any extra attributes which could influence how the type is decoded.
	if fields.iter().any(|field| {
		utils::get_encoded_as_type(field).is_some() ||
			utils::is_compact(field) ||
			utils::should_skip(&field.attrs)
	}) {
		return None;
	}

	// Go through each field and call `decode_into` on it.
	//
	// Normally if there's more than one field in the struct this would be incorrect,
	// however since the struct's marked as `#[repr(transparent)]` we're guaranteed that
	// there's at most one non zero-sized field, so only one of these `decode_into` calls
	// should actually do something, and the rest should just be dummy calls that do nothing.
	let mut decode_fields = Vec::new();
	let mut sizes = Vec::new();
	let mut non_zst_field_count = Vec::new();
	for field in fields {
		let field_type = &field.ty;
		decode_fields.push(quote! {{
			let dst_: &mut ::core::mem::MaybeUninit<Self> = dst_; // To make sure the type is what we expect.

			// Here we cast `&mut MaybeUninit<Self>` into a `&mut MaybeUninit<#field_type>`.
			//
			// SAFETY: The struct is marked as `#[repr(transparent)]` so the address of every field will
			//         be the same as the address of the struct itself.
			let dst_: &mut ::core::mem::MaybeUninit<#field_type> = unsafe {
				&mut *dst_.as_mut_ptr().cast::<::core::mem::MaybeUninit<#field_type>>()
			};
			<#field_type as #crate_path::Decode>::decode_into(#input, dst_)?;
		}});

		if !sizes.is_empty() {
			sizes.push(quote! { + });
		}
		sizes.push(quote! { ::core::mem::size_of::<#field_type>() });

		if !non_zst_field_count.is_empty() {
			non_zst_field_count.push(quote! { + });
		}
		non_zst_field_count
			.push(quote! { if ::core::mem::size_of::<#field_type>() > 0 { 1 } else { 0 } });
	}

	Some(quote! {
		// Just a sanity check. These should always be true and will be optimized-out.
		::core::assert_eq!(#(#sizes)*, ::core::mem::size_of::<Self>());
		::core::assert!(#(#non_zst_field_count)* <= 1);

		#(#decode_fields)*

		// SAFETY: We've successfully called `decode_into` for all of the fields.
		unsafe { ::core::result::Result::Ok(#crate_path::DecodeFinished::assert_decoding_finished()) }
	})
}

fn create_decode_expr(
	field: &Field,
	name: &str,
	input: &TokenStream,
	crate_path: &syn::Path,
) -> TokenStream {
	let encoded_as = utils::get_encoded_as_type(field);
	let compact = utils::get_compact_type(field, crate_path);
	let skip = utils::should_skip(&field.attrs);

	let res = quote!(__codec_res_edqy);

	if encoded_as.is_some() as u8 + compact.is_some() as u8 + skip as u8 > 1 {
		return Error::new(
			field.span(),
			"`encoded_as`, `compact` and `skip` can only be used one at a time!",
		)
		.to_compile_error();
	}

	let err_msg = format!("Could not decode `{}`", name);

	if let Some(compact) = compact {
		quote_spanned! { field.span() =>
			{
				let #res = <#compact as #crate_path::Decode>::decode(#input);
				match #res {
					::core::result::Result::Err(e) => return ::core::result::Result::Err(e.chain(#err_msg)),
					::core::result::Result::Ok(#res) => #res.into(),
				}
			}
		}
	} else if let Some(encoded_as) = encoded_as {
		quote_spanned! { field.span() =>
			{
				let #res = <#encoded_as as #crate_path::Decode>::decode(#input);
				match #res {
					::core::result::Result::Err(e) => return ::core::result::Result::Err(e.chain(#err_msg)),
					::core::result::Result::Ok(#res) => #res.into(),
				}
			}
		}
	} else if skip {
		quote_spanned! { field.span() => ::core::default::Default::default() }
	} else {
		let field_type = &field.ty;
		quote_spanned! { field.span() =>
			{
				let #res = <#field_type as #crate_path::Decode>::decode(#input);
				match #res {
					::core::result::Result::Err(e) => return ::core::result::Result::Err(e.chain(#err_msg)),
					::core::result::Result::Ok(#res) => #res,
				}
			}
		}
	}
}

fn create_instance(
	name: TokenStream,
	name_str: &str,
	input: &TokenStream,
	fields: &Fields,
	crate_path: &syn::Path,
) -> TokenStream {
	match *fields {
		Fields::Named(ref fields) => {
			let recurse = fields.named.iter().map(|f| {
				let name_ident = &f.ident;
				let field_name = match name_ident {
					Some(a) => format!("{}::{}", name_str, a),
					None => name_str.to_string(), // Should never happen, fields are named.
				};
				let decode = create_decode_expr(f, &field_name, input, crate_path);

				quote_spanned! { f.span() =>
					#name_ident: #decode
				}
			});

			quote_spanned! { fields.span() =>
				::core::result::Result::Ok(#name {
					#( #recurse, )*
				})
			}
		},
		Fields::Unnamed(ref fields) => {
			let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
				let field_name = format!("{}.{}", name_str, i);

				create_decode_expr(f, &field_name, input, crate_path)
			});

			quote_spanned! { fields.span() =>
				::core::result::Result::Ok(#name (
					#( #recurse, )*
				))
			}
		},
		Fields::Unit => {
			quote_spanned! { fields.span() =>
				::core::result::Result::Ok(#name)
			}
		},
	}
}

pub fn quote_decode_with_mem_tracking_checks(data: &Data, crate_path: &syn::Path) -> TokenStream {
	let fields: Box<dyn Iterator<Item = &Field>> = match data {
		Data::Struct(data) => Box::new(data.fields.iter()),
		Data::Enum(ref data) => {
			let variants = match utils::try_get_variants(data) {
				Ok(variants) => variants,
				Err(e) => return e.to_compile_error(),
			};

			let mut fields: Box<dyn Iterator<Item = &Field>> = Box::new(iter::empty());
			for variant in variants {
				fields = Box::new(fields.chain(variant.fields.iter()));
			}
			fields
		},
		Data::Union(_) => {
			return Error::new(Span::call_site(), "Union types are not supported.")
				.to_compile_error();
		},
	};

	let processed_fields = fields.filter_map(|field| {
		if utils::should_skip(&field.attrs) {
			return None;
		}

		let field_type = if let Some(compact) = utils::get_compact_type(field, crate_path) {
			compact
		} else if let Some(encoded_as) = utils::get_encoded_as_type(field) {
			encoded_as
		} else {
			field.ty.to_token_stream()
		};
		Some(quote_spanned! {field.span() => #field_type})
	});

	quote! {
		fn check_field<T: #crate_path::DecodeWithMemTracking>() {}

		#(
			check_field::<#processed_fields>();
		)*
	}
}
