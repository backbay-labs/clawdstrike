// Copyright (C) 2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg(feature = "max-encoded-len")]

use crate::{
	trait_bounds,
	utils::{codec_crate_path, custom_mel_trait_bound, has_dumb_trait_bound, should_skip},
};
use quote::{quote, quote_spanned};
use syn::{parse_quote, spanned::Spanned, Data, DeriveInput, Field, Fields};

/// impl for `#[derive(MaxEncodedLen)]`
pub fn derive_max_encoded_len(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let mut input: DeriveInput = match syn::parse(input) {
		Ok(input) => input,
		Err(e) => return e.to_compile_error().into(),
	};

	let crate_path = match codec_crate_path(&input.attrs) {
		Ok(crate_path) => crate_path,
		Err(error) => return error.into_compile_error().into(),
	};

	let name = &input.ident;
	if let Err(e) = trait_bounds::add(
		&input.ident,
		&mut input.generics,
		&input.data,
		custom_mel_trait_bound(&input.attrs),
		parse_quote!(#crate_path::MaxEncodedLen),
		None,
		has_dumb_trait_bound(&input.attrs),
		&crate_path,
		false,
	) {
		return e.to_compile_error().into();
	}
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

	let data_expr = data_length_expr(&input.data, &crate_path);

	quote::quote!(
		const _: () = {
			#[automatically_derived]
			impl #impl_generics #crate_path::MaxEncodedLen for #name #ty_generics #where_clause {
				fn max_encoded_len() -> ::core::primitive::usize {
					#data_expr
				}
			}
		};
	)
	.into()
}

/// generate an expression to sum up the max encoded length from several fields
fn fields_length_expr(fields: &Fields, crate_path: &syn::Path) -> proc_macro2::TokenStream {
	let fields_iter: Box<dyn Iterator<Item = &Field>> = match fields {
		Fields::Named(ref fields) =>
			Box::new(fields.named.iter().filter(|field| !should_skip(&field.attrs))),
		Fields::Unnamed(ref fields) =>
			Box::new(fields.unnamed.iter().filter(|field| !should_skip(&field.attrs))),
		Fields::Unit => Box::new(std::iter::empty()),
	};
	// expands to an expression like
	//
	//   0
	//     .saturating_add(<type of first field>::max_encoded_len())
	//     .saturating_add(<type of second field>::max_encoded_len())
	//
	// We match the span of each field to the span of the corresponding
	// `max_encoded_len` call. This way, if one field's type doesn't implement
	// `MaxEncodedLen`, the compiler's error message will underline which field
	// caused the issue.
	let expansion = fields_iter.map(|field| {
		let ty = &field.ty;
		quote_spanned! {
			ty.span() => .saturating_add(<#ty as #crate_path::MaxEncodedLen>::max_encoded_len())
		}
	});
	quote! {
		0_usize #( #expansion )*
	}
}

// generate an expression to sum up the max encoded length of each field
fn data_length_expr(data: &Data, crate_path: &syn::Path) -> proc_macro2::TokenStream {
	match *data {
		Data::Struct(ref data) => fields_length_expr(&data.fields, crate_path),
		Data::Enum(ref data) => {
			// We need an expression expanded for each variant like
			//
			//   0
			//     .max(<variant expression>)
			//     .max(<variant expression>)
			//     .saturating_add(1)
			//
			// The 1 derives from the discriminant; see
			// https://github.com/paritytech/parity-scale-codec/
			//   blob/f0341dabb01aa9ff0548558abb6dcc5c31c669a1/derive/src/encode.rs#L211-L216
			//
			// Each variant expression's sum is computed the way an equivalent struct's would be.

			let expansion =
				data.variants.iter().filter(|variant| !should_skip(&variant.attrs)).map(
					|variant| {
						let variant_expression = fields_length_expr(&variant.fields, crate_path);
						quote! {
							.max(#variant_expression)
						}
					},
				);

			quote! {
				0_usize #( #expansion )* .saturating_add(1)
			}
		},
		Data::Union(ref data) => {
			// https://github.com/paritytech/parity-scale-codec/
			//   blob/f0341dabb01aa9ff0548558abb6dcc5c31c669a1/derive/src/encode.rs#L290-L293
			syn::Error::new(data.union_token.span(), "Union types are not supported.")
				.to_compile_error()
		},
	}
}
