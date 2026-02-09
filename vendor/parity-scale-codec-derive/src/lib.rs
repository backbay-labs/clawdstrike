// Copyright 2017-2021 Parity Technologies
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

//! Derives serialization and deserialization codec for complex structs for simple marshalling.

#![recursion_limit = "128"]
extern crate proc_macro;

#[macro_use]
extern crate syn;

#[macro_use]
extern crate quote;

use crate::utils::{codec_crate_path, is_lint_attribute};
use syn::{spanned::Spanned, Data, DeriveInput, Error, Field, Fields};

mod decode;
mod encode;
mod max_encoded_len;
mod trait_bounds;
mod utils;

/// Wraps the impl block in a "dummy const"
fn wrap_with_dummy_const(
	input: DeriveInput,
	impl_block: proc_macro2::TokenStream,
) -> proc_macro::TokenStream {
	let attrs = input.attrs.into_iter().filter(is_lint_attribute);
	let generated = quote! {
		#[allow(deprecated)]
		const _: () = {
			#(#attrs)*
			#impl_block
		};
	};

	generated.into()
}

/// Derive `parity_scale_codec::Encode` and `parity_scale_codec::EncodeLike` for struct and enum.
///
/// # Top level attributes
///
/// By default the macro will add [`Encode`] and [`Decode`] bounds to all types, but the bounds can
/// be specified manually with the top level attributes:
/// * `#[codec(encode_bound(T: Encode))]`: a custom bound added to the `where`-clause when deriving
///   the `Encode` trait, overriding the default.
/// * `#[codec(decode_bound(T: Decode))]`: a custom bound added to the `where`-clause when deriving
///   the `Decode` trait, overriding the default.
///
/// # Struct
///
/// A struct is encoded by encoding each of its fields successively.
///
/// Fields can have some attributes:
/// * `#[codec(skip)]`: the field is not encoded. It must derive `Default` if Decode is derived.
/// * `#[codec(compact)]`: the field is encoded in its compact representation i.e. the field must
///   implement `parity_scale_codec::HasCompact` and will be encoded as `HasCompact::Type`.
/// * `#[codec(encoded_as = "$EncodeAs")]`: the field is encoded as an alternative type. $EncodedAs
///   type must implement `parity_scale_codec::EncodeAsRef<'_, $FieldType>` with $FieldType the type
///   of the field with the attribute. This is intended to be used for types implementing
///   `HasCompact` as shown in the example.
///
/// ```
/// # use parity_scale_codec_derive::Encode;
/// # use parity_scale_codec::{Encode as _, HasCompact};
/// #[derive(Encode)]
/// struct StructType {
///     #[codec(skip)]
///     a: u32,
///     #[codec(compact)]
///     b: u32,
///     #[codec(encoded_as = "<u32 as HasCompact>::Type")]
///     c: u32,
/// }
/// ```
///
/// # Enum
///
/// The variable is encoded with one byte for the variant and then the variant struct encoding.
/// The variant number is:
/// * if variant has attribute: `#[codec(index = "$n")]` then n
/// * else if variant has discriminant (like 3 in `enum T { A = 3 }`) then the discriminant.
/// * else its position in the variant set, excluding skipped variants, but including variant with
///   discriminant or attribute. Warning this position does collision with discriminant or attribute
///   index.
///
/// variant attributes:
/// * `#[codec(skip)]`: the variant is not encoded.
/// * `#[codec(index = "$n")]`: override variant index.
///
/// field attributes: same as struct fields attributes.
///
/// ```
/// # use parity_scale_codec_derive::Encode;
/// # use parity_scale_codec::Encode as _;
/// #[derive(Encode)]
/// enum EnumType {
///     #[codec(index = 15)]
///     A,
///     #[codec(skip)]
///     B,
///     C = 3,
///     D,
/// }
///
/// assert_eq!(EnumType::A.encode(), vec![15]);
/// assert_eq!(EnumType::B.encode(), vec![]);
/// assert_eq!(EnumType::C.encode(), vec![3]);
/// assert_eq!(EnumType::D.encode(), vec![2]);
/// ```
#[proc_macro_derive(Encode, attributes(codec))]
pub fn encode_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let mut input: DeriveInput = match syn::parse(input) {
		Ok(input) => input,
		Err(e) => return e.to_compile_error().into(),
	};

	if let Err(e) = utils::check_attributes(&input) {
		return e.to_compile_error().into();
	}

	let crate_path = match codec_crate_path(&input.attrs) {
		Ok(crate_path) => crate_path,
		Err(error) => return error.into_compile_error().into(),
	};

	if let Err(e) = trait_bounds::add(
		&input.ident,
		&mut input.generics,
		&input.data,
		utils::custom_encode_trait_bound(&input.attrs),
		parse_quote!(#crate_path::Encode),
		None,
		utils::has_dumb_trait_bound(&input.attrs),
		&crate_path,
		false,
	) {
		return e.to_compile_error().into();
	}

	let name = &input.ident;
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

	let encode_impl = encode::quote(&input.data, name, &crate_path);

	let impl_block = quote! {
		#[automatically_derived]
		impl #impl_generics #crate_path::Encode for #name #ty_generics #where_clause {
			#encode_impl
		}

		#[automatically_derived]
		impl #impl_generics #crate_path::EncodeLike for #name #ty_generics #where_clause {}
	};

	wrap_with_dummy_const(input, impl_block)
}

/// Derive `parity_scale_codec::Decode` for struct and enum.
///
/// see derive `Encode` documentation.
#[proc_macro_derive(Decode, attributes(codec))]
pub fn decode_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let mut input: DeriveInput = match syn::parse(input) {
		Ok(input) => input,
		Err(e) => return e.to_compile_error().into(),
	};

	if let Err(e) = utils::check_attributes(&input) {
		return e.to_compile_error().into();
	}

	let crate_path = match codec_crate_path(&input.attrs) {
		Ok(crate_path) => crate_path,
		Err(error) => return error.into_compile_error().into(),
	};

	if let Err(e) = trait_bounds::add(
		&input.ident,
		&mut input.generics,
		&input.data,
		utils::custom_decode_trait_bound(&input.attrs),
		parse_quote!(#crate_path::Decode),
		Some(parse_quote!(Default)),
		utils::has_dumb_trait_bound(&input.attrs),
		&crate_path,
		false,
	) {
		return e.to_compile_error().into();
	}

	let name = &input.ident;
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
	let ty_gen_turbofish = ty_generics.as_turbofish();

	let input_ = quote!(__codec_input_edqy);
	let decoding =
		decode::quote(&input.data, name, &quote!(#ty_gen_turbofish), &input_, &crate_path);

	let decode_into_body =
		decode::quote_decode_into(&input.data, &crate_path, &input_, &input.attrs);

	let impl_decode_into = if let Some(body) = decode_into_body {
		quote! {
			fn decode_into<__CodecInputEdqy: #crate_path::Input>(
				#input_: &mut __CodecInputEdqy,
				dst_: &mut ::core::mem::MaybeUninit<Self>,
			) -> ::core::result::Result<#crate_path::DecodeFinished, #crate_path::Error> {
				#body
			}
		}
	} else {
		quote! {}
	};

	let impl_block = quote! {
		#[automatically_derived]
		impl #impl_generics #crate_path::Decode for #name #ty_generics #where_clause {
			fn decode<__CodecInputEdqy: #crate_path::Input>(
				#input_: &mut __CodecInputEdqy
			) -> ::core::result::Result<Self, #crate_path::Error> {
				#decoding
			}

			#impl_decode_into
		}
	};

	wrap_with_dummy_const(input, impl_block)
}

/// Derive `parity_scale_codec::DecodeWithMemTracking` for struct and enum.
#[proc_macro_derive(DecodeWithMemTracking, attributes(codec))]
pub fn decode_with_mem_tracking_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let mut input: DeriveInput = match syn::parse(input) {
		Ok(input) => input,
		Err(e) => return e.to_compile_error().into(),
	};

	if let Err(e) = utils::check_attributes(&input) {
		return e.to_compile_error().into();
	}

	let crate_path = match codec_crate_path(&input.attrs) {
		Ok(crate_path) => crate_path,
		Err(error) => return error.into_compile_error().into(),
	};

	if let Err(e) = trait_bounds::add(
		&input.ident,
		&mut input.generics,
		&input.data,
		utils::custom_decode_with_mem_tracking_trait_bound(&input.attrs),
		parse_quote!(#crate_path::DecodeWithMemTracking),
		Some(parse_quote!(Default)),
		utils::has_dumb_trait_bound(&input.attrs),
		&crate_path,
		true,
	) {
		return e.to_compile_error().into();
	}

	let name = &input.ident;
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

	let decode_with_mem_tracking_checks =
		decode::quote_decode_with_mem_tracking_checks(&input.data, &crate_path);
	let impl_block = quote! {
		fn check_struct #impl_generics() #where_clause {
			#decode_with_mem_tracking_checks
		}

		#[automatically_derived]
		impl #impl_generics #crate_path::DecodeWithMemTracking for #name #ty_generics #where_clause {
		}
	};

	wrap_with_dummy_const(input, impl_block)
}

/// Derive `parity_scale_codec::Compact` and `parity_scale_codec::CompactAs` for struct with single
/// field.
///
/// Attribute skip can be used to skip other fields.
///
/// # Example
///
/// ```
/// # use parity_scale_codec_derive::CompactAs;
/// # use parity_scale_codec::{Encode, HasCompact};
/// # use std::marker::PhantomData;
/// #[derive(CompactAs)]
/// struct MyWrapper<T>(u32, #[codec(skip)] PhantomData<T>);
/// ```
#[proc_macro_derive(CompactAs, attributes(codec))]
pub fn compact_as_derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let mut input: DeriveInput = match syn::parse(input) {
		Ok(input) => input,
		Err(e) => return e.to_compile_error().into(),
	};

	if let Err(e) = utils::check_attributes(&input) {
		return e.to_compile_error().into();
	}

	let crate_path = match codec_crate_path(&input.attrs) {
		Ok(crate_path) => crate_path,
		Err(error) => return error.into_compile_error().into(),
	};

	if let Err(e) = trait_bounds::add::<()>(
		&input.ident,
		&mut input.generics,
		&input.data,
		None,
		parse_quote!(#crate_path::CompactAs),
		None,
		utils::has_dumb_trait_bound(&input.attrs),
		&crate_path,
		false,
	) {
		return e.to_compile_error().into();
	}

	let name = &input.ident;
	let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

	fn val_or_default(field: &Field) -> proc_macro2::TokenStream {
		let skip = utils::should_skip(&field.attrs);
		if skip {
			quote_spanned!(field.span()=> Default::default())
		} else {
			quote_spanned!(field.span()=> x)
		}
	}

	let (inner_ty, inner_field, constructor) = match input.data {
		Data::Struct(ref data) => match data.fields {
			Fields::Named(ref fields) if utils::filter_skip_named(fields).count() == 1 => {
				let recurse = fields.named.iter().map(|f| {
					let name_ident = &f.ident;
					let val_or_default = val_or_default(f);
					quote_spanned!(f.span()=> #name_ident: #val_or_default)
				});
				let field = utils::filter_skip_named(fields).next().expect("Exactly one field");
				let field_name = &field.ident;
				let constructor = quote!( #name { #( #recurse, )* });
				(&field.ty, quote!(&self.#field_name), constructor)
			},
			Fields::Unnamed(ref fields) if utils::filter_skip_unnamed(fields).count() == 1 => {
				let recurse = fields.unnamed.iter().map(|f| {
					let val_or_default = val_or_default(f);
					quote_spanned!(f.span()=> #val_or_default)
				});
				let (id, field) =
					utils::filter_skip_unnamed(fields).next().expect("Exactly one field");
				let id = syn::Index::from(id);
				let constructor = quote!( #name(#( #recurse, )*));
				(&field.ty, quote!(&self.#id), constructor)
			},
			_ =>
				return Error::new(
					data.fields.span(),
					"Only structs with a single non-skipped field can derive CompactAs",
				)
				.to_compile_error()
				.into(),
		},
		Data::Enum(syn::DataEnum { enum_token: syn::token::Enum { span }, .. }) |
		Data::Union(syn::DataUnion { union_token: syn::token::Union { span }, .. }) =>
			return Error::new(span, "Only structs can derive CompactAs").to_compile_error().into(),
	};

	let impl_block = quote! {
		#[automatically_derived]
		impl #impl_generics #crate_path::CompactAs for #name #ty_generics #where_clause {
			type As = #inner_ty;
			fn encode_as(&self) -> &#inner_ty {
				#inner_field
			}
			fn decode_from(x: #inner_ty)
				-> ::core::result::Result<#name #ty_generics, #crate_path::Error>
			{
				::core::result::Result::Ok(#constructor)
			}
		}

		#[automatically_derived]
		impl #impl_generics From<#crate_path::Compact<#name #ty_generics>>
			for #name #ty_generics #where_clause
		{
			fn from(x: #crate_path::Compact<#name #ty_generics>) -> #name #ty_generics {
				x.0
			}
		}
	};

	wrap_with_dummy_const(input, impl_block)
}

/// Derive `parity_scale_codec::MaxEncodedLen` for struct and enum.
///
/// # Top level attribute
///
/// By default the macro will try to bound the types needed to implement `MaxEncodedLen`, but the
/// bounds can be specified manually with the top level attribute:
/// ```
/// # use parity_scale_codec_derive::Encode;
/// # use parity_scale_codec::MaxEncodedLen;
/// # #[derive(Encode, MaxEncodedLen)]
/// #[codec(mel_bound(T: MaxEncodedLen))]
/// # struct MyWrapper<T>(T);
/// ```
#[cfg(feature = "max-encoded-len")]
#[proc_macro_derive(MaxEncodedLen, attributes(max_encoded_len_mod))]
pub fn derive_max_encoded_len(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	max_encoded_len::derive_max_encoded_len(input)
}
