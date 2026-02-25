use std::collections::HashSet;

use proc_macro::TokenStream;
use quote::quote;
use syn::Generics;
use syn::{parse_macro_input, DeriveInput};

use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    GenericArgument, Path, PathArguments, Result, Token, Type, TypeArray, TypeReference, TypeSlice,
};

#[derive(Default, Debug, Clone)]
struct PicusArgs {
    input: bool,
    output: bool,
    selector: bool,
}

enum Arg {
    Input,
    Output,
    Selector,
}

impl Parse for Arg {
    // parses the arguments for the picus attribute
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key: Path = input.parse()?;

        let is = |s: &str| key.is_ident(s);

        if is("input") {
            return Ok(Arg::Input);
        }
        if is("output") {
            return Ok(Arg::Output);
        }
        if is("selector") {
            return Ok(Arg::Selector);
        }

        Err(syn::Error::new_spanned(key, "unknown key in #[picus(...)]"))
    }
}

fn parse_picus_attr(attr: &syn::Attribute) -> syn::Result<Option<PicusArgs>> {
    // check that the attribute is a picus attribute
    if !attr.path.is_ident("picus") {
        return Ok(None);
    }
    // parse the attributes
    let items = attr.parse_args_with(Punctuated::<Arg, Token![,]>::parse_terminated)?;
    let mut out = PicusArgs::default();
    for it in items {
        match it {
            Arg::Input => out.input = true,
            Arg::Output => out.output = true,
            Arg::Selector => out.selector = true,
        }
    }
    Ok(Some(out))
}

// ---------- type substitution: replace *type* params with `u8` ----------
fn type_params_set(gens: &Generics) -> HashSet<syn::Ident> {
    gens.type_params().map(|tp| tp.ident.clone()).collect()
}

// column values are determined by computing the offset of the ColStruct when instantiated
// with the u8 parameter. This utility substitutes a type parameter with `u8` so we can calculate offsets.
fn ty_sub_u8(mut ty: Type, type_params: &HashSet<syn::Ident>) -> Type {
    match ty {
        Type::Path(ref mut tp) => {
            if tp.qself.is_none() && tp.path.segments.len() == 1 {
                let seg = &tp.path.segments[0];
                if type_params.contains(&seg.ident) {
                    return parse_quote!(u8);
                }
            }
            for seg in tp.path.segments.iter_mut() {
                if let PathArguments::AngleBracketed(ref mut ab) = seg.arguments {
                    for arg in ab.args.iter_mut() {
                        if let GenericArgument::Type(ref mut inner) = arg {
                            *inner = ty_sub_u8(inner.clone(), type_params);
                        }
                    }
                }
            }
            ty
        }
        Type::Reference(TypeReference { ref mut elem, .. }) => {
            **elem = ty_sub_u8((**elem).clone(), type_params);
            ty
        }
        Type::Array(TypeArray { ref mut elem, .. })
        | Type::Slice(TypeSlice { ref mut elem, .. }) => {
            **elem = ty_sub_u8((**elem).clone(), type_params);
            ty
        }
        Type::Tuple(ref mut tup) => {
            for el in tup.elems.iter_mut() {
                *el = ty_sub_u8(el.clone(), type_params);
            }
            ty
        }
        _ => ty,
    }
}

// Build Self<u8, u8, ...> actual type args; keep lifetimes/consts as-is.
fn concrete_type_args(gens: &Generics) -> proc_macro2::TokenStream {
    let args = gens.params.iter().map(|p| match p {
        syn::GenericParam::Type(_) => quote!(u8),
        syn::GenericParam::Lifetime(lt) => {
            let lt = &lt.lifetime;
            quote!(#lt)
        }
        syn::GenericParam::Const(c) => {
            let id = &c.ident;
            quote!(#id)
        }
    });
    quote!(<#(#args),*>)
}

// impl generics = lifetimes + consts only (type params fixed to u8)
fn impl_generics_without_type_params(gens: &Generics) -> proc_macro2::TokenStream {
    let lifetimes = gens.lifetimes().map(|d| d.lifetime.clone());
    let consts = gens.const_params().map(|c| {
        let id = &c.ident;
        let ty = &c.ty;
        quote!(const #id: #ty)
    });
    let mut parts: Vec<proc_macro2::TokenStream> = Vec::new();
    for lt in lifetimes {
        parts.push(quote!(#lt));
    }
    for c in consts {
        parts.push(c);
    }
    if parts.is_empty() {
        quote!()
    } else {
        quote!(< #(#parts),* >)
    }
}

pub fn picus_annotations_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();
    let gens = input.generics.clone();

    let data = match &input.data {
        syn::Data::Struct(s) => s,
        _ => {
            return syn::Error::new_spanned(&input, "PicusInfoGen only supports structs")
                .to_compile_error()
                .into()
        }
    };
    let fields = match &data.fields {
        syn::Fields::Named(f) => &f.named,
        _ => {
            return syn::Error::new_spanned(&input, "PicusInfoGen requires named fields")
                .to_compile_error()
                .into()
        }
    };

    let type_params = type_params_set(&gens);
    let impl_gens = impl_generics_without_type_params(&gens);
    let self_args = concrete_type_args(&gens);
    let self_conc = quote!(#ident #self_args);

    // Per-field code
    let mut steps = Vec::new();
    for field in fields.iter() {
        let f_ident = field.ident.as_ref().unwrap();
        let f_name = f_ident.to_string();
        // Collect flags
        let mut flags = PicusArgs::default();
        for attr in &field.attrs {
            if attr.path.is_ident("picus") {
                match parse_picus_attr(attr) {
                    Ok(Some(a)) => {
                        flags.input |= a.input;
                        flags.output |= a.output;
                        flags.selector |= a.selector;
                    }
                    Ok(None) => {}
                    Err(e) => return e.to_compile_error().into(),
                }
            }
        }

        // Field type with all *type* params → u8
        let conc_ty: Type = ty_sub_u8(field.ty.clone(), &type_params);

        // Add name to id map
        let push_name = {
            quote! {
                if width > 0 {
                    info.name_to_colrange.insert((#f_name).to_string(), (cur, cur+width));
                    for x in cur..(cur+width) {
                        info.col_to_name.insert(x, format!("{}_{}", #f_name, x));
                    }
                }
            }
        };
        let push_in = if flags.input {
            quote! { if width > 0 { info.input_ranges.push((cur, cur + width, #f_name.to_string())); } }
        } else {
            quote!()
        };

        let push_out = if flags.output {
            quote! { if width > 0 { info.output_ranges.push((cur, cur + width, #f_name.to_string())); } }
        } else {
            quote!()
        };

        let push_sel = if flags.selector {
            quote! {
                if width > 0 {
                    for i in 0..width {
                        info.selector_indices.push((cur + i, #f_name.to_string()));
                    }
                }

            }
        } else {
            quote!()
        };
        // If the field name is "is_real" then add that mark it in PicusInfo
        let push_is_real = if f_name == "is_real" {
            quote! {
                if width > 0 {
                    info.is_real_index = Some(cur);
                }
            }
        } else {
            quote!()
        };

        steps.push(quote! {{
            let width: usize = ::core::mem::size_of::<#conc_ty>();
            #push_name
            #push_in
            #push_out
            #push_sel
            #push_is_real
            cur += width;
        }});
    }

    let expanded = quote! {
        // Implement on the concrete instantiation where *type* params are `u8`
        impl #impl_gens #self_conc {
            pub fn picus_info() -> PicusInfo {
                let mut info = PicusInfo::default();
                let mut cur: usize = 0; // 1 column == 1 byte
                #(#steps)*
                info
            }
        }
    };
    expanded.into()
}
