use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Derives a Debug implementation that elides secret values.
///
/// This macro generates a Debug implementation that outputs `<elided secret for TypeName>`
/// instead of the actual field values, preventing accidental leakage of sensitive data
/// in logs, error messages, or debug output.
///
/// # Example
///
/// ```ignore
/// #[derive(SilentDebug)]
/// pub struct SecretKey {
///     inner: [u8; 32],
/// }
///
/// let sk = SecretKey { inner: [0u8; 32] };
/// assert_eq!(format!("{:?}", sk), "<elided secret for SecretKey>");
/// ```
#[proc_macro_derive(SilentDebug)]
pub fn silent_debug(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    let expanded = quote! {
        // In order to ensure that secrets are never leaked, Debug is elided
        impl #impl_generics ::core::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derives a Display implementation that elides secret values.
///
/// This macro generates a Display implementation that outputs `<elided secret for TypeName>`
/// instead of the actual field values. While implementing Display for secret keys is
/// generally discouraged (as Display implies "user-facing output"), this safe implementation
/// prevents compilation errors in generic contexts while still protecting sensitive data.
///
/// # Example
///
/// ```ignore
/// #[derive(SilentDisplay)]
/// pub struct SecretKey {
///     inner: [u8; 32],
/// }
///
/// let sk = SecretKey { inner: [0u8; 32] };
/// assert_eq!(format!("{}", sk), "<elided secret for SecretKey>");
/// ```
#[proc_macro_derive(SilentDisplay)]
pub fn silent_display(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    let expanded = quote! {
        // In order to ensure that secrets are never leaked, Display is elided
        impl #impl_generics ::core::fmt::Display for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}
