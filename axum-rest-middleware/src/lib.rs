//! axum-rest-middleware

#![forbid(unsafe_code)]
#![deny(unreachable_pub, private_in_public)]
#![allow(unused_imports)]
#![warn(
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    //missing_docs
)]

mod error;

pub mod middleware;

/// Alias for a type-erased error type.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
