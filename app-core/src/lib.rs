//! app-core

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

pub mod error;
pub use self::error::Error;
