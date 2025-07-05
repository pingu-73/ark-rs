//! Lightning Network integration for Ark protocol through submarine swaps
//!
//! This crate provides lightning network integration for the Ark protocol through submarine swaps,
//! enabling seamless Lightning Network payments using VTXOs.

pub mod types;
pub mod traits;
pub mod lightning_swaps;
pub mod utils;
pub mod errors;

#[cfg(feature = "boltz")]
pub mod boltz;

pub use types::*;
pub use traits::*;
pub use lightning_swaps::*;
pub use errors::*;
