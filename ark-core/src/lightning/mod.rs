//! Lightning swaps integration for Ark protocol
//!
//! This module provides traits and types for integrating lightning network payments
//! with the Ark protocol through submarine swaps.

#[cfg(feature = "lightning")]
pub mod errors;
#[cfg(feature = "lightning")]
pub mod lightning_swaps;
#[cfg(feature = "lightning")]
pub mod traits;
#[cfg(feature = "lightning")]
pub mod types;
#[cfg(feature = "lightning")]
pub mod utils;

#[cfg(feature = "lightning")]
pub use errors::*;
#[cfg(feature = "lightning")]
pub use lightning_swaps::*;
#[cfg(feature = "lightning")]
pub use traits::*;
#[cfg(feature = "lightning")]
pub use types::*;
