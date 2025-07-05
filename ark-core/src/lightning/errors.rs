//! Error types for Lightning swaps

use std::fmt;

/// Errors that can occur during lightning swap operations
#[derive(Debug, Clone)]
pub enum LightningSwapError {
    /// Insufficient funds for the swap
    InsufficientFunds(String),
    /// Generic swap error with optional refund data
    SwapError {
        message: String,
        is_refundable: bool,
        swap_data: Option<crate::lightning::SwapData>,
    },
    /// Invalid swap response
    InvalidSwapResponse(String),
    /// Swap timeout
    SwapTimeout(String),
    /// Invoice decoding error
    InvoiceDecodeError(String),
    /// Wallet operation error
    WalletError(String),
    /// Network error
    NetworkError(String),
    /// Configuration error
    ConfigError(String),
}

impl fmt::Display for LightningSwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LightningSwapError::InsufficientFunds(msg) => write!(f, "Insufficient funds: {}", msg),
            LightningSwapError::SwapError { message, .. } => write!(f, "Swap error: {}", message),
            LightningSwapError::InvalidSwapResponse(msg) => {
                write!(f, "Invalid swap response: {}", msg)
            }
            LightningSwapError::SwapTimeout(msg) => write!(f, "Swap timeout: {}", msg),
            LightningSwapError::InvoiceDecodeError(msg) => {
                write!(f, "Invoice decode error: {}", msg)
            }
            LightningSwapError::WalletError(msg) => write!(f, "Wallet error: {}", msg),
            LightningSwapError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            LightningSwapError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for LightningSwapError {}

/// Convenience type alias for lightning swap results
pub type LightningSwapResult<T> = Result<T, LightningSwapError>;

/// Error for insufficient funds
#[derive(Debug, Clone)]
pub struct InsufficientFundsError {
    pub message: String,
}

impl InsufficientFundsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for InsufficientFundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Insufficient funds: {}", self.message)
    }
}

impl std::error::Error for InsufficientFundsError {}

/// Error for swap operations
#[derive(Debug, Clone)]
pub struct SwapError {
    pub message: String,
    pub is_refundable: bool,
    pub swap_data: Option<crate::lightning::SwapData>,
}

impl SwapError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_refundable: false,
            swap_data: None,
        }
    }

    pub fn with_refund_data(
        message: impl Into<String>,
        swap_data: crate::lightning::SwapData,
    ) -> Self {
        Self {
            message: message.into(),
            is_refundable: true,
            swap_data: Some(swap_data),
        }
    }
}

impl fmt::Display for SwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Swap error: {}", self.message)
    }
}

impl std::error::Error for SwapError {}

impl From<InsufficientFundsError> for LightningSwapError {
    fn from(err: InsufficientFundsError) -> Self {
        LightningSwapError::InsufficientFunds(err.message)
    }
}

impl From<SwapError> for LightningSwapError {
    fn from(err: SwapError) -> Self {
        LightningSwapError::SwapError {
            message: err.message,
            is_refundable: err.is_refundable,
            swap_data: err.swap_data,
        }
    }
}
