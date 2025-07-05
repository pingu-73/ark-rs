//! Core types for Lightning swaps

use serde::{Deserialize, Serialize};

/// Configuration for ArkadeLightning
pub struct ArkadeLightningConfig {
    pub wallet: Box<dyn crate::Wallet>,
    pub swap_provider: Box<dyn crate::SwapProvider>,
    pub refund_handler: Option<Box<dyn crate::RefundHandler>>,
    pub timeout_config: Option<TimeoutConfig>,
    pub fee_config: Option<FeeConfig>,
    pub retry_config: Option<RetryConfig>,
}

/// Default timeout configuration
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    pub swap_expiry_blocks: u32,
    pub invoice_expiry_seconds: u32,
    pub claim_delay_blocks: u32,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            swap_expiry_blocks: 144,
            invoice_expiry_seconds: 3600,
            claim_delay_blocks: 10,
        }
    }
}

/// Fee configuration for swaps
#[derive(Debug, Clone)]
pub struct FeeConfig {
    pub max_miner_fee_sats: u64,
    pub max_swap_fee_sats: u64,
}

impl Default for FeeConfig {
    fn default() -> Self {
        Self {
            max_miner_fee_sats: 5000,
            max_swap_fee_sats: 1000,
        }
    }
}

/// Retry configuration for operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            delay_ms: 2000,
        }
    }
}

/// VTXO representation for lightning swaps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
    pub tx: TransactionData,
}

/// Transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub hex: String,
}

/// Arguments for sending lightning payments
#[derive(Debug, Clone)]
pub struct SendPaymentArgs {
    pub invoice: String,
    pub source_vtxos: Option<Vec<Vtxo>>,
}

/// Result of a lightning payment
#[derive(Debug, Clone)]
pub struct PaymentResult {
    pub preimage: String,
    pub txid: String,
}

/// Result of creating a lightning invoice
#[derive(Debug, Clone)]
pub struct CreateInvoiceResult {
    pub invoice: String,
    pub payment_hash: String,
}

/// Arguments for creating lightning invoices
#[derive(Debug, Clone)]
pub struct CreateInvoiceArgs {
    pub amount_sats: u64,
    pub description: Option<String>,
}

/// Decoded lightning invoice
#[derive(Debug, Clone)]
pub struct DecodedInvoice {
    pub amount_sats: u64,
    pub description: String,
    pub destination: String,
    pub payment_hash: String,
    pub expiry: u32,
}

/// BOLT12 offer for Lightning payments
#[derive(Debug, Clone)]
pub struct Bolt12Offer {
    pub offer_id: String,
    pub amount_sats: Option<u64>,
    pub description: String,
    pub node_id: String,
    pub expiry: Option<u32>,
    pub paths: Vec<String>,
}

/// Decoded BOLT12 invoice request
#[derive(Debug, Clone)]
pub struct DecodedBolt12InvoiceRequest {
    pub offer_id: String,
    pub amount_sats: u64,
    pub payer_key: String,
    pub payer_note: Option<String>,
}

/// BOLT12 invoice
#[derive(Debug, Clone)]
pub struct Bolt12Invoice {
    pub invoice_request_id: String,
    pub amount_sats: u64,
    pub description: String,
    pub payment_hash: String,
    pub payment_paths: Vec<String>,
    pub expiry: u32,
}

/// Arguments for creating BOLT12 offers
#[derive(Debug, Clone)]
pub struct CreateOfferArgs {
    pub amount_sats: Option<u64>, // None for flexible amounts
    pub description: String,
    pub expiry_seconds: Option<u32>,
    pub quantity_max: Option<u64>,
}

/// Arguments for paying a BOLT12 offer
#[derive(Debug, Clone)]
pub struct PayOfferArgs {
    pub offer: String, // The BOLT12 offer string
    pub amount_sats: Option<u64>, // Required if offer doesn't specify amount
    pub payer_note: Option<String>,
    pub source_vtxos: Option<Vec<Vtxo>>,
}

/// Incoming payment subscription
pub struct IncomingPaymentSubscription {
    // Implementation will vary based on event system used
    _phantom: std::marker::PhantomData<()>,
}

impl IncomingPaymentSubscription {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn on<F>(&self, _event: &str, _listener: F) -> &Self
    where
        F: Fn() + Send + 'static,
    {
        // TODO: Implement event subscription
        self
    }

    pub fn unsubscribe(&self) {
        // TODO: Implement unsubscribe
    }
}

/// Swap data for tracking swap operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapData {
    pub id: String,
    pub invoice: String,
    pub refund_address: Option<String>,
    pub expected_amount: u64,
    pub timeout_block_height: u32,
    pub preimage: Option<String>,
    pub claim_txid: Option<String>,
    pub refund_txid: Option<String>,
    pub status: SwapStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Status of a swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwapStatus {
    Created,
    InvoiceSet,
    TransactionMempool,
    TransactionConfirmed,
    TransactionClaimed,
    SwapExpired,
    InvoiceExpired,
    TransactionRefunded,
    TransactionFailed,
}

/// Submarine swap response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmarineSwapResponse {
    pub id: String,
    pub address: Option<String>,
    pub expected_amount: Option<u64>,
    pub timeout_block_height: Option<u32>,
    pub swap_tree: Option<SwapTree>,
    pub claim_public_key: Option<String>,
    pub refund_public_key: Option<String>,
    pub redeem_script: Option<String>,
}

/// Swap tree structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapTree {
    pub claim_leaf: Option<SwapTreeLeaf>,
    pub refund_leaf: Option<SwapTreeLeaf>,
}

/// Swap tree leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapTreeLeaf {
    pub output: String,
    pub version: u8,
}

/// Swap status response (Boltz-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoltzSwapStatusResponse {
    pub status: String,
    pub transaction: Option<SwapTransaction>,
}

/// Transaction in swap status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapTransaction {
    pub id: Option<String>,
    pub hex: Option<String>,
    pub preimage: Option<String>,
}

/// Network type for Bitcoin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

/// Broadcast transaction result
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    pub txid: String,
}
