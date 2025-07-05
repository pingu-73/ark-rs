//! Traits for Lightning swaps integration

use async_trait::async_trait;
use bitcoin::Transaction;
use crate::{
    BroadcastResult, CreateInvoiceArgs, DecodedInvoice, 
    LightningSwapResult, SubmarineSwapResponse, 
    SwapData, BoltzSwapStatusResponse, Vtxo, BitcoinNetwork
};

/// Trait for wallet operations required by lightning swaps
#[async_trait]
pub trait Wallet: Send + Sync {
    /// Get the public key for refund transactions
    async fn get_public_key(&self) -> LightningSwapResult<String>;
    
    /// Get available VTXOs for spending
    async fn get_vtxos(&self) -> LightningSwapResult<Vec<Vtxo>>;
    
    /// Sign a transaction
    async fn sign_tx(&self, tx: Transaction) -> LightningSwapResult<Transaction>;
    
    /// Broadcast a transaction
    async fn broadcast_tx(&self, tx: Transaction) -> LightningSwapResult<BroadcastResult>;
}

/// Trait for swap provider operations
#[async_trait]
pub trait SwapProvider: Send + Sync {
    /// Get the network this provider operates on
    fn get_network(&self) -> BitcoinNetwork;
    
    /// Create a submarine swap for sending lightning payments
    async fn create_submarine_swap(
        &self, 
        invoice: &str, 
        refund_pubkey: &str
    ) -> LightningSwapResult<SubmarineSwapResponse>;
    
    /// Create a reverse submarine swap for receiving lightning payments
    async fn create_reverse_submarine_swap(
        &self, 
        args: &CreateInvoiceArgs,
        claim_pubkey: &str
    ) -> LightningSwapResult<SubmarineSwapResponse>;
    
    /// Get the status of a swap
    async fn get_swap_status(&self, swap_id: &str) -> LightningSwapResult<BoltzSwapStatusResponse>;
    
    /// Get pending swaps
    async fn get_pending_swaps(&self) -> LightningSwapResult<Vec<SwapData>>;
}

/// Trait for handling refund operations
#[async_trait]
pub trait RefundHandler: Send + Sync {
    /// Called when a refund is needed
    async fn on_refund_needed(&self, swap_data: SwapData) -> LightningSwapResult<()>;
}

/// Trait for decoding lightning invoices
#[async_trait]
pub trait InvoiceDecoder: Send + Sync {
    /// Decode a BOLT11 invoice
    async fn decode_invoice(&self, invoice: &str) -> LightningSwapResult<DecodedInvoice>;
}
