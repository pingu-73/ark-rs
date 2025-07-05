//! ArkadeLightning implementation for lightning swaps

use crate::lightning::utils::get_bitcoin_network;
use crate::lightning::utils::poll;
use crate::lightning::ArkadeLightningConfig;
use crate::lightning::BoltzSwapStatusResponse;
use crate::lightning::CreateInvoiceArgs;
use crate::lightning::CreateInvoiceResult;
use crate::lightning::DecodedInvoice;
use crate::lightning::FeeConfig;
use crate::lightning::IncomingPaymentSubscription;
use crate::lightning::InsufficientFundsError;
use crate::lightning::LightningSwapError;
use crate::lightning::LightningSwapResult;
use crate::lightning::PaymentResult;
use crate::lightning::RefundHandler;
use crate::lightning::RetryConfig;
use crate::lightning::SendPaymentArgs;
use crate::lightning::SwapData;
use crate::lightning::SwapError;
use crate::lightning::SwapProvider;
use crate::lightning::TimeoutConfig;
use crate::lightning::Wallet;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use std::sync::Arc;

/// Default configuration values
const DEFAULT_TIMEOUT_CONFIG: TimeoutConfig = TimeoutConfig {
    swap_expiry_blocks: 144,
    invoice_expiry_seconds: 3600,
    claim_delay_blocks: 10,
};

const DEFAULT_FEE_CONFIG: FeeConfig = FeeConfig {
    max_miner_fee_sats: 5000,
    max_swap_fee_sats: 1000,
};

const DEFAULT_RETRY_CONFIG: RetryConfig = RetryConfig {
    max_attempts: 5,
    delay_ms: 2000,
};

/// Default refund handler that does nothing
#[derive(Debug)]
pub struct DefaultRefundHandler;

#[async_trait]
impl RefundHandler for DefaultRefundHandler {
    async fn on_refund_needed(&self, _swap_data: SwapData) -> LightningSwapResult<()> {
        // Default implementation does nothing
        Ok(())
    }
}

/// ArkadeLightning implementation for lightning swaps
pub struct ArkadeLightning {
    wallet: Arc<dyn Wallet>,
    swap_provider: Arc<dyn SwapProvider>,
    refund_handler: Arc<dyn RefundHandler>,
    timeout_config: TimeoutConfig,
    fee_config: FeeConfig,
    retry_config: RetryConfig,
}

impl ArkadeLightning {
    /// Create a new ArkadeLightning instance
    pub fn new(config: ArkadeLightningConfig) -> LightningSwapResult<Self> {
        let wallet = Arc::from(config.wallet);
        let swap_provider = Arc::from(config.swap_provider);
        let refund_handler = Arc::from(
            config
                .refund_handler
                .unwrap_or_else(|| Box::new(DefaultRefundHandler)),
        );
        let timeout_config = config.timeout_config.unwrap_or(DEFAULT_TIMEOUT_CONFIG);
        let fee_config = config.fee_config.unwrap_or(DEFAULT_FEE_CONFIG);
        let retry_config = config.retry_config.unwrap_or(DEFAULT_RETRY_CONFIG);

        Ok(Self {
            wallet,
            swap_provider,
            refund_handler,
            timeout_config,
            fee_config,
            retry_config,
        })
    }

    /// Create a lightning invoice for receiving payments
    pub async fn create_lightning_invoice(
        &self,
        args: CreateInvoiceArgs,
    ) -> LightningSwapResult<CreateInvoiceResult> {
        tracing::info!("Creating lightning invoice for {} sats", args.amount_sats);

        // For now, return an error as reverse submarine swaps are not implemented
        Err(LightningSwapError::ConfigError(
            "Receiving via reverse submarine swap is not implemented in this version".to_string(),
        ))
    }

    /// Monitor incoming payments
    pub fn monitor_incoming_payment(&self) -> IncomingPaymentSubscription {
        // Return a basic subscription - implementation depends on event system
        IncomingPaymentSubscription::new()
    }

    /// Decode a BOLT11 invoice
    pub async fn decode_invoice(&self, invoice: &str) -> LightningSwapResult<DecodedInvoice> {
        tracing::warn!("Invoice decoding is mocked");

        // Mock implementation - in a real implementation, use a proper BOLT11 decoder
        let amount_match = invoice
            .matches("lnbc")
            .chain(invoice.matches("lntb"))
            .next();
        let amount = if amount_match.is_some() {
            // Try to extract amount from invoice - this is a very basic extraction
            invoice
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .unwrap_or(0)
        } else {
            0
        };

        Ok(DecodedInvoice {
            amount_sats: amount,
            description: "Mocked description".to_string(),
            destination: "02mockdestinationpubkey".to_string(),
            payment_hash: "mockpaymenthash".to_string(),
            expiry: 3600,
        })
    }

    /// Send a lightning payment via submarine swap
    pub async fn send_lightning_payment(
        &self,
        args: SendPaymentArgs,
    ) -> LightningSwapResult<PaymentResult> {
        tracing::info!("Sending lightning payment for invoice: {}", args.invoice);

        // Get refund public key from wallet
        let refund_pubkey = self.wallet.get_public_key().await?;

        // Create submarine swap
        let swap = self
            .swap_provider
            .create_submarine_swap(&args.invoice, &refund_pubkey)
            .await?;

        // Validate swap response
        let swap_address = swap.address.ok_or_else(|| {
            LightningSwapError::InvalidSwapResponse("No swap address provided".to_string())
        })?;

        let expected_amount = swap.expected_amount.ok_or_else(|| {
            LightningSwapError::InvalidSwapResponse("No expected amount provided".to_string())
        })?;

        // Get UTXOs for the swap
        let utxos = if let Some(source_vtxos) = args.source_vtxos {
            source_vtxos
        } else {
            self.wallet.get_vtxos().await?
        };

        // Simple coin selection - use the first UTXO that has enough funds
        let selected_utxo = utxos
            .iter()
            .find(|utxo| utxo.sats >= expected_amount)
            .ok_or_else(|| InsufficientFundsError::new("Not enough funds for the swap"))?;

        // Check if fees are within acceptable limits
        let estimated_fee = self.fee_config.max_miner_fee_sats; // Simple estimation
        if estimated_fee > self.fee_config.max_swap_fee_sats {
            return Err(LightningSwapError::SwapError {
                message: "Estimated fees exceed maximum allowed".to_string(),
                is_refundable: false,
                swap_data: None,
            });
        }

        // Create transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Add input
        let txid_bytes = hex::decode(&selected_utxo.txid)
            .map_err(|_| LightningSwapError::InvalidSwapResponse("Invalid TXID".to_string()))?;
        let txid = bitcoin::Txid::from_slice(&txid_bytes).map_err(|_| {
            LightningSwapError::InvalidSwapResponse("Invalid TXID format".to_string())
        })?;

        tx.input.push(bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(txid, selected_utxo.vout),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        });

        // Add output
        let network = get_bitcoin_network(self.swap_provider.get_network());
        let address = swap_address
            .parse::<bitcoin::Address<_>>()
            .map_err(|_| {
                LightningSwapError::InvalidSwapResponse("Invalid swap address".to_string())
            })?
            .require_network(network)
            .map_err(|_| {
                LightningSwapError::InvalidSwapResponse("Address network mismatch".to_string())
            })?;

        tx.output.push(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(expected_amount),
            script_pubkey: address.script_pubkey(),
        });

        // Sign transaction
        let signed_tx = self.wallet.sign_tx(tx).await?;

        // Broadcast transaction
        let broadcast_result = self.wallet.broadcast_tx(signed_tx).await?;

        // Wait for swap settlement
        let final_status = self.wait_for_swap_settlement(&swap.id).await?;

        // Check if swap has expired based on timeout config
        if let Some(timeout_height) = swap.timeout_block_height {
            // In a real implementation, you would check the current block height
            // For now, we just log the timeout configuration
            tracing::debug!(
                "Swap timeout block height: {}, claim delay: {}",
                timeout_height,
                self.timeout_config.claim_delay_blocks
            );
        }

        if let Some(transaction) = final_status.transaction {
            if let Some(preimage) = transaction.preimage {
                return Ok(PaymentResult {
                    preimage,
                    txid: broadcast_result.txid,
                });
            }
        }

        // If we get here, the swap didn't settle properly
        let swap_data = SwapData {
            id: swap.id,
            invoice: args.invoice,
            refund_address: None,
            expected_amount,
            timeout_block_height: swap.timeout_block_height.unwrap_or(0),
            preimage: None,
            claim_txid: None,
            refund_txid: None,
            status: crate::lightning::SwapStatus::TransactionFailed,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Err(
            SwapError::with_refund_data("Swap settlement did not return a preimage", swap_data)
                .into(),
        )
    }

    /// Wait for swap settlement
    async fn wait_for_swap_settlement(
        &self,
        swap_id: &str,
    ) -> LightningSwapResult<BoltzSwapStatusResponse> {
        let swap_provider = Arc::clone(&self.swap_provider);
        let swap_id_string = swap_id.to_string();

        let result = poll(
            move || {
                let provider = Arc::clone(&swap_provider);
                let id = swap_id_string.clone();
                Box::pin(async move { provider.get_swap_status(&id).await })
            },
            |status| status.status == "transaction.claimed",
            self.retry_config.delay_ms,
            self.retry_config.max_attempts,
        )
        .await;

        match result {
            Ok(status) => Ok(status),
            Err(e) => {
                // Create swap data for refund handler
                let swap_data = SwapData {
                    id: swap_id.to_string(),
                    invoice: "".to_string(), // We don't have the invoice here
                    refund_address: None,
                    expected_amount: 0,
                    timeout_block_height: 0,
                    preimage: None,
                    claim_txid: None,
                    refund_txid: None,
                    status: crate::lightning::SwapStatus::SwapExpired,
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    updated_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                // Notify refund handler
                let _ = self
                    .refund_handler
                    .on_refund_needed(swap_data.clone())
                    .await;

                Err(SwapError::with_refund_data(
                    format!("Swap settlement failed: {}", e),
                    swap_data,
                )
                .into())
            }
        }
    }

    /// Get pending swaps
    pub async fn get_pending_swaps(&self) -> LightningSwapResult<Vec<SwapData>> {
        tracing::warn!("get_pending_swaps is not implemented");
        Ok(vec![])
    }

    /// Claim a refund for a failed swap
    pub async fn claim_refund(&self, swap_data: SwapData) -> LightningSwapResult<String> {
        tracing::warn!(
            "Refund claiming not fully implemented for swap: {}",
            swap_data.id
        );
        Err(LightningSwapError::ConfigError(
            "Not implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lightning::BitcoinNetwork;
    use crate::lightning::BroadcastResult;
    use crate::lightning::SubmarineSwapResponse;
    use crate::lightning::TransactionData;
    use crate::lightning::Vtxo;
    use bitcoin::Transaction;

    // Mock implementations for testing
    struct MockWallet;

    #[async_trait]
    impl Wallet for MockWallet {
        async fn get_public_key(&self) -> LightningSwapResult<String> {
            Ok("mock_pubkey".to_string())
        }

        async fn get_vtxos(&self) -> LightningSwapResult<Vec<Vtxo>> {
            Ok(vec![Vtxo {
                txid: "mock_txid".to_string(),
                vout: 0,
                sats: 100000,
                tx: TransactionData {
                    hex: "mock_hex".to_string(),
                },
            }])
        }

        async fn sign_tx(&self, tx: Transaction) -> LightningSwapResult<Transaction> {
            Ok(tx)
        }

        async fn broadcast_tx(&self, _tx: Transaction) -> LightningSwapResult<BroadcastResult> {
            Ok(BroadcastResult {
                txid: "mock_broadcast_txid".to_string(),
            })
        }
    }

    struct MockSwapProvider;

    #[async_trait]
    impl SwapProvider for MockSwapProvider {
        fn get_network(&self) -> BitcoinNetwork {
            BitcoinNetwork::Regtest
        }

        async fn create_submarine_swap(
            &self,
            _invoice: &str,
            _refund_pubkey: &str,
        ) -> LightningSwapResult<SubmarineSwapResponse> {
            Ok(SubmarineSwapResponse {
                id: "mock_swap_id".to_string(),
                address: Some("bcrt1qmock".to_string()),
                expected_amount: Some(50000),
                timeout_block_height: Some(144),
                swap_tree: None,
                claim_public_key: None,
                refund_public_key: None,
                redeem_script: None,
            })
        }

        async fn create_reverse_submarine_swap(
            &self,
            _args: &CreateInvoiceArgs,
            _claim_pubkey: &str,
        ) -> LightningSwapResult<SubmarineSwapResponse> {
            Ok(SubmarineSwapResponse {
                id: "mock_reverse_swap_id".to_string(),
                address: Some("bcrt1qmock".to_string()),
                expected_amount: Some(50000),
                timeout_block_height: Some(144),
                swap_tree: None,
                claim_public_key: None,
                refund_public_key: None,
                redeem_script: None,
            })
        }

        async fn get_swap_status(
            &self,
            _swap_id: &str,
        ) -> LightningSwapResult<BoltzSwapStatusResponse> {
            Ok(BoltzSwapStatusResponse {
                status: "transaction.claimed".to_string(),
                transaction: Some(crate::lightning::SwapTransaction {
                    id: Some("mock_tx_id".to_string()),
                    hex: Some("mock_hex".to_string()),
                    preimage: Some("mock_preimage".to_string()),
                }),
            })
        }

        async fn get_pending_swaps(&self) -> LightningSwapResult<Vec<SwapData>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_arkade_lightning_creation() {
        let config = ArkadeLightningConfig {
            wallet: Box::new(MockWallet),
            swap_provider: Box::new(MockSwapProvider),
            refund_handler: None,
            timeout_config: None,
            fee_config: None,
            retry_config: None,
        };

        let arkade_lightning = ArkadeLightning::new(config).unwrap();
        assert!(arkade_lightning.wallet.get_public_key().await.is_ok());
    }

    #[tokio::test]
    async fn test_decode_invoice() {
        let config = ArkadeLightningConfig {
            wallet: Box::new(MockWallet),
            swap_provider: Box::new(MockSwapProvider),
            refund_handler: None,
            timeout_config: None,
            fee_config: None,
            retry_config: None,
        };

        let arkade_lightning = ArkadeLightning::new(config).unwrap();
        let result = arkade_lightning.decode_invoice("lnbc1000").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_lightning_invoice_not_implemented() {
        let config = ArkadeLightningConfig {
            wallet: Box::new(MockWallet),
            swap_provider: Box::new(MockSwapProvider),
            refund_handler: None,
            timeout_config: None,
            fee_config: None,
            retry_config: None,
        };

        let arkade_lightning = ArkadeLightning::new(config).unwrap();
        let result = arkade_lightning
            .create_lightning_invoice(CreateInvoiceArgs {
                amount_sats: 1000,
                description: None,
            })
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LightningSwapError::ConfigError(_)
        ));
    }
}
