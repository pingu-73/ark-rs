//! Boltz swap provider implementation
//!
//! This module provides a concrete implementation of the SwapProvider trait
//! using the Boltz Lightning Network swap service via HTTP API.

use crate::BitcoinNetwork;
use crate::BoltzSwapStatusResponse;
use crate::CreateInvoiceArgs;
use crate::LightningSwapError;
use crate::LightningSwapResult;
use crate::SubmarineSwapResponse;
use crate::SwapData;
use crate::SwapProvider;
use crate::SwapTransaction;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

/// Boltz API request for creating a submarine swap
#[derive(Debug, Clone, Serialize)]
struct CreateSubmarineSwapRequest {
    pub r#type: String,
    pub pair_id: String,
    pub order_side: String,
    pub refund_public_key: String,
    pub invoice: String,
}

/// Boltz API request for creating a reverse submarine swap
#[derive(Debug, Clone, Serialize)]
struct CreateReverseSwapRequest {
    pub r#type: String,
    pub pair_id: String,
    pub order_side: String,
    pub claim_public_key: String,
    pub invoice_amount: u64,
    pub preimage_hash: Option<String>,
    pub description: Option<String>,
}

/// Boltz API response for creating a swap
#[derive(Debug, Clone, Deserialize)]
struct CreateSwapResponse {
    pub id: String,
    pub address: Option<String>,
    pub expected_amount: Option<u64>,
    pub timeout_block_height: Option<u32>,
    pub redeem_script: Option<String>,
    pub claim_public_key: Option<String>,
    pub refund_public_key: Option<String>,
    pub invoice: Option<String>,
    pub onchain_amount: Option<u64>,
}

/// Boltz API response for swap status
#[derive(Debug, Clone, Deserialize)]
struct SwapStatusResponse {
    pub status: String,
    pub transaction: Option<SwapStatusTransaction>,
}

/// Transaction in swap status response
#[derive(Debug, Clone, Deserialize)]
struct SwapStatusTransaction {
    pub id: Option<String>,
    pub hex: Option<String>,
}

/// Boltz swap provider configuration
#[derive(Debug, Clone)]
pub struct BoltzConfig {
    /// Boltz API base URL
    pub api_url: String,
    /// Bitcoin network to use
    pub network: BitcoinNetwork,
    /// Optional API key for authenticated requests
    pub api_key: Option<String>,
}

impl Default for BoltzConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.boltz.exchange".to_string(),
            network: BitcoinNetwork::Mainnet,
            api_key: None,
        }
    }
}

/// Boltz swap provider implementation
pub struct BoltzSwapProvider {
    client: Client,
    config: BoltzConfig,
}

impl BoltzSwapProvider {
    /// Create a new Boltz swap provider
    pub fn new(config: BoltzConfig) -> LightningSwapResult<Self> {
        let client = Client::new();

        Ok(Self { client, config })
    }

    /// Create a new Boltz swap provider with default configuration
    pub fn new_mainnet() -> LightningSwapResult<Self> {
        Self::new(BoltzConfig::default())
    }

    /// Create a new Boltz swap provider for testnet
    pub fn new_testnet() -> LightningSwapResult<Self> {
        let config = BoltzConfig {
            api_url: "https://testnet.boltz.exchange/api".to_string(),
            network: BitcoinNetwork::Testnet,
            api_key: None,
        };
        Self::new(config)
    }

    /// Create a new Boltz swap provider for regtest/local development
    pub fn new_regtest(api_url: String) -> LightningSwapResult<Self> {
        let config = BoltzConfig {
            api_url,
            network: BitcoinNetwork::Regtest,
            api_key: None,
        };
        Self::new(config)
    }
}

/// Convert CreateSwapResponse to SubmarineSwapResponse
impl From<CreateSwapResponse> for SubmarineSwapResponse {
    fn from(response: CreateSwapResponse) -> Self {
        SubmarineSwapResponse {
            id: response.id,
            address: response.address,
            expected_amount: response.expected_amount,
            timeout_block_height: response.timeout_block_height,
            swap_tree: None, // Boltz API doesn't return swap tree structure
            claim_public_key: response.claim_public_key,
            refund_public_key: response.refund_public_key,
            redeem_script: response.redeem_script,
        }
    }
}

/// Convert SwapStatusResponse to BoltzSwapStatusResponse
impl From<SwapStatusResponse> for BoltzSwapStatusResponse {
    fn from(response: SwapStatusResponse) -> Self {
        BoltzSwapStatusResponse {
            status: response.status,
            transaction: response.transaction.map(|tx| SwapTransaction {
                id: tx.id,
                hex: tx.hex,
                preimage: None, // Preimage not included in status response
            }),
        }
    }
}

/// Convert SwapStatusTransaction to SwapTransaction
impl From<SwapStatusTransaction> for SwapTransaction {
    fn from(tx: SwapStatusTransaction) -> Self {
        SwapTransaction {
            id: tx.id,
            hex: tx.hex,
            preimage: None, // Preimage not included in status response
        }
    }
}

#[async_trait]
impl SwapProvider for BoltzSwapProvider {
    fn get_network(&self) -> BitcoinNetwork {
        self.config.network
    }

    async fn create_submarine_swap(
        &self,
        invoice: &str,
        refund_pubkey: &str,
    ) -> LightningSwapResult<SubmarineSwapResponse> {
        tracing::debug!("Creating submarine swap for invoice: {}", invoice);

        let request = CreateSubmarineSwapRequest {
            r#type: "submarine".to_string(),
            pair_id: "BTC/BTC".to_string(),
            order_side: "sell".to_string(),
            refund_public_key: refund_pubkey.to_string(),
            invoice: invoice.to_string(),
        };

        let url = format!("{}/createswap", self.config.api_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                LightningSwapError::NetworkError(format!("Failed to create submarine swap: {}", e))
            })?;

        let response_text = response.text().await.map_err(|e| {
            LightningSwapError::NetworkError(format!("Failed to read response: {}", e))
        })?;

        let swap_response: CreateSwapResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                LightningSwapError::InvalidSwapResponse(format!(
                    "Failed to parse swap response: {}",
                    e
                ))
            })?;

        Ok(swap_response.into())
    }

    async fn create_reverse_submarine_swap(
        &self,
        args: &CreateInvoiceArgs,
        claim_pubkey: &str,
    ) -> LightningSwapResult<SubmarineSwapResponse> {
        tracing::debug!(
            "Creating reverse submarine swap for {} sats",
            args.amount_sats
        );

        let request = CreateReverseSwapRequest {
            r#type: "reversesubmarine".to_string(),
            pair_id: "BTC/BTC".to_string(),
            order_side: "buy".to_string(),
            claim_public_key: claim_pubkey.to_string(),
            invoice_amount: args.amount_sats,
            preimage_hash: None, // Boltz will generate
            description: args.description.clone(),
        };

        let url = format!("{}/createswap", self.config.api_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                LightningSwapError::NetworkError(format!(
                    "Failed to create reverse submarine swap: {}",
                    e
                ))
            })?;

        let response_text = response.text().await.map_err(|e| {
            LightningSwapError::NetworkError(format!("Failed to read response: {}", e))
        })?;

        let swap_response: CreateSwapResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                LightningSwapError::InvalidSwapResponse(format!(
                    "Failed to parse reverse swap response: {}",
                    e
                ))
            })?;

        Ok(swap_response.into())
    }

    async fn get_swap_status(&self, swap_id: &str) -> LightningSwapResult<BoltzSwapStatusResponse> {
        tracing::debug!("Getting swap status for: {}", swap_id);

        let url = format!("{}/swapstatus", self.config.api_url);
        let mut params = HashMap::new();
        params.insert("id", swap_id);

        let response = self
            .client
            .post(&url)
            .json(&params)
            .send()
            .await
            .map_err(|e| {
                LightningSwapError::NetworkError(format!("Failed to get swap status: {}", e))
            })?;

        let response_text = response.text().await.map_err(|e| {
            LightningSwapError::NetworkError(format!("Failed to read response: {}", e))
        })?;

        let status_response: SwapStatusResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                LightningSwapError::InvalidSwapResponse(format!(
                    "Failed to parse swap status response: {}",
                    e
                ))
            })?;

        Ok(status_response.into())
    }

    async fn get_pending_swaps(&self) -> LightningSwapResult<Vec<SwapData>> {
        // Boltz doesn't provide a general "get all pending swaps" endpoint
        // This would typically be implemented by tracking swaps locally
        tracing::warn!("get_pending_swaps not implemented for Boltz provider");
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boltz_config_default() {
        let config = BoltzConfig::default();
        assert_eq!(config.api_url, "https://api.boltz.exchange");
        assert_eq!(config.network, BitcoinNetwork::Mainnet);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_boltz_provider_creation() {
        let config = BoltzConfig::default();
        let result = BoltzSwapProvider::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_boltz_testnet_creation() {
        let result = BoltzSwapProvider::new_testnet();
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.get_network(), BitcoinNetwork::Testnet);
    }

    #[test]
    fn test_boltz_regtest_creation() {
        let api_url = "http://localhost:9000/api".to_string();
        let result = BoltzSwapProvider::new_regtest(api_url.clone());
        assert!(result.is_ok());

        let provider = result.unwrap();
        assert_eq!(provider.get_network(), BitcoinNetwork::Regtest);
        assert_eq!(provider.config.api_url, api_url);
    }
}
