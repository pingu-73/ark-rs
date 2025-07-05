//! Utility functions for Lightning swaps

use crate::lightning::BitcoinNetwork;
use crate::lightning::LightningSwapError;
use crate::lightning::LightningSwapResult;
use bitcoin::Transaction;
use std::future::Future;
use std::pin::Pin;

/// Get Bitcoin network from BitcoinNetwork enum
pub fn get_bitcoin_network(network: BitcoinNetwork) -> bitcoin::Network {
    match network {
        BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
        BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
        BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
        BitcoinNetwork::Signet => bitcoin::Network::Signet,
    }
}

/// Poll a function until a condition is met or timeout
pub async fn poll<F, T, P>(
    mut func: F,
    mut predicate: P,
    delay_ms: u64,
    max_attempts: u32,
) -> LightningSwapResult<T>
where
    F: FnMut() -> Pin<Box<dyn Future<Output = LightningSwapResult<T>> + Send>>,
    P: FnMut(&T) -> bool,
    T: Clone,
{
    let mut attempts = 0;

    while attempts < max_attempts {
        match func().await {
            Ok(result) => {
                if predicate(&result) {
                    return Ok(result);
                }
            }
            Err(e) => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(e);
                }
            }
        }

        attempts += 1;
        if attempts < max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
    }

    Err(LightningSwapError::SwapTimeout(format!(
        "Condition not met after {} attempts",
        max_attempts
    )))
}

/// Validate a Bitcoin transaction
pub fn validate_transaction(tx: &Transaction) -> LightningSwapResult<()> {
    // Basic validation
    if tx.input.is_empty() {
        return Err(LightningSwapError::InvalidSwapResponse(
            "Transaction has no inputs".to_string(),
        ));
    }

    if tx.output.is_empty() {
        return Err(LightningSwapError::InvalidSwapResponse(
            "Transaction has no outputs".to_string(),
        ));
    }

    Ok(())
}

/// Calculate transaction fee
pub fn calculate_fee(tx: &Transaction, input_values: &[u64]) -> LightningSwapResult<u64> {
    let total_input: u64 = input_values.iter().sum();
    let total_output: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();

    if total_input < total_output {
        return Err(LightningSwapError::InvalidSwapResponse(
            "Transaction outputs exceed inputs".to_string(),
        ));
    }

    Ok(total_input - total_output)
}

/// Format satoshis as Bitcoin amount string
pub fn format_sats(sats: u64) -> String {
    let btc = sats as f64 / 100_000_000.0;
    format!("{:.8} BTC", btc)
}

/// Parse Bitcoin amount string to satoshis
pub fn parse_btc_amount(amount_str: &str) -> LightningSwapResult<u64> {
    let amount_str = amount_str.trim().to_lowercase();

    if amount_str.ends_with(" btc") {
        let btc_part = &amount_str[..amount_str.len() - 4];
        let btc: f64 = btc_part.parse().map_err(|_| {
            LightningSwapError::InvalidSwapResponse(format!("Invalid BTC amount: {}", amount_str))
        })?;
        Ok((btc * 100_000_000.0) as u64)
    } else if amount_str.ends_with(" sat") || amount_str.ends_with(" sats") {
        let sat_part = if amount_str.ends_with(" sat") {
            &amount_str[..amount_str.len() - 4]
        } else {
            &amount_str[..amount_str.len() - 5]
        };
        sat_part.parse().map_err(|_| {
            LightningSwapError::InvalidSwapResponse(format!(
                "Invalid satoshi amount: {}",
                amount_str
            ))
        })
    } else {
        // Assume it's satoshis
        amount_str.parse().map_err(|_| {
            LightningSwapError::InvalidSwapResponse(format!("Invalid amount: {}", amount_str))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sats() {
        assert_eq!(format_sats(100_000_000), "1.00000000 BTC");
        assert_eq!(format_sats(50_000_000), "0.50000000 BTC");
        assert_eq!(format_sats(1), "0.00000001 BTC");
    }

    #[test]
    fn test_parse_btc_amount() {
        assert_eq!(parse_btc_amount("1.0 BTC").unwrap(), 100_000_000);
        assert_eq!(parse_btc_amount("0.5 BTC").unwrap(), 50_000_000);
        assert_eq!(parse_btc_amount("1000 sat").unwrap(), 1000);
        assert_eq!(parse_btc_amount("1000 sats").unwrap(), 1000);
        assert_eq!(parse_btc_amount("1000").unwrap(), 1000);
    }

    #[test]
    fn test_get_bitcoin_network() {
        assert_eq!(
            get_bitcoin_network(BitcoinNetwork::Mainnet),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            get_bitcoin_network(BitcoinNetwork::Testnet),
            bitcoin::Network::Testnet
        );
        assert_eq!(
            get_bitcoin_network(BitcoinNetwork::Regtest),
            bitcoin::Network::Regtest
        );
        assert_eq!(
            get_bitcoin_network(BitcoinNetwork::Signet),
            bitcoin::Network::Signet
        );
    }
}
