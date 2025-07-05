# Lightning Swaps Integration

This module provides lightning network integration for the Ark protocol through submarine swaps.

## Features

- **Feature Flag**: The lightning functionality is behind the `lightning` feature flag
- **Async Support**: All operations are async using `tokio`
- **Trait-based Design**: Core functionality is defined through traits for easy extensibility

## Core Components

### Traits

- `Wallet`: Handles wallet operations (signing, broadcasting, UTXO management)
- `SwapProvider`: Handles swap operations (creating swaps, checking status)
- `RefundHandler`: Handles refund scenarios
- `InvoiceDecoder`: Decodes BOLT11 invoices

### Main Implementation

- `ArkadeLightning`: Main class that orchestrates lightning payments through submarine swaps

## Usage

```rust
use ark_core::lightning::*;

// Enable the lightning feature in your Cargo.toml:
// ark-core = { version = "0.7.0", features = ["lightning"] }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet and swap provider implementations
    let wallet = Box::new(YourWalletImplementation::new());
    let swap_provider = Box::new(YourSwapProviderImplementation::new());

    // Configure ArkadeLightning
    let config = ArkadeLightningConfig {
        wallet,
        swap_provider,
        refund_handler: None, // Optional
        timeout_config: None, // Optional - uses defaults
        fee_config: None,     // Optional - uses defaults
        retry_config: None,   // Optional - uses defaults
    };

    // Create ArkadeLightning instance
    let arkade_lightning = ArkadeLightning::new(config)?;

    // Send a lightning payment
    let payment_args = SendPaymentArgs {
        invoice: "lnbc1000...".to_string(),
        source_vtxos: None, // Optional - will use wallet's UTXOs
    };

    let result = arkade_lightning
        .send_lightning_payment(payment_args)
        .await?;
    println!(
        "Payment sent! Preimage: {}, TXID: {}",
        result.preimage, result.txid
    );

    Ok(())
}
```

## BoltzSwapProvider Implementation

The `SwapProvider` trait should be implemented by external crates. Here's an example structure:

```rust
use ark_core::lightning::*;
use async_trait::async_trait;

pub struct BoltzSwapProvider {
    api_url: String,
    network: BitcoinNetwork,
    // Add fields for HTTP client, credentials, etc.
}

#[async_trait]
impl SwapProvider for BoltzSwapProvider {
    fn get_network(&self) -> BitcoinNetwork {
        self.network
    }

    async fn create_submarine_swap(
        &self,
        invoice: &str,
        refund_pubkey: &str,
    ) -> LightningSwapResult<SubmarineSwapResponse> {
        // Implementation for creating submarine swaps with Boltz
        todo!("Implement Boltz API calls")
    }

    async fn get_swap_status(&self, swap_id: &str) -> LightningSwapResult<BoltzSwapStatusResponse> {
        // Implementation for checking swap status
        todo!("Implement Boltz status check")
    }

    // ... other methods
}
```

## Default Configuration

The following default values are used if not specified:

```rust
// Timeout configuration
swap_expiry_blocks: 144,
invoice_expiry_seconds: 3600,
claim_delay_blocks: 10,

// Fee configuration
max_miner_fee_sats: 5000,
max_swap_fee_sats: 1000,

// Retry configuration
max_attempts: 5,
delay_ms: 2000,
```

## Error Handling

The module uses `LightningSwapError` for all error cases:

- `InsufficientFunds`: Not enough funds for the swap
- `SwapError`: Generic swap errors with optional refund data
- `InvalidSwapResponse`: Invalid response from swap provider
- `SwapTimeout`: Swap operation timed out
- `InvoiceDecodeError`: Failed to decode lightning invoice
- `WalletError`: Wallet operation failed
- `NetworkError`: Network communication error
- `ConfigError`: Configuration error

## Testing

The module includes comprehensive tests with mock implementations. Run tests with:

```bash
cargo test --features lightning
```

## Future Improvements

- Implement reverse submarine swaps for receiving payments
- Add support for multiple swap providers
- Implement proper BOLT11 invoice decoding
- Add more sophisticated coin selection algorithms
- Implement automatic refund claiming
