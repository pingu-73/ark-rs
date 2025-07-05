# ark-lightning

Lightning Network integration for the Ark protocol through submarine swaps.

## Overview

`ark-lightning` provides Lightning Network integration for the Ark protocol, enabling seamless Lightning Network payments using VTXOs (Virtual TXOs). The crate implements submarine swaps to bridge between the Ark protocol and Lightning Network.

## Features

- **Submarine Swaps**: Send Lightning payments using Ark VTXOs
- **Reverse Submarine Swaps**: Receive Lightning payments and convert to Ark VTXOs
- **BOLT11 Invoice Decoding**: Proper BOLT11 invoice parsing using `lightning-invoice`
- **BOLT12 Support**: Basic BOLT12 offer decoding (full support requires Lightning node integration)
- **Boltz Integration**: Built-in support for Boltz swap service under `boltz` feature flag
- **Configurable Swap Providers**: Support for multiple swap providers
- **Async/Await Support**: Full async support for non-blocking operations
- **Error Handling**: Comprehensive error types and handling for swap operations
- **Refund Handling**: Automatic refund mechanisms for failed swaps

## Architecture

The crate is organized into several modules:

- `types`: Core data structures and configuration types
- `traits`: Trait definitions for wallets, swap providers, and handlers
- `lightning_swaps`: Main implementation of the ArkadeLightning client
- `utils`: Utility functions for Bitcoin network operations and polling
- `errors`: Error types and result aliases
- `boltz`: Boltz-specific swap provider implementation (feature-gated)

## Usage

```rust
use ark_lightning::{ArkadeLightning, ArkadeLightningConfig};

// Configure the lightning client
let config = ArkadeLightningConfig {
    wallet: Box::new(your_wallet),
    swap_provider: Box::new(your_swap_provider),
    refund_handler: None, // Optional
    timeout_config: None, // Optional
    fee_config: None,     // Optional
    retry_config: None,   // Optional
};

// Create the lightning client
let lightning_client = ArkadeLightning::new(config)?;

// Send a lightning payment
let result = lightning_client.send_lightning_payment(SendPaymentArgs {
    invoice: "lnbc1000...",
    source_vtxos: None, // Optional
}).await?;

// Decode an invoice
let decoded = lightning_client.decode_invoice("lnbc1000...").await?;

// BOLT12 offer decoding (basic support)
let offer = lightning_client.decode_bolt12_offer("lno1...").await?;
```

### Using the Boltz Swap Provider

Enable the `boltz` feature and use the Boltz swap provider:

```rust
use ark_lightning::boltz::BoltzSwapProvider;

// Create Boltz provider for mainnet
let boltz_provider = BoltzSwapProvider::new_mainnet()?;

// Or for testnet
let boltz_provider = BoltzSwapProvider::new_testnet()?;

// Use with ArkadeLightning
let config = ArkadeLightningConfig {
    wallet: Box::new(your_wallet),
    swap_provider: Box::new(boltz_provider),
    // ... other config
};
```

## Features

- `default`: Default features (BOLT11 invoice support, basic Lightning functionality)
- `boltz`: Enable Boltz swap provider integration with HTTP API client

## Dependencies

- `ark-core`: Core Ark protocol types and utilities
- `bitcoin`: Bitcoin protocol types and utilities
- `lightning-invoice`: BOLT11 invoice parsing and validation
- `tokio`: Async runtime
- `async-trait`: Async trait support
- `futures`: Async utilities
- `serde`: Serialization/deserialization
- `reqwest`: HTTP client (optional, for swap providers)

## Error Handling

The crate provides comprehensive error types through the `LightningSwapError` enum:

- `InsufficientFunds`: Not enough funds for the swap
- `SwapError`: Generic swap operation errors
- `InvalidSwapResponse`: Invalid response from swap provider
- `SwapTimeout`: Swap operation timed out
- `InvoiceDecodeError`: Failed to decode Lightning invoice
- `WalletError`: Wallet operation errors
- `NetworkError`: Network communication errors
- `ConfigError`: Configuration errors

## Testing

Run the test suite with:

```bash
cargo test -p ark-lightning
```

## License

MIT License
