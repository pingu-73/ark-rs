//! Example demonstrating the new generic Resolver enum for BIP 353 DNS resolution
//!
//! This example shows how to use the different resolver types:
//! - HTTP resolver for DNS over HTTPS
//! - Pure resolver for traditional DNS
//! - DNSSEC-enabled resolver

use ark_lightning::bip353::DnsPaymentResolver;
use ark_lightning::bip353::Resolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create different resolver types
    println!("=== BIP 353 Resolver Examples ===\n");

    // 1. HTTP resolver (DNS over HTTPS) - default
    let http_resolver = DnsPaymentResolver::with_resolver(Resolver::http_resolver_default());
    println!("HTTP Resolver: {}", http_resolver.get_resolver_info());

    // 2. Custom HTTP resolver with different DNS over HTTPS provider
    let custom_http = DnsPaymentResolver::with_resolver(Resolver::http_resolver(
        "https://8.8.8.8/dns-query".to_string(),
    ));
    println!("Custom HTTP Resolver: {}", custom_http.get_resolver_info());

    // 3. Pure DNS resolver (traditional DNS)
    let pure_resolver = DnsPaymentResolver::with_resolver(Resolver::pure_resolver_default());
    println!("Pure DNS Resolver: {}", pure_resolver.get_resolver_info());

    // 4. DNSSEC-enabled resolver
    let dnssec_resolver = DnsPaymentResolver::with_resolver(Resolver::pure_resolver_with_dnssec());
    println!("DNSSEC Resolver: {}", dnssec_resolver.get_resolver_info());

    // 5. Using the convenience methods
    let convenience_http = DnsPaymentResolver::with_dns_over_https(None);
    println!("Convenience HTTP: {}", convenience_http.get_resolver_info());

    let convenience_dnssec = DnsPaymentResolver::with_dnssec();
    println!(
        "Convenience DNSSEC: {}",
        convenience_dnssec.get_resolver_info()
    );

    // Default resolver (HTTP with Cloudflare)
    let default_resolver = DnsPaymentResolver::new();
    println!("Default Resolver: {}", default_resolver.get_resolver_info());

    println!("\n=== Example Resolution (using HTTP resolver) ===");

    // Example resolution using HTTP resolver
    let test_address = "vincenzopalazzo@easybitcoinaddress.me";
    match http_resolver.resolve_address_string(test_address).await {
        Ok(payment_instruction) => {
            println!("✓ Successfully resolved: {}", payment_instruction.uri);
            println!("  TTL: {}", payment_instruction.ttl);
            println!("  DNSSEC Valid: {}", payment_instruction.dnssec_valid);

            // Parse the payment instruction
            if let Ok(parsed) = http_resolver.parse_payment_instruction(&payment_instruction) {
                println!("  Has Lightning Offer: {}", parsed.has_lightning_offer());
                println!("  Has On-chain Address: {}", parsed.has_onchain());
                println!("  Has LNURL: {}", parsed.has_lnurl());

                if let Some(offer) = parsed.get_lightning_offer() {
                    println!("  Lightning Offer: {}", offer);
                }
            }
        }
        Err(e) => {
            println!("✗ Resolution failed: {:?}", e);
        }
    }

    println!("\n=== Address Validation ===");

    // Test address validation
    let valid_addresses = vec![
        "test@example.com",
        "vincenzopalazzo@easybitcoinaddress.me",
        "alice@bitcoin.org",
    ];

    let invalid_addresses = vec![
        "invalid",
        "@example.com",
        "test@",
        "",
        "test@invalid..domain",
    ];

    for addr in valid_addresses {
        println!("✓ Valid: {}", addr);
        assert!(DnsPaymentResolver::is_valid_address(addr));
    }

    for addr in invalid_addresses {
        println!("✗ Invalid: {}", addr);
        assert!(!DnsPaymentResolver::is_valid_address(addr));
    }

    println!("\n=== DNS Query Building ===");

    // Test DNS query building
    let test_addr = "alice@example.com";
    match DnsPaymentResolver::build_dns_query(test_addr) {
        Ok(dns_query) => {
            println!("Address: {} -> DNS Query: {}", test_addr, dns_query);
            assert_eq!(dns_query, "alice.user._bitcoin-payment.example.com");
        }
        Err(e) => {
            println!("Failed to build DNS query: {:?}", e);
        }
    }

    Ok(())
}
