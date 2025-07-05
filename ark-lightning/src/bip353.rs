//! BIP 353 Human Readable Names implementation
//!
//! This module implements BIP 353 DNS-based payment instructions for resolving
//! human-readable addresses to Bitcoin payment instructions.
//!
//! Reference: https://bips.dev/353/

use crate::LightningSwapError;
use crate::LightningSwapResult;
use serde::Deserialize;

/// DNS over HTTPS resolver for BIP 353 payment resolution
#[derive(Debug, Clone)]
pub struct Resolver {
    /// HTTP client for DNS over HTTPS queries
    pub http_client: reqwest::Client,
    /// DNS over HTTPS resolver URL
    pub dns_over_https_url: String,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    /// Create a new HTTP resolver with default configuration
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            dns_over_https_url: "https://cloudflare-dns.com/dns-query".to_string(),
        }
    }

    /// Create a new HTTP resolver with custom DNS over HTTPS URL
    pub fn with_dns_over_https(dns_over_https_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            dns_over_https_url,
        }
    }

    /// Get resolver type description
    pub fn get_resolver_info(&self) -> String {
        format!("DNS over HTTPS resolver: {}", self.dns_over_https_url)
    }
}

/// A BIP 353 payment instruction parsed from DNS TXT records
#[derive(Debug, Clone)]
pub struct PaymentInstruction {
    /// The URI containing the payment instruction
    pub uri: String,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Whether DNSSEC validation was successful
    pub dnssec_valid: bool,
    /// When this record was resolved
    pub resolved_at: std::time::SystemTime,
}

/// Parsed payment instruction with extracted fields
#[derive(Debug, Clone)]
pub struct ParsedPaymentInstruction {
    /// Bitcoin address (if on-chain)
    pub onchain: Option<String>,
    /// Lightning offer (BOLT12)
    pub offer: Option<String>,
    /// LNURL for Lightning payments
    pub lnurl: Option<String>,
    /// Amount in BTC
    pub amount: Option<f64>,
    /// Payment label
    pub label: Option<String>,
    /// Payment message
    pub message: Option<String>,
}

/// DNS over HTTPS response structure
#[derive(Debug, Deserialize)]
struct DnsOverHttpsResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DnsAnswer {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    r#type: u32,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

impl ParsedPaymentInstruction {
    /// Check if this has a Lightning offer
    pub fn has_lightning_offer(&self) -> bool {
        self.offer.is_some()
    }

    /// Check if this has an LNURL
    pub fn has_lnurl(&self) -> bool {
        self.lnurl.is_some()
    }

    /// Check if this has an on-chain address
    pub fn has_onchain(&self) -> bool {
        self.onchain.is_some()
    }

    /// Get the Lightning offer
    pub fn get_lightning_offer(&self) -> Option<&String> {
        self.offer.as_ref()
    }

    /// Get the LNURL
    pub fn get_lnurl(&self) -> Option<&String> {
        self.lnurl.as_ref()
    }

    /// Get the on-chain address
    pub fn get_onchain_address(&self) -> Option<&String> {
        self.onchain.as_ref()
    }
}

/// DNS-based payment resolver for BIP 353
pub struct DnsPaymentResolver {
    /// DNS resolver instance
    resolver: Resolver,
}

impl Default for DnsPaymentResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsPaymentResolver {
    /// Create a new DNS payment resolver with default configuration
    pub fn new() -> Self {
        Self {
            resolver: Resolver::default(),
        }
    }

    /// Create a new DNS payment resolver with the specified resolver type
    pub fn with_resolver(resolver: Resolver) -> Self {
        Self { resolver }
    }

    /// Create a new DNS payment resolver with DNS over HTTPS
    pub fn with_dns_over_https(url: Option<String>) -> Self {
        Self {
            resolver: Resolver::with_dns_over_https(
                url.unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string()),
            ),
        }
    }

    /// Check if an address is valid for BIP 353 resolution
    pub fn is_valid_address(address: &str) -> bool {
        if address.is_empty() {
            return false;
        }

        let parts: Vec<&str> = address.split('@').collect();
        if parts.len() != 2 {
            return false;
        }

        let user = parts[0];
        let domain = parts[1];

        // Check user part - must not be empty
        if user.is_empty() {
            return false;
        }

        // Check domain part
        if domain.is_empty()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return false;
        }

        true
    }

    /// Build the DNS query name for BIP 353
    pub fn build_dns_query(address: &str) -> LightningSwapResult<String> {
        if !Self::is_valid_address(address) {
            return Err(LightningSwapError::ConfigError(format!(
                "Invalid human-readable address format: {}",
                address
            )));
        }

        let parts: Vec<&str> = address.split('@').collect();
        let username = parts[0];
        let domain = parts[1];

        // BIP 353 DNS query format: username.user._bitcoin-payment.domain
        Ok(format!("{}.user._bitcoin-payment.{}", username, domain))
    }

    /// Resolve a human-readable address to payment instructions
    pub async fn resolve_address_string(
        &self,
        address: &str,
    ) -> LightningSwapResult<PaymentInstruction> {
        let dns_query = Self::build_dns_query(address)?;

        self.resolve_via_dns_over_https(&dns_query).await
    }

    /// Resolve via DNS over HTTPS
    async fn resolve_via_dns_over_https(
        &self,
        dns_query: &str,
    ) -> LightningSwapResult<PaymentInstruction> {
        let http_client = &self.resolver.http_client;
        let dns_over_https_url = &self.resolver.dns_over_https_url;

        let url = format!("{}?name={}&type=TXT", dns_over_https_url, dns_query);

        let response = http_client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| {
                LightningSwapError::NetworkError(format!("DNS over HTTPS request failed: {}", e))
            })?;

        let dns_response: DnsOverHttpsResponse = response.json().await.map_err(|e| {
            LightningSwapError::NetworkError(format!("Failed to parse DNS response: {}", e))
        })?;

        if dns_response.status != 0 {
            return Err(LightningSwapError::NetworkError(format!(
                "DNS query failed with status: {}",
                dns_response.status
            )));
        }

        let answer = dns_response.answer.ok_or_else(|| {
            LightningSwapError::NetworkError("No DNS answer in response".to_string())
        })?;

        let first_record = answer
            .first()
            .ok_or_else(|| LightningSwapError::NetworkError("No TXT records found".to_string()))?;

        // Clean up the TXT record data (remove quotes and escapes)
        let cleaned_data = first_record
            .data
            .trim_matches('"')
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");

        if !self.is_valid_payment_instruction(&cleaned_data) {
            return Err(LightningSwapError::ConfigError(format!(
                "Invalid payment instruction format: {}",
                cleaned_data
            )));
        }

        Ok(PaymentInstruction {
            uri: cleaned_data,
            ttl: first_record.ttl,
            dnssec_valid: false, /* DNS over HTTPS doesn't provide DNSSEC info in this simple
                                  * implementation */
            resolved_at: std::time::SystemTime::now(),
        })
    }

    /// Parse a payment instruction into structured data
    pub fn parse_payment_instruction(
        &self,
        instruction: &PaymentInstruction,
    ) -> LightningSwapResult<ParsedPaymentInstruction> {
        let uri = &instruction.uri;

        // Check if it starts with bitcoin: prefix
        if !uri.starts_with("bitcoin:") {
            return Err(LightningSwapError::ConfigError(format!(
                "Payment instruction must start with 'bitcoin:', got: {}",
                uri
            )));
        }

        // Remove the bitcoin: prefix
        let content = &uri[8..]; // Remove "bitcoin:"

        // Split by '?' to separate address and query parameters
        let parts: Vec<&str> = content.split('?').collect();

        let mut parsed = ParsedPaymentInstruction {
            onchain: None,
            offer: None,
            lnurl: None,
            amount: None,
            label: None,
            message: None,
        };

        // Handle the address part (before ?)
        if !parts.is_empty() && !parts[0].is_empty() {
            parsed.onchain = Some(parts[0].to_string());
        }

        // Handle query parameters (after ?)
        if parts.len() > 1 {
            let query_params = parts[1];
            let params: std::collections::HashMap<String, String> = query_params
                .split('&')
                .filter_map(|param| {
                    let mut split = param.split('=');
                    let key = split.next()?;
                    let value = split.next()?;
                    Some((key.to_string(), value.to_string()))
                })
                .collect();

            // Extract known parameters
            parsed.offer = params.get("lno").cloned();
            parsed.lnurl = params.get("lnurl").cloned();
            parsed.label = params.get("label").cloned();
            parsed.message = params.get("message").cloned();

            // Parse amount if present
            if let Some(amount_str) = params.get("amount") {
                if let Ok(amount) = amount_str.parse::<f64>() {
                    parsed.amount = Some(amount);
                }
            }
        }

        Ok(parsed)
    }

    /// Check if a string looks like a valid Bitcoin payment instruction
    pub fn is_valid_payment_instruction(&self, instruction: &str) -> bool {
        // Must start with bitcoin: for BIP 353
        if !instruction.starts_with("bitcoin:") {
            return false;
        }

        // Basic length check
        if instruction.len() < 8 {
            // "bitcoin:" is 8 characters
            return false;
        }

        // The rest of the validation will be done during parsing
        true
    }

    /// Get DNS resolver configuration info
    pub fn get_resolver_info(&self) -> String {
        self.resolver.get_resolver_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_address() {
        assert!(DnsPaymentResolver::is_valid_address("test@example.com"));
        assert!(DnsPaymentResolver::is_valid_address(
            "vincenzopalazzo@easybitcoinaddress.me"
        ));
        assert!(!DnsPaymentResolver::is_valid_address("invalid"));
        assert!(!DnsPaymentResolver::is_valid_address("@example.com"));
        assert!(!DnsPaymentResolver::is_valid_address("test@"));
        assert!(!DnsPaymentResolver::is_valid_address(""));
    }

    #[test]
    fn test_build_dns_query() {
        let query =
            DnsPaymentResolver::build_dns_query("vincenzopalazzo@easybitcoinaddress.me").unwrap();
        assert_eq!(
            query,
            "vincenzopalazzo.user._bitcoin-payment.easybitcoinaddress.me"
        );

        let query = DnsPaymentResolver::build_dns_query("test@example.com").unwrap();
        assert_eq!(query, "test.user._bitcoin-payment.example.com");

        assert!(DnsPaymentResolver::build_dns_query("invalid").is_err());
    }

    #[test]
    fn test_parse_payment_instruction() {
        let resolver = DnsPaymentResolver::new();

        // Test Lightning offer payment instruction
        let instruction = PaymentInstruction {
            uri: "bitcoin:?lno=lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq".to_string(),
            ttl: 3600,
            dnssec_valid: true,
            resolved_at: std::time::SystemTime::now(),
        };

        let parsed = resolver.parse_payment_instruction(&instruction).unwrap();
        assert!(parsed.has_lightning_offer());
        assert!(!parsed.has_onchain());
        assert!(!parsed.has_lnurl());
        assert!(parsed.get_lightning_offer().is_some());
        assert_eq!(parsed.get_lightning_offer().unwrap(), "lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq");
    }

    #[test]
    fn test_parse_payment_instruction_with_onchain() {
        let resolver = DnsPaymentResolver::new();

        // Test on-chain address with Lightning offer
        let instruction = PaymentInstruction {
            uri: "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?lno=lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq".to_string(),
            ttl: 3600,
            dnssec_valid: true,
            resolved_at: std::time::SystemTime::now(),
        };

        let parsed = resolver.parse_payment_instruction(&instruction).unwrap();
        assert!(parsed.has_lightning_offer());
        assert!(parsed.has_onchain());
        assert_eq!(
            parsed.get_onchain_address().unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(parsed.get_lightning_offer().unwrap(), "lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq");
    }

    #[tokio::test]
    async fn test_resolve_invalid_address() {
        let resolver = DnsPaymentResolver::new();
        let result = resolver.resolve_address_string("invalid_address").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_real_dns_resolution_vincenzopalazzo() {
        // Use HTTP resolver (DNS over HTTPS) for better reliability
        let resolver = DnsPaymentResolver::with_dns_over_https(None);

        // Test with vincenzopalazzo@easybitcoinaddress.me
        let result = resolver
            .resolve_address_string("vincenzopalazzo@easybitcoinaddress.me")
            .await;

        match result {
            Ok(payment_instruction) => {
                println!(
                    "Successfully resolved with HTTP resolver: {}",
                    payment_instruction.uri
                );
                assert!(payment_instruction.uri.starts_with("bitcoin:"));

                // Parse the instruction to verify it's valid
                let parsed = resolver
                    .parse_payment_instruction(&payment_instruction)
                    .unwrap();

                // Should have a Lightning offer
                assert!(parsed.has_lightning_offer(), "Should have Lightning offer");

                if let Some(offer) = parsed.get_lightning_offer() {
                    assert!(offer.starts_with("lno"), "Should be a BOLT12 offer");
                    println!("Lightning offer: {}", offer);
                }

                println!("TTL: {}", payment_instruction.ttl);
                println!("DNSSEC Valid: {}", payment_instruction.dnssec_valid);
            }
            Err(e) => {
                println!(
                    "HTTP resolver failed (may be expected in some environments): {:?}",
                    e
                );
                // This is acceptable in some test environments
            }
        }
    }

    #[tokio::test]
    async fn test_payment_instruction_validation() {
        let resolver = DnsPaymentResolver::new();

        // Test valid BIP 353 format
        assert!(resolver.is_valid_payment_instruction("bitcoin:?lno=lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq"));
        assert!(resolver.is_valid_payment_instruction("bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?lno=lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq"));
        assert!(resolver.is_valid_payment_instruction("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));

        // Test invalid formats
        assert!(!resolver.is_valid_payment_instruction("invalid"));
        assert!(!resolver.is_valid_payment_instruction(""));
        assert!(!resolver.is_valid_payment_instruction("lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq"));
        assert!(!resolver.is_valid_payment_instruction("bitcoin"));
    }

    #[tokio::test]
    async fn test_dns_over_https_resolver() {
        let resolver = DnsPaymentResolver::with_dns_over_https(None);

        // Test that it uses the default URL
        let info = resolver.get_resolver_info();
        assert!(info.contains("https://cloudflare-dns.com/dns-query"));

        // Test with custom URL
        let custom_resolver =
            DnsPaymentResolver::with_dns_over_https(Some("https://1.1.1.1/dns-query".to_string()));
        let custom_info = custom_resolver.get_resolver_info();
        assert!(custom_info.contains("https://1.1.1.1/dns-query"));
    }
}
