use ark_lightning::bip353::DnsPaymentResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DNS resolver with DNS over HTTPS support
    let resolver = DnsPaymentResolver::new();

    // Example address to resolve
    let address = "vincenzopalazzo@easybitcoinaddress.me";

    println!("Resolving BIP 353 address: {}", address);

    // Resolve the address
    match resolver.resolve_address_string(address).await {
        Ok(payment_instruction) => {
            println!("✅ Successfully resolved!");
            println!("Payment instruction: {}", payment_instruction.uri);
            println!("TTL: {} seconds", payment_instruction.ttl);
            println!("DNSSEC Valid: {}", payment_instruction.dnssec_valid);

            // Parse the payment instruction
            match resolver.parse_payment_instruction(&payment_instruction) {
                Ok(parsed) => {
                    println!("\n📄 Parsed payment instruction:");

                    if let Some(onchain) = parsed.get_onchain_address() {
                        println!("🔗 On-chain address: {}", onchain);
                    }

                    if let Some(offer) = parsed.get_lightning_offer() {
                        println!("⚡ Lightning offer: {}", offer);
                    }

                    if let Some(lnurl) = parsed.get_lnurl() {
                        println!("🔗 LNURL: {}", lnurl);
                    }

                    if let Some(amount) = parsed.amount {
                        println!("💰 Amount: {} BTC", amount);
                    }

                    if let Some(label) = &parsed.label {
                        println!("🏷️  Label: {}", label);
                    }

                    if let Some(message) = &parsed.message {
                        println!("💬 Message: {}", message);
                    }
                }
                Err(e) => {
                    println!("❌ Failed to parse payment instruction: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to resolve address: {}", e);
        }
    }

    // Test with a simple DNS query builder
    println!("\n🔍 DNS Query Examples:");
    match DnsPaymentResolver::build_dns_query("test@example.com") {
        Ok(query) => println!("test@example.com → {}", query),
        Err(e) => println!("Invalid: {}", e),
    }

    match DnsPaymentResolver::build_dns_query("satoshi@bitcoin.org") {
        Ok(query) => println!("satoshi@bitcoin.org → {}", query),
        Err(e) => println!("Invalid: {}", e),
    }

    Ok(())
}
