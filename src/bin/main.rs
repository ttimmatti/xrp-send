//! Example/test binary for the XRP Send library

use dotenv::dotenv;
use std::env;

use xrp_send::{Keypair, Network, TransactionOptions, XrpClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    // Test XRP sending
    test_xrp_send()?;

    // Test token sending (commented out as it requires specific setup)
    // test_token_send()?;

    println!("All tests passed!");
    Ok(())
}

fn test_xrp_send() -> Result<(), Box<dyn std::error::Error>> {
    let secret_str = env::var("SECRET_STR").expect("SECRET_STR must be set in .env");
    let expected_address = env::var("ADDRESS").expect("ADDRESS must be set in .env");

    println!("Testing XRP send functionality...");

    // Create keypair from secret
    let keypair = Keypair::from_secret(&secret_str)?;
    let derived_address = keypair.derive_address();

    println!("Expected address: {}", expected_address);
    println!("Derived address: {}", derived_address);

    // Verify address derivation
    assert_eq!(
        derived_address, expected_address,
        "Derived address does not match expected address"
    );
    println!("✓ Address derivation is correct");

    // Create client and send XRP
    let client = XrpClient::new(Network::Testnet);
    let options = TransactionOptions {
        simulate: true, // Use simulation for testing
        confirm: true,
        confirm_timeout_seconds: 30,
    };

    let response = client.send_xrp(
        &keypair,
        "rG1QQv2nh2gr7RCZ1P8YYcBUKCCN633jCn",
        123123.0,
        Some(options),
    )?;

    println!("✓ XRP transaction successful");
    println!("  Hash: {}", response.hash);
    println!("  Result: {}", response.result);

    Ok(())
}

#[allow(dead_code)]
fn test_token_send() -> Result<(), Box<dyn std::error::Error>> {
    let secret_str = env::var("SECRET_WITH_ISSUED_TOKENS")
        .expect("SECRET_WITH_ISSUED_TOKENS must be set in .env");
    let expected_address = env::var("ADDRESS_WITH_ISSUED_TOKENS")
        .expect("ADDRESS_WITH_ISSUED_TOKENS must be set in .env");

    println!("Testing token send functionality...");

    let keypair = Keypair::from_secret(&secret_str)?;
    let derived_address = keypair.derive_address();

    assert_eq!(derived_address, expected_address);
    println!("✓ Token keypair address verification passed");

    let client = XrpClient::new(Network::Testnet);
    let options = TransactionOptions {
        simulate: true,
        confirm: true,
        confirm_timeout_seconds: 30,
    };

    let response = client.send_token(
        &keypair,
        "rG1QQv2nh2gr7RCZ1P8YYcBUKCCN633jCn",
        "1",
        "FOO",
        "rP5CcKTLcQFfA3aWasydk9hMxCJawJ85CM",
        Some(options),
    )?;

    println!("✓ Token transaction successful");
    println!("  Hash: {}", response.hash);

    Ok(())
}
