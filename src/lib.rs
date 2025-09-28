//! XRP Send Library
//!
//! A simple library for sending XRP transactions on the XRP Ledger.
//!
//! # Example
//! 
//! ```rust,no_run
//! use xrp_send::{XrpClient, Keypair, Network};
//! 
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let keypair = Keypair::from_secret("your_secret_here")?;
//! let client = XrpClient::new(Network::Testnet);
//! 
//! let response = client.send_xrp(&keypair, "rDestination...", 1.0, None)?;
//! println!("Transaction hash: {}", response.hash);
//! # Ok(())
//! # }
//! ```

// Internal modules (not part of public API)
mod constant;

pub mod error;
pub mod types;

// Internal modules that depend on public modules
pub mod client;
mod encode_tx;
pub mod keypair;

// Re-export main types for convenience
pub use client::XrpClient;
pub use error::{Result, XrpError};
pub use keypair::Keypair;
pub use types::{Network, TransactionOptions, TransactionResponse};
