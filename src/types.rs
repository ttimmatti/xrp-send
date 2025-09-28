//! Type definitions for the XRP Send library

use serde::{Deserialize, Serialize};

/// XRP Ledger network configuration
#[derive(Debug, Clone, PartialEq)]
pub enum Network {
    /// Mainnet (production)
    Mainnet,
    /// Testnet (development)
    Testnet,
    /// Custom network with custom URL
    Custom(String),
}

impl Network {
    pub fn api_url(&self) -> &str {
        match self {
            Network::Mainnet => "https://xrplcluster.com/",
            Network::Testnet => "https://s.altnet.rippletest.net:51234/",
            Network::Custom(url) => url,
        }
    }
}

/// Transaction response from XRP Ledger
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub hash: String,
    pub result: String,
    pub message: String,
    pub applied: bool,
}

/// Account information
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account: String,
    pub balance: String,
    pub sequence: u32,
}

/// Transaction options
#[derive(Debug, Clone)]
pub struct TransactionOptions {
    pub simulate: bool,
    pub confirm: bool,
    pub confirm_timeout_seconds: u64,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            simulate: true,
            confirm: true,
            confirm_timeout_seconds: 30,
        }
    }
}
