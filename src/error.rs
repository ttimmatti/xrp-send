//! Error types for the XRP Send library

use thiserror::Error;

/// Main error type for the XRP Send library
#[derive(Error, Debug)]
pub enum XrpError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid secret key: {0}")]
    InvalidSecret(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Transaction simulation failed: {result} - {message}")]
    TransactionSimulationFailed { result: String, message: String },

    #[error("Transaction failed: {result} - {message}")]
    TransactionFailed { result: String, message: String },

    #[error("Transaction not found within timeout")]
    TransactionNotFound,

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("API error: {error} (code: {code})")]
    ApiError { error: String, code: u32 },

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    // Additional error types for missing From implementations
    #[error("Base58 decode error: {0}")]
    Base58Decode(#[from] bs58::decode::Error),

    #[error("Parse int error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Parse float error: {0}")]
    ParseFloat(#[from] std::num::ParseFloatError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("String error: {0}")]
    StringError(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<&str> for XrpError {
    fn from(err: &str) -> Self {
        XrpError::StringError(err.to_string())
    }
}

impl From<String> for XrpError {
    fn from(err: String) -> Self {
        XrpError::StringError(err)
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, XrpError>;
