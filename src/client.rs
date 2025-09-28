//! XRP client for sending transactions

use serde_json::{json, Value};
use std::time::Duration;

use crate::encode_tx;
use crate::error::{Result, XrpError};
use crate::keypair::Keypair;
use crate::types::{Network, TransactionOptions, TransactionResponse};

/// XRP client for interacting with the XRP Ledger
///
/// This client provides a high-level interface for sending XRP and token transactions
/// to the XRP Ledger. It handles transaction encoding, signing, and submission.
///
/// # Example
///
/// ```rust,no_run
/// use xrp_send::{XrpClient, Keypair, Network, TransactionOptions};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypair = Keypair::from_secret("your_secret_here")?;
/// let client = XrpClient::new(Network::Testnet);
///
/// let options = TransactionOptions {
///     simulate: true,
///     timeout_seconds: 30,
/// };
///
/// let response = client.send_xrp(
///     &keypair,
///     "rDestinationAddress...",
///     1.0, // 1 XRP
///     Some(options),
/// )?;
///
/// println!("Transaction hash: {}", response.hash);
/// # Ok(())
/// # }
/// ```
pub struct XrpClient {
    network: Network,
    client: reqwest::blocking::Client,
}

impl XrpClient {
    /// Create a new XRP client
    pub fn new(network: Network) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { network, client }
    }

    /// Send XRP to a destination address
    ///
    /// # Arguments
    /// * `keypair` - The sender's keypair containing private key
    /// * `destination` - Destination XRP address (must start with 'r')
    /// * `amount_xrp` - Amount to send in XRP (not drops)
    /// * `options` - Optional transaction configuration
    ///
    /// # Returns
    /// * `TransactionResponse` - Contains transaction hash, result, and status
    ///
    /// # Errors
    /// * `XrpError::InvalidAddress` - Invalid destination address format
    /// * `XrpError::InvalidAmount` - Invalid amount (negative, too large, etc.)
    /// * `XrpError::TransactionFailed` - Transaction failed on the ledger
    /// * `XrpError::Network` - Network communication error
    ///
    /// # Example
    /// ```rust,no_run
    /// # use xrp_send::{XrpClient, Keypair, Network};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = XrpClient::new(Network::Testnet);
    /// let keypair = Keypair::from_secret("your_secret")?;
    ///
    /// let response = client.send_xrp(&keypair, "rDestination...", 1.0, None)?;
    /// println!("Sent 1 XRP, hash: {}", response.hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_xrp(
        &self,
        keypair: &Keypair,
        destination: &str,
        amount_xrp: f64,
        options: Option<TransactionOptions>,
    ) -> Result<TransactionResponse> {
        let opts = options.unwrap_or_default();
        let amount_drops = (amount_xrp * 1_000_000.0) as u64;

        let mut tx = self.build_xrp_transaction(
            &keypair.public_key_str(),
            &keypair.derive_address(),
            destination,
            &amount_drops.to_string(),
        )?;

        self.execute_transaction(keypair, &mut tx, opts)
    }

    /// Send tokens to a destination address
    /// - Trust line must be established between receiver and sender
    pub fn send_token(
        &self,
        keypair: &Keypair,
        destination: &str,
        amount: &str,
        currency: &str,
        issuer: &str,
        options: Option<TransactionOptions>,
    ) -> Result<TransactionResponse> {
        let opts = options.unwrap_or_default();

        let mut tx = self.build_token_transaction(
            &keypair.public_key_str(),
            &keypair.derive_address(),
            destination,
            amount,
            currency,
            issuer,
        )?;

        self.execute_transaction(keypair, &mut tx, opts)
    }

    fn build_xrp_transaction(
        &self,
        signing_key: &str,
        account: &str,
        destination: &str,
        amount: &str,
    ) -> Result<Value> {
        let sequence = self.get_account_sequence(account)?;
        let last_ledger = self.get_last_ledger_sequence()?;

        Ok(json!({
            "TransactionType": "Payment",
            "Account": account,
            "Destination": destination,
            "Amount": amount,
            "SigningPubKey": signing_key,
            "Fee": "1000",
            "Sequence": sequence,
            "LastLedgerSequence": last_ledger + 100,
        }))
    }

    fn build_token_transaction(
        &self,
        signing_key: &str,
        account: &str,
        destination: &str,
        amount: &str,
        currency: &str,
        issuer: &str,
    ) -> Result<Value> {
        let sequence = self.get_account_sequence(account)?;
        let last_ledger = self.get_last_ledger_sequence()?;

        Ok(json!({
            "TransactionType": "Payment",
            "Account": account,
            "Destination": destination,
            "Amount": {
                "currency": currency,
                "issuer": issuer,
                "value": amount,
            },
            "SigningPubKey": signing_key,
            "Fee": "1000",
            "Sequence": sequence,
            "LastLedgerSequence": last_ledger + 100,
        }))
    }

    fn execute_transaction(
        &self,
        keypair: &Keypair,
        tx: &mut Value,
        options: TransactionOptions,
    ) -> Result<TransactionResponse> {
        // Encode and sign transaction
        let tx_blob = encode_tx::encode_transaction(tx, false)?;

        if options.simulate {
            self.simulate_transaction(tx)?;
        }

        let signature = keypair.sign(&tx_blob);
        tx["TxnSignature"] = json!(hex::encode_upper(&signature));

        let signed_tx_blob = encode_tx::encode_transaction(tx, true)?;

        // Submit transaction
        let response = self.submit_transaction(&hex::encode(&signed_tx_blob))?;

        // Extract transaction hash for confirmation
        let tx_hash = response["result"]["tx_json"]["hash"]
            .as_str()
            .ok_or_else(|| XrpError::ApiError {
                error: "Missing transaction hash".to_string(),
                code: 0,
            })?
            .to_string();

        // Wait for confirmation if needed
        if options.confirm {
            let t = std::time::Instant::now();
            let _confirmed = self.wait_for_transaction(&tx_hash, options.confirm_timeout_seconds)?;
            let duration = t.elapsed();
            println!("Transaction confirmed in {:?}", duration);
        }

        Ok(TransactionResponse {
            hash: tx_hash,
            result: response["result"]["engine_result"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            message: response["result"]["engine_result_message"]
                .as_str()
                .unwrap_or("Unknown")
                .to_string(),
            applied: response["result"]["applied"].as_bool().unwrap_or(false),
        })
    }

    fn get_account_sequence(&self, account: &str) -> Result<u32> {
        let params = json!({
            "method": "account_info",
            "params": [{"account": account, "ledger_index": "current"}]
        });

        let response = self.make_request(params)?;
        let sequence = response["result"]["account_data"]["Sequence"]
            .as_u64()
            .ok_or_else(|| XrpError::ApiError {
                error: "Invalid account sequence".to_string(),
                code: 0,
            })?;

        Ok(sequence as u32)
    }

    fn get_last_ledger_sequence(&self) -> Result<u64> {
        let params = json!({
            "method": "ledger_closed",
            "params": [{}]
        });

        let response = self.make_request(params)?;
        let ledger_index =
            response["result"]["ledger_index"]
                .as_u64()
                .ok_or_else(|| XrpError::ApiError {
                    error: "Invalid ledger index".to_string(),
                    code: 0,
                })?;

        Ok(ledger_index)
    }

    fn simulate_transaction(&self, tx: &Value) -> Result<()> {
        let params = json!({
            "method": "simulate",
            "params": [{"tx_json": tx}]
        });

        let response = self.make_request(params)?;
        let engine_result_code = response["result"]["engine_result_code"]
            .as_u64()
            .unwrap_or(1);

        if engine_result_code != 0 {
            let engine_result = response["result"]["engine_result"]
                .as_str()
                .unwrap_or("Unknown error");
            let engine_result_message = response["result"]["engine_result_message"]
                .as_str()
                .unwrap_or("Unknown error");

            return Err(XrpError::TransactionSimulationFailed {
                result: engine_result.to_string(),
                message: engine_result_message.to_string(),
            });
        }

        Ok(())
    }

    fn submit_transaction(&self, tx_blob: &str) -> Result<serde_json::Value> {
        let params = json!({
            "method": "submit",
            "params": [{"tx_blob": tx_blob}]
        });

        let response = self.make_request(params)?;

        // check if the transaction was accepted. may still fail onchain
        if !response["result"]["accepted"].as_bool().unwrap_or(false) {
            let engine_result = response["result"]["engine_result"]
                .as_str()
                .unwrap_or("Unknown error");
            let engine_result_message = response["result"]["engine_result_message"]
                .as_str()
                .unwrap_or("Unknown error");

            return Err(XrpError::TransactionFailed {
                result: engine_result.to_string(),
                message: engine_result_message.to_string(),
            });
        }

        Ok(response)
    }

    fn confirm_transaction(&self, tx_hash: &str) -> Result<serde_json::Value> {
        let params = json!({
            "method": "tx",
            "params": [{
                "transaction": tx_hash,
                "binary": false,
                "api_version": 2
            }]
        });
    
        let response = self.make_request(params)?;

        // txnNotFound or invalid params
        if response.get("error").is_some() {
            return Err(XrpError::TransactionNotFound);
        }
        
        // txn processing but not applied yet
        if response["result"]["meta"].is_null() {
            return Err(XrpError::TransactionNotFound);
        }

        // txn processed
        if response["result"]["meta"]["TransactionResult"].as_str().unwrap_or("Unknown error") != "tesSUCCESS" {
            let result = response["result"]["meta"]["TransactionResult"]
                .as_str()
                .unwrap_or("Unknown error");

            return Err(XrpError::TransactionFailed {
                result: result.to_string(),
                message: "Unknown error".to_string(),
            });
        }

        Ok(response)
    }
    
    fn wait_for_transaction(&self, tx_hash: &str, timeout_seconds: u64) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        while start_time.elapsed().as_secs() < timeout_seconds {
            match self.confirm_transaction(tx_hash) {
                Ok(_) => {
                    // Transaction succeeded
                    return Ok(());
                }
                Err(XrpError::TransactionNotFound) => {
                    // tx is not accepted yet or dropped
                }
                Err(XrpError::TransactionFailed { result, message }) => {
                    return Err(XrpError::TransactionFailed { result, message });
                }
                Err(e) => {
                    return Err(e);
                }
            }
            
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    
        // Timeout reached, transaction not found
        Err(XrpError::TransactionNotFound)
    }

    fn make_request(&self, params: Value) -> Result<Value> {
        let response = self
            .client
            .post(self.network.api_url())
            .json(&params)
            .send()
            .map_err(|e| XrpError::Network(e))?;

        let result: Value = response.json()?;

        if let Some(error) = result.get("error") {
            return Err(XrpError::ApiError {
                error: error["error"]
                    .as_str()
                    .unwrap_or("Unknown error")
                    .to_string(),
                code: error["error_code"].as_u64().unwrap_or(0) as u32,
            });
        }

        Ok(result)
    }
}
