use std::error::Error;

use serde_json::json;

use crate::encode_tx;
use crate::keypair;
use crate::xrp_api;

use xrp_api::SubmitTransactionResponse;


const LEDGER_SEQUENCE_DEADLINE_OFFSET: u64 = 100;


fn autofill_tx(tx: &mut serde_json::Value) -> Result<(), Box<dyn Error>> {
    if !tx.as_object().unwrap().contains_key("Sequence") {
        let account_address = tx["Account"].as_str().ok_or("Account must be a string")?;
        let account_info_response = xrp_api::get_account_info(account_address)?;
        let account_info = account_info_response.result.account_data;
        tx["Sequence"] = json!(account_info.sequence);
    }
    if !tx.as_object().unwrap().contains_key("LastLedgerSequence") {
        let last_ledger_sequence_response = xrp_api::get_last_ledger_sequence()?;
        let last_ledger_sequence = last_ledger_sequence_response.result.ledger_index;
        tx["LastLedgerSequence"] = json!(last_ledger_sequence+LEDGER_SEQUENCE_DEADLINE_OFFSET);
    }
    Ok(())
}

fn get_send_drops_tx(
    signing_public_key: &str,
    source_address: &str,
    destination_address: &str,
    amount_drops: &str,
) -> serde_json::Value {
    json!({
        "TransactionType" : "Payment",
        "Account" : source_address,
        "Destination" : destination_address,
        "Amount" : amount_drops,
        "SigningPubKey": signing_public_key,
        "Fee": "1000",
    })
}

fn get_send_token_tx(
    signing_public_key: &str,
    source_address: &str,
    destination_address: &str,
    amount_token: &str,
    currency: &str,
    issuer: &str,
) -> serde_json::Value {
    json!({
        "TransactionType" : "Payment",
        "Account" : source_address,
        "Destination" : destination_address,
        "Amount" : json!({
            "currency": currency,
            "issuer": issuer,
            "value": amount_token,
        }),
        "SigningPubKey": signing_public_key,
        "Fee": "1000",
    })
}

fn send_tx(keypair: &keypair::Keypair, tx: &mut serde_json::Value, simulate: bool) -> Result<SubmitTransactionResponse, Box<dyn Error>> {
    autofill_tx(tx)?;

    let tx_blob = encode_tx::encode_transaction(&tx, false)?;

    if simulate {
        xrp_api::simulate_transaction(&tx)?;
    }

    let txn_signature = keypair.sign(&tx_blob);
    tx["TxnSignature"] = json!(hex::encode_upper(&txn_signature));

    let signed_tx_blob = encode_tx::encode_transaction(&tx, true)?;

    let submitted_tx = xrp_api::submit_transaction(&hex::encode(&signed_tx_blob))?;

    Ok(submitted_tx)
}

/// Send XRP to destination address
pub fn send_xrp(keypair: &keypair::Keypair, destination_address: &str, amount_xrp: f64, simulate: bool) -> Result<SubmitTransactionResponse, Box<dyn Error>> {
    let amount_drops = (amount_xrp * 1_000_000.0) as u64;

    let mut tx = get_send_drops_tx(
        &keypair.public_key_str(),
        &keypair.derive_address(),
        destination_address,
        &amount_drops.to_string(),
    );

    send_tx(keypair, &mut tx, simulate)
}

/// Send token to destination address
/// - Trust line must be established between receiver and sender
pub fn send_token(
    keypair: &keypair::Keypair,
    destination_address: &str,
    amount_token: &str,
    currency: &str,
    issuer: &str,
    simulate: bool
) -> Result<SubmitTransactionResponse, Box<dyn Error>> {
    let mut tx = get_send_token_tx(
        &keypair.public_key_str(),
        &keypair.derive_address(),
        destination_address,
        &amount_token.to_string(),
        currency,
        issuer,
    );

    send_tx(keypair, &mut tx, simulate)
}
