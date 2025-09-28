use crate::error::Result;
use byteorder::{BigEndian, WriteBytesExt};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::constant::XRPL_ALPHABET;

/// Unsigned single signing transaction prefix
const STX_PREFIX: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

#[derive(Debug)]
struct FieldInfo {
    type_code: u8,
    field_code: u8,
    #[allow(unused)]
    is_vl_encoded: bool,
    is_signing_field: bool,
}

fn load_field_definitions() -> BTreeMap<String, FieldInfo> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "TransactionType".to_string(),
        FieldInfo {
            type_code: 1,
            field_code: 2,
            is_vl_encoded: false,
            is_signing_field: true,
        },
    );
    fields.insert(
        "Account".to_string(),
        FieldInfo {
            type_code: 8,
            field_code: 1,
            is_vl_encoded: true,
            is_signing_field: true,
        },
    );
    fields.insert(
        "Destination".to_string(),
        FieldInfo {
            type_code: 8,
            field_code: 3,
            is_vl_encoded: true,
            is_signing_field: true,
        },
    );
    fields.insert(
        "Amount".to_string(),
        FieldInfo {
            type_code: 6,
            field_code: 1,
            is_vl_encoded: false,
            is_signing_field: true,
        },
    );
    fields.insert(
        "Fee".to_string(),
        FieldInfo {
            type_code: 6,
            field_code: 8,
            is_vl_encoded: false,
            is_signing_field: true,
        },
    );
    fields.insert(
        "Sequence".to_string(),
        FieldInfo {
            type_code: 2,
            field_code: 4,
            is_vl_encoded: false,
            is_signing_field: true,
        },
    );
    fields.insert(
        "LastLedgerSequence".to_string(),
        FieldInfo {
            type_code: 2,
            field_code: 27,
            is_vl_encoded: false,
            is_signing_field: true,
        },
    );
    fields.insert(
        "SigningPubKey".to_string(),
        FieldInfo {
            type_code: 7,
            field_code: 3,
            is_vl_encoded: true,
            is_signing_field: true,
        },
    );
    fields.insert(
        "TxnSignature".to_string(),
        FieldInfo {
            type_code: 7,
            field_code: 4,
            is_vl_encoded: true,
            is_signing_field: false,
        },
    );
    fields
}

fn encode_field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    let mut result = Vec::new();
    if type_code < 16 && field_code < 16 {
        result.push((type_code << 4) | field_code);
    } else if type_code < 16 && field_code >= 16 {
        result.push(type_code << 4);
        result.push(field_code);
    } else if type_code >= 16 && field_code < 16 {
        result.push(field_code);
        result.push(type_code);
    } else {
        result.push(0x00);
        result.push(type_code);
        result.push(field_code);
    }
    result
}

fn encode_variable_length(length: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    if length <= 192 {
        result.push(length as u8);
    } else if length <= 12480 {
        let adjusted = length - 193;
        result.push(193 + (adjusted / 256) as u8);
        result.push((adjusted % 256) as u8);
    } else if length <= 918744 {
        let adjusted = length - 12481;
        result.push(241 + (adjusted / 65536) as u8);
        result.push(((adjusted / 256) % 256) as u8);
        result.push((adjusted % 256) as u8);
    } else {
        return Err("Length exceeds 918744 bytes".into());
    }
    Ok(result)
}

fn encode_account_id(address: &str) -> Result<Vec<u8>> {
    let alphabet = bs58::alphabet::Alphabet::new(XRPL_ALPHABET).unwrap();
    let decoded = bs58::decode(address).with_alphabet(&alphabet).into_vec()?;
    if decoded.len() < 21 || decoded[0] != 0x00 {
        return Err("Invalid XRP address".into());
    }
    let mut result = encode_variable_length(20)?;
    result.extend_from_slice(&decoded[1..21]);
    Ok(result)
}

fn encode_xrp_amount(drops: &str) -> Result<Vec<u8>> {
    let amount = drops.parse::<u64>()?;
    if amount > 100_000_000_000_000_000 {
        return Err("XRP amount exceeds maximum (10^17 drops)".into());
    }
    let mut result = Vec::new();
    let encoded = amount | 0x4000000000000000;
    result.write_u64::<BigEndian>(encoded)?;
    Ok(result)
}

fn encode_token_amount(obj: &Map<String, Value>) -> Result<Vec<u8>> {
    let value_str = obj
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("Invalid token amount: missing value")?;
    let currency = obj
        .get("currency")
        .and_then(|v| v.as_str())
        .ok_or("Invalid token amount: missing currency")?;
    let issuer = obj
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or("Invalid token amount: missing issuer")?;

    // Parse value as f64 and normalize to [10^15, 10^16-1]
    let value_f64 = value_str.parse::<f64>()?;
    if value_f64 <= 0.0 {
        return Err("Token amount must be positive".into());
    }
    let (mantissa, exponent) = normalize_token_amount(value_f64)?;
    let sign_bit = if value_f64 >= 0.0 { 1 } else { 0 };

    // Encode 64-bit amount
    let mut result = Vec::new();
    let amount_field = (1u64 << 63) | // Not XRP bit
                        (sign_bit << 62) | // Sign bit
                        (((exponent as i16 + 97) as u64) << 54) | // Exponent (+97 for unsigned)
                        mantissa; // Mantissa
    result.write_u64::<BigEndian>(amount_field)?;

    // Encode currency code (160 bits)
    result.extend(encode_currency_code(currency)?);

    // Encode issuer AccountID (160 bits, not length-prefixed)
    let issuer_bytes = bs58::decode(issuer)
        .with_alphabet(&bs58::Alphabet::new(XRPL_ALPHABET).unwrap())
        .into_vec()?;
    if issuer_bytes.len() < 21 || issuer_bytes[0] != 0x00 {
        return Err("Invalid issuer address".into());
    }
    result.extend_from_slice(&issuer_bytes[1..21]);

    Ok(result)
}

fn encode_amount(value: &Value) -> Result<Vec<u8>> {
    if let Some(drops) = value.as_str() {
        // XRP amount (string in drops)
        Ok(encode_xrp_amount(drops)?)
    } else if let Some(obj) = value.as_object() {
        // Issued token amount
        Ok(encode_token_amount(&obj)?)
    } else {
        Err("Amount must be a string (XRP) or object (token)".into())
    }
}

fn normalize_token_amount(value: f64) -> Result<(u64, i8)> {
    // Normalize to [10^15, 10^16-1]
    let abs_value = value.abs();
    let mut exponent = 0i8;
    let mut mantissa = abs_value;

    while mantissa >= 10_000_000_000_000_000.0 {
        mantissa /= 10.0;
        exponent += 1;
    }
    while mantissa < 1_000_000_000_000_000.0 && mantissa != 0.0 {
        mantissa *= 10.0;
        exponent -= 1;
    }

    if exponent < -96 || exponent > 80 {
        return Err("Exponent out of range (-96 to 80)".into());
    }

    Ok((mantissa as u64, exponent))
}

fn encode_currency_code(currency: &str) -> Result<Vec<u8>> {
    if currency.len() == 3
        && currency != "XRP"
        && currency
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!@#$%^&*<>(){}[]|?".contains(c))
    {
        // Standard 3-character ISO code
        let mut result = vec![0x00]; // Type code for ISO 4217
        result.extend(vec![0u8; 88 / 8]); // 88-bit reserved
        result.extend(currency.as_bytes()); // 24-bit ASCII
        result.extend(vec![0u8; 40 / 8]); // 40-bit reserved
        Ok(result)
    } else {
        // Non-standard 160-bit currency code (hex)
        let bytes = hex::decode(currency)?;
        if bytes.len() != 20 {
            return Err("Non-standard currency code must be 20 bytes".into());
        }
        if bytes == [0u8; 20]
            || bytes
                == [0u8; 12]
                    .iter()
                    .chain("XRP".as_bytes())
                    .chain(&[0u8; 5])
                    .copied()
                    .collect::<Vec<u8>>()
        {
            return Err("Invalid currency code: reserved for XRP".into());
        }
        Ok(bytes)
    }
}

fn encode_uint16(value: u16) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result.write_u16::<BigEndian>(value)?;
    Ok(result)
}

fn encode_uint32(value: u32) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result.write_u32::<BigEndian>(value)?;
    Ok(result)
}

fn encode_blob(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex)?;
    let mut result = encode_variable_length(bytes.len())?;
    result.extend_from_slice(&bytes);
    Ok(result)
}

pub fn encode_transaction(tx_json: &Value, is_signed: bool) -> Result<Vec<u8>> {
    let fields_def = load_field_definitions();
    let mut fields: Vec<(u8, u8, Vec<u8>)> = Vec::new();
    let tx_types = BTreeMap::from([("Payment".to_string(), 0u16)]);

    for (field_name, value) in tx_json.as_object().ok_or("Invalid JSON object")?.iter() {
        let field_info = fields_def
            .get(field_name)
            .ok_or(format!("Unknown field: {}", field_name))?;
        if !field_info.is_signing_field && !is_signed {
            continue;
        }

        let encoded = match field_name.as_str() {
            "TransactionType" => {
                let tx_type = value.as_str().ok_or("TransactionType must be a string")?;
                let tx_code = *tx_types.get(tx_type).ok_or("Unknown TransactionType")?;
                encode_uint16(tx_code)?
            }
            "Account" | "Destination" => encode_account_id(
                value
                    .as_str()
                    .ok_or("Account/Destination must be a string")?,
            )?,
            "Amount" | "Fee" => encode_amount(value)?,
            "Sequence" | "LastLedgerSequence" => encode_uint32(
                value
                    .as_u64()
                    .ok_or("Sequence/LastLedgerSequence must be a number")? as u32,
            )?,
            "SigningPubKey" => {
                encode_blob(value.as_str().ok_or("SigningPubKey must be a hex string")?)?
            }
            "TxnSignature" => {
                encode_blob(value.as_str().ok_or("TxnSignature must be a hex string")?)?
            }
            _ => return Err(format!("Unsupported field: {}", field_name).into()),
        };

        fields.push((field_info.type_code, field_info.field_code, encoded));
    }

    fields.sort_by_key(|(type_code, field_code, _)| (*type_code, *field_code));
    let mut result = Vec::new();
    for (type_code, field_code, data) in fields {
        result.extend(encode_field_id(type_code, field_code));
        result.extend(data);
    }

    if !is_signed {
        result = [STX_PREFIX.to_vec(), result].concat();
    }
    Ok(result)
}
