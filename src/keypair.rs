use ring::{
    digest::{SHA512, digest},
    signature::{Ed25519KeyPair, KeyPair},
};
use ripemd::{Digest, Ripemd160};

enum _Algorithm {
    Ed25519,
    Secp256k1,
}

const _XRPL_SEED_PREFIX: u8 = 0x21;
const _XRPL_ACCT_PUBKEY_PREFIX: u8 = 0x23;
const XRPL_ADDRESS_PREFIX: &[u8] = &[0x00];
const ED_PREFIX: u8 = 0xed;
const ED25519_SECRET_LEN: usize = 23;
const ED25519_SEED_PREFIX: [u8; 3] = [0x01, 0xE1, 0x4B];
const CHECKSUM_LENGTH: usize = 4;
const XRPL_ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// Ed25519 keypair
pub struct KeypairEd25519 {
    raw_private: Vec<u8>,
    raw_public: Vec<u8>,
}

impl KeypairEd25519 {
    pub fn from_secret_str(secret_str: &str) -> Self {
        let seed = decode_ed25519(secret_str, &ED25519_SEED_PREFIX).unwrap();
        let raw_private = sha512_half(&seed).unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&raw_private).unwrap();
        let mut raw_public = key_pair.public_key().as_ref().to_vec();
        raw_public.insert(0, ED_PREFIX);
        Self {
            raw_private,
            raw_public,
        }
    }

    pub fn derive_address(&self) -> String {
        let hash = hash160(&self.raw_public)[..20].to_vec();
        encode_address(&hash)
    }
}

fn sha512_half(secret_bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    Ok(digest(&SHA512, secret_bytes).as_ref()[..32].to_vec())
}

fn calc_checksum(bytes: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    sha256_digest(&sha256_digest(bytes))[..CHECKSUM_LENGTH]
        .try_into()
        .unwrap()
}

fn verify_checksum(input: &[u8], checksum: &[u8]) -> Result<(), &'static str> {
    if calc_checksum(input) == checksum {
        Ok(())
    } else {
        Err("Invalid checksum")
    }
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    digest(&ring::digest::SHA256, data).as_ref().to_vec()
}

fn ripemd160_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().as_slice().into()
}

fn hash160(data: &[u8]) -> Vec<u8> {
    ripemd160_digest(&sha256_digest(data))
}

fn encode_address(public_key_bytes: &[u8]) -> String {
    let bytes: &[u8] = &[XRPL_ADDRESS_PREFIX, public_key_bytes].concat();
    let checked_bytes = &[bytes, &calc_checksum(bytes)].concat();
    let alphabet = bs58::alphabet::Alphabet::new(XRPL_ALPHABET).unwrap();

    bs58::encode(checked_bytes)
        .with_alphabet(&alphabet)
        .into_string()
}

fn decode_ed25519(b58_secret_str: &str, prefix: &[u8]) -> Result<Vec<u8>, &'static str> {
    let alphabet = bs58::alphabet::Alphabet::new(XRPL_ALPHABET).unwrap();

    let mut decoded_bytes = bs58::decode(b58_secret_str)
        .with_alphabet(&alphabet)
        .into_vec()
        .unwrap();

    if !decoded_bytes.starts_with(prefix) {
        return Err("Invalid prefix");
    }
    if decoded_bytes.len() != ED25519_SECRET_LEN {
        return Err("Invalid length");
    }

    let checksum = decoded_bytes.split_off(decoded_bytes.len() - CHECKSUM_LENGTH);
    verify_checksum(&decoded_bytes, &checksum)?;

    Ok(decoded_bytes[prefix.len()..].to_vec()) // correct seed len 16
}
