use {
    crate::{address::AptosAddress, format::AptosFormat},
    anychain_core::{hex, AddressError, PublicKey, PublicKeyError},
    aptos_sdk::{
        crypto::ed25519::Ed25519PublicKey, types::transaction::authenticator::AuthenticationKey,
    },
    core::{fmt, str::FromStr},
};

/// Represents a public key in the Aptos blockchain.
///
/// This struct wraps an `ed25519_dalek::PublicKey` and provides functionality
/// for converting it into an `AptosAddress` using the Aptos blockchain's address format.
/// It implements the `PublicKey` trait, allowing it to be used generically within
/// cryptographic operations that are common in blockchain applications.
///
/// # Examples
///
/// Basic usage:
///
/// use anychain_aptos::AptosPublicKey;
/// use std::str::FromStr;
///
/// // Example of creating an `AptosPublicKey` from a hexadecimal string representation.
/// let pubkey_str = "ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c";
/// let aptos_pubkey = AptosPublicKey::from_str(pubkey_str).expect("Invalid public key format");
///
/// // Convert the `AptosPublicKey` to an `AptosAddress`.
/// let address = aptos_pubkey.to_address(&AptosFormat::Standard).expect("Failed to convert to address");
/// println!("Address: {}", address);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosPublicKey(pub(crate) ed25519_dalek::PublicKey);

pub const MAX_HEX_LEN: usize = 64;

impl PublicKey for AptosPublicKey {
    type SecretKey = ed25519_dalek::SecretKey;
    type Address = AptosAddress;
    type Format = AptosFormat;

    /// Constructs an `AptosPublicKey` from an Ed25519 SecretKey
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let secret = ed25519_dalek::SecretKey::from_bytes(secret_key.as_bytes()).unwrap();
        let public: ed25519_dalek::PublicKey = (&secret).into();
        Self(public)
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        let public_ed25519 = Ed25519PublicKey::try_from(self.0.as_ref()).unwrap(); // self.0 is of type ed25519_dalek::PublicKey
        let authentication_key = AuthenticationKey::ed25519(&public_ed25519);
        let address = authentication_key.account_address();
        Ok(AptosAddress(address))
    }
}

impl FromStr for AptosPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != MAX_HEX_LEN {
            return Err(PublicKeyError::InvalidByteLength(s.len()));
        }
        let bin = hex::decode(s)?;
        let verifying_key = ed25519_dalek::PublicKey::from_bytes(bin.as_slice())
            .map_err(|error| PublicKeyError::Crate("hex", format!("{:?}", error)))?;
        Ok(AptosPublicKey(verifying_key))
    }
}

impl fmt::Display for AptosPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_address(&AptosFormat::Standard).unwrap())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{from_derive_path, DEFAULT_DERIVE_PATH_APTOS};
    const SAMPLE_ED25519_ADDRESS: [&str; 2] = [
        "0x906382a3bda854ffb73ea80e65977f4106cbfa4640c78eae736ae76783377f0b",
        "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30",
    ];

    const SAMPLE_MNEMONIC: [&str; 2] = [
        "provide stem law exchange laptop prison wrap alone frog skill subway tumble",
        "shoot island position soft burden budget tooth cruel issue economy destroy above",
    ];

    const _SAMPLE_SEED_0: [u8; 32] = [
        51, 95, 147, 235, 93, 221, 105, 227, 208, 198, 105, 132, 164, 28, 174, 83, 68, 231, 82,
        133, 50, 67, 181, 184, 126, 93, 85, 244, 135, 108, 205, 101,
    ];

    #[test]
    fn test_ed25519_sk_to_addresses() {
        for (index, mnemonic) in SAMPLE_MNEMONIC.iter().enumerate() {
            let secret_key = from_derive_path(DEFAULT_DERIVE_PATH_APTOS, mnemonic).unwrap();
            let public_key = AptosPublicKey::from_secret_key(&secret_key);
            let address = public_key.to_address(&AptosFormat::Standard).unwrap();
            assert_eq!(
                SAMPLE_ED25519_ADDRESS[index],
                address.to_string().as_str(),
                "Address mismatch for mnemonic at index {}: {}",
                index,
                mnemonic
            );
        }
    }

    #[test]
    fn test_ed25519_pk_from_str() {
        // pubkey of 0x079..30
        let pubkey_str = "ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c";
        let public_key = AptosPublicKey::from_str(pubkey_str);
        assert!(public_key.is_ok());
    }
}
