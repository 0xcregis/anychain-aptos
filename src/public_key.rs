use {
    crate::{address::AptosAddress, format::AptosFormat},
    anychain_core::{AddressError, PublicKey, PublicKeyError, hex},
    aptos_sdk::{
        crypto::ed25519::Ed25519PublicKey, types::transaction::authenticator::AuthenticationKey,
    },
    core::{fmt, str::FromStr},
    curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE as G},
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosPublicKey(pub ed25519_dalek::PublicKey);

pub const MAX_HEX_LEN: usize = 64;

impl PublicKey for AptosPublicKey {
    type SecretKey = Scalar;
    type Address = AptosAddress;
    type Format = AptosFormat;

    /// Constructs an `AptosPublicKey` from an Ed25519 SecretKey
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let pk = secret_key * G;
        let pk = pk.to_bytes();
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk).unwrap();
        Self(pk)
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        let pk = Ed25519PublicKey::try_from(self.0.as_ref()).unwrap(); // self.0 is of type ed25519_dalek::PublicKey
        let pk = AuthenticationKey::ed25519(&pk);
        let address = pk.account_address();
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
            .map_err(|error| PublicKeyError::Crate("hex", format!("{error:?}")))?;
        Ok(AptosPublicKey(verifying_key))
    }
}

impl fmt::Display for AptosPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_address(&AptosFormat::Standard).unwrap())
    }
}
