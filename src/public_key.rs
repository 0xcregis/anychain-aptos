use {
    crate::{address::AptosAddress, format::AptosFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError, hex},
    aptos_sdk::types::AccountAddress,
    core::{fmt, str::FromStr},
    curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE as G},
    group::GroupEncoding,
    sha3::{Digest, Sha3_256},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosPublicKey(pub ed25519_dalek::VerifyingKey);

pub const MAX_HEX_LEN: usize = 64;

impl PublicKey for AptosPublicKey {
    type SecretKey = Scalar;
    type Address = AptosAddress;
    type Format = AptosFormat;

    /// Constructs an `AptosPublicKey` from an Ed25519 SecretKey
    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let pk = secret_key * G;
        let pk = pk.to_bytes();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        Self(pk)
    }

    fn to_address(&self, _format: &Self::Format) -> Result<Self::Address, AddressError> {
        let mut hasher = Sha3_256::new();
        hasher.update(self.0.as_bytes());
        hasher.update([0u8]); // Ed25519 single-key scheme identifier
        let hash = hasher.finalize();

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);

        Ok(AptosAddress(AccountAddress::new(addr)))
    }
}

impl FromStr for AptosPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != MAX_HEX_LEN {
            return Err(PublicKeyError::InvalidByteLength(s.len()));
        }
        let bin = hex::decode(s)?;
        let verifying_key = ed25519_dalek::VerifyingKey::try_from(bin.as_slice())
            .map_err(|error| PublicKeyError::Crate("hex", format!("{error:?}")))?;
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

    const SCALAR_BYTES_SEED_ALICE: [u8; 32] = [
        202, 240, 171, 205, 215, 167, 224, 27, 59, 98, 120, 15, 54, 14, 189, 47, 174, 26, 23, 3,
        82, 134, 81, 182, 155, 193, 118, 192, 136, 190, 243, 14,
    ];

    const SCALAR_BYTES_SEED_BOB: [u8; 32] = [
        244, 236, 138, 247, 95, 55, 67, 44, 199, 164, 153, 95, 55, 238, 52, 98, 10, 196, 14, 137,
        134, 199, 135, 147, 219, 29, 78, 243, 105, 252, 161, 14,
    ];

    #[test]
    fn test_invalid_public_key_cwe248() {
        // Typically, callers should avoid using unwrap() here;
        // instead, they should assert that the Result is not Err, then unwrap
        let res = AptosPublicKey::from_str("deadbeef");
        assert!(res.is_err());
    }

    #[test]
    fn test_from_secret_key_0x01_0x02() {
        let secret_key = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_ALICE);
        let public_key = AptosPublicKey::from_secret_key(&secret_key);

        assert_eq!(
            "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd",
            public_key.to_string()
        );

        let secret_key = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_BOB);
        let public_key = AptosPublicKey::from_secret_key(&secret_key);

        assert_eq!(
            "0x7d9947d5ce9efdd02bb88c44cf2f941c829ed5ac483090a6ba22c12db9251c41",
            public_key.to_string()
        )
    }

    #[test]
    fn test_public_key_to_address() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = AptosPublicKey::from_secret_key(&sk);

        let addr1 = pk.to_address(&AptosFormat::Standard).unwrap();
        let addr2 = AptosAddress::from_public_key(&pk, &AptosFormat::Standard).unwrap();

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_public_key_known_vector() {
        let sk = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_ALICE);
        let pk = AptosPublicKey::from_secret_key(&sk);
        let addr = pk.to_address(&AptosFormat::Standard).unwrap();

        assert_eq!(
            pk.to_string(),
            "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd"
        );
        assert_eq!(
            addr.to_string(),
            "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd"
        );
    }

    #[test]
    fn test_public_key_eq_and_clone() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk1 = AptosPublicKey::from_secret_key(&sk);
        let pk2 = pk1.clone();

        assert_eq!(pk1, pk2);
    }
}
