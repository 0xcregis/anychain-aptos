use {
    crate::{format::AptosFormat, public_key::AptosPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    aptos_sdk::move_types::account_address::AccountAddress,
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    curve25519_dalek::Scalar,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AptosAddress(pub(crate) AccountAddress);

impl Address for AptosAddress {
    type SecretKey = Scalar;
    type Format = AptosFormat;
    type PublicKey = AptosPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        public_key.to_address(&AptosFormat::Standard)
    }
}

impl FromStr for AptosAddress {
    type Err = AddressError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let addr = AccountAddress::from_str(addr)
            .map_err(|e| AddressError::InvalidAddress(e.to_string()))?;
        Ok(AptosAddress(addr))
    }
}

impl Display for AptosAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use super::AptosAddress;
    // use crate::AptosFormat;
    // use crate::public_key::AptosPublicKey;
    // use anychain_core::Address;
    // use aptos_sdk::types::account_address::AccountAddress;
    // use core::str::FromStr;

    const SAMPLE_ED25519_ADDRESS: &str =
        "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30";

    #[test]
    fn test_address_from_public_key() {
        // Define a public key string.
        let pubkey_str = "ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c";
        // Convert the string to an `AptosPublicKey` instance
        let pubkey_res = AptosPublicKey::from_str(pubkey_str);
        assert!(pubkey_res.is_ok());
        let pubkey = pubkey_res.unwrap();
        // Attempt to create an `AptosAddress` from the `AptosPublicKey` using the standard format.
        let address = AptosAddress::from_public_key(&pubkey, &AptosFormat::Standard);

        assert!(address.is_ok());

        let address = address.unwrap();
        assert_eq!(SAMPLE_ED25519_ADDRESS, address.to_string());
    }

    #[test]
    fn test_address_from_str() {
        // Attempt to create an `AptosAddress` from a string representation.
        let address = AptosAddress::from_str(SAMPLE_ED25519_ADDRESS);
        assert!(address.is_ok());
        assert_eq!(SAMPLE_ED25519_ADDRESS, address.unwrap().to_string());
    }

    #[test]
    fn test_aptos_address_display() {
        let addr = AptosAddress(AccountAddress::new([1u8; 32]));

        assert_eq!(addr.to_string(), format!("0x{}", hex::encode([1u8; 32])));
        assert_eq!(addr.to_string().len(), 66);
    }

    #[test]
    fn test_aptos_address_from_str_with_0x() {
        let raw = [1u8; 32];
        let s = format!("0x{}", hex::encode(raw));

        let addr = s.parse::<AptosAddress>().unwrap();

        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn test_aptos_address_from_str_without_0x() {
        let raw = [2u8; 32];
        let s = hex::encode(raw);

        let addr = s.parse::<AptosAddress>().unwrap();

        assert_eq!(addr.to_string(), format!("0x{}", s));
    }

    #[test]
    fn test_aptos_address_from_str_invalid_length_error() {
        // let err = "0x1234".parse::<AptosAddress>().unwrap_err();
        let _err = "0x1234".parse::<AptosAddress>();
        dbg!(_err);

        // assert!(matches!(err, AddressError::InvalidCharacterLength(4)));
    }

    #[test]
    fn test_aptos_address_from_public_key() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = AptosPublicKey::from_secret_key(&sk);

        let addr = AptosAddress::from_public_key(&pk, &AptosFormat::Standard).unwrap();

        assert_eq!(addr.to_string().len(), 66);
        assert!(addr.to_string().starts_with("0x"));
    }

    #[test]
    fn test_aptos_address_from_secret_key_matches_public_key() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);

        let pk = AptosPublicKey::from_secret_key(&sk);
        let addr_from_pk = AptosAddress::from_public_key(&pk, &AptosFormat::Standard).unwrap();
        let addr_from_sk = AptosAddress::from_secret_key(&sk, &AptosFormat::Standard).unwrap();

        assert_eq!(addr_from_sk, addr_from_pk);
    }

    #[test]
    fn test_aptos_address_to_raw() {
        let raw = [3u8; 32];
        let _addr = AptosAddress(AccountAddress::new(raw));

        // TODO:: test to_raw
        // let aptos_addr = addr.to_raw().unwrap();

        // assert_eq!(aptos_addr.to_string(), addr.to_string());
    }

    #[test]
    fn test_aptos_address_known_vector() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);

        let addr = AptosAddress::from_secret_key(&sk, &AptosFormat::Standard).unwrap();

        assert_eq!(
            addr.to_string(),
            "0x335037e0300fa5b9ee242b6a61e065cd500e780362e231762885ea71f07b28d9"
        );
    }

    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;

    const SEED_ALICE: [u8; 32] = [1u8; 32];
    const SEED_BOB: [u8; 32] = [2u8; 32];

    const SCALAR_BYTES_SEED_ALICE: [u8; 32] = [
        202, 240, 171, 205, 215, 167, 224, 27, 59, 98, 120, 15, 54, 14, 189, 47, 174, 26, 23, 3,
        82, 134, 81, 182, 155, 193, 118, 192, 136, 190, 243, 14,
    ];

    const SCALAR_BYTES_SEED_BOB: [u8; 32] = [
        244, 236, 138, 247, 95, 55, 67, 44, 199, 164, 153, 95, 55, 238, 52, 98, 10, 196, 14, 137,
        134, 199, 135, 147, 219, 29, 78, 243, 105, 252, 161, 14,
    ];

    const ADDRESS_ALICE: &str =
        "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd";
    const ADDRESS_BOB: &str = "0x7d9947d5ce9efdd02bb88c44cf2f941c829ed5ac483090a6ba22c12db9251c41";
    #[test]
    fn test_signing_key_to_scalar_match() {
        // SigningKey -> Scalar
        let sk = SigningKey::from_bytes(&SEED_ALICE);
        let scalar = sk.to_scalar();

        // Scalar from bytes
        // Scalar::from_bytes_mod_order();

        // Alice
        assert_eq!(scalar.to_bytes(), SCALAR_BYTES_SEED_ALICE);
        let addr = AptosAddress::from_secret_key(&scalar, &AptosFormat::Standard).unwrap();
        assert_eq!(addr.to_string(), ADDRESS_ALICE);

        let sk = SigningKey::from_bytes(&SEED_BOB);
        let scalar = sk.to_scalar();

        // Bob
        assert_eq!(scalar.to_bytes(), SCALAR_BYTES_SEED_BOB);
        let addr = AptosAddress::from_secret_key(&scalar, &AptosFormat::Standard).unwrap();
        assert_eq!(addr.to_string(), ADDRESS_BOB);
    }
}
