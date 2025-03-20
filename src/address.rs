use {
    crate::{format::AptosFormat, public_key::AptosPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    aptos_sdk::move_types::account_address::AccountAddress,
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// Represents an Aptos blockchain address.
///
/// This struct encapsulates an `AccountAddress` from the Aptos SDK, providing additional
/// functionality for working with Aptos addresses within the context of the `anychain-aptos` library.
/// It implements the `Address` trait, enabling interoperability with different blockchain
/// address formats and key types.
///
/// # Examples
///
/// Creating an `AptosAddress` from a public key:
///
/// use anychain_aptos::{AptosAddress, AptosPublicKey, AptosFormat};
/// use anychain_core::Address;
/// use std::str::FromStr;
///
/// let public_key_str = "your_public_key_here";
/// let pubkey = AptosPublicKey::from_str(public_key_str).unwrap();
/// let aptos_address = AptosAddress::from_public_key(&pubkey, &AptosFormat::Standard);
/// assert!(aptos_address.is_ok());
///
/// Creating an `AptosAddress` from a string representation:
///
/// use anychain_aptos::AptosAddress;
/// use anychain_core::Address;
/// use core::str::FromStr;
///
/// let address_str = "0x1...";
/// let aptos_address = AptosAddress::from_str(address_str);
/// assert!(aptos_address.is_ok());
/// Represents a Solana address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AptosAddress(pub AccountAddress);

impl Address for AptosAddress {
    type SecretKey = ed25519_dalek::SecretKey;
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

    fn is_valid(address: &str) -> bool {
        Self::from_str(address).is_ok()
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
    use super::AptosAddress;
    use crate::public_key::AptosPublicKey;
    use crate::AptosFormat;
    use anychain_core::Address;
    use core::str::FromStr;

    const SAMPLE_ED25519_ADDRESS: &str =
        "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30";

    #[test]
    fn test_address_from_public_key() {
        // Define a public key string.
        let pubkey_str = "ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c";
        // Convert the string to an `AptosPublicKey` instance
        let pubkey = AptosPublicKey::from_str(pubkey_str).unwrap();
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
}
