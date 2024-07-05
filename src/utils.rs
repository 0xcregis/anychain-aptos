use anychain_core::no_std::FromStr;
use anyhow::Result;
use bip39::{Language, Mnemonic, Seed};
use ed25519_dalek::SecretKey;
use ed25519_dalek_bip32::{DerivationPath, ExtendedSecretKey};

pub const DEFAULT_DERIVE_PATH_APTOS: &str = "m/44'/637'/0'/0'/0'";

/// Recover an account from derive path (e.g. m/44'/637'/0'/0'/0') and mnemonic phrase,
pub fn from_derive_path(
    derive_path: &str,
    mnemonic_phrase: &str,
) -> Result<ed25519_dalek::SecretKey> {
    let derive_path = DerivationPath::from_str(derive_path)?;
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    let key = ExtendedSecretKey::from_seed(seed.as_bytes())?
        .derive(&derive_path)?
        .secret_key;
    let key = SecretKey::from_bytes(&key.to_bytes())?;
    Ok(key)
}
