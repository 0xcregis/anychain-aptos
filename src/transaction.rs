use crate::utils::DEFAULT_DERIVE_PATH_APTOS;
use crate::{AptosAddress, AptosFormat, AptosPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use aptos_sdk::{
    move_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{ModuleId, TypeTag},
    },
    transaction_builder::TransactionBuilder,
    types::chain_id::ChainId,
    types::transaction::{EntryFunction, TransactionPayload},
    types::LocalAccount,
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt, str::FromStr};

const _NAMED_CHAIN_MAINNET: u8 = 1;
const NAME_CHAIN_TESTNET: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AptosTransactionParameters {
    pub from: AptosAddress,
    pub to: AptosAddress,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AptosTransaction {
    pub params: AptosTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AptosTransactionId {}

impl fmt::Display for AptosTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0xtxid")
    }
}

impl TransactionId for AptosTransactionId {}

impl Transaction for AptosTransaction {
    type Address = AptosAddress;
    type Format = AptosFormat;
    type PublicKey = AptosPublicKey;
    type TransactionId = AptosTransactionId;
    type TransactionParameters = AptosTransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(AptosTransaction {
            params: params.clone(),
            signature: None,
        })
    }

    fn sign(&mut self, _rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

impl AptosTransaction {
    pub fn to_signed_txn(&self, mnemonic: &str) -> Result<Vec<u8>, TransactionError> {
        let amount: u64 = 1_000;
        let options = aptos_sdk::coin_client::TransferOptions::default();
        let transaction_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()),
                Identifier::new("transfer").unwrap(),
                vec![TypeTag::from_str(options.coin_type).unwrap()],
                vec![
                    bcs::to_bytes(&self.params.to.0).unwrap(),
                    bcs::to_bytes(&amount).unwrap(),
                ],
            )),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + options.timeout_secs,
            ChainId::new(NAME_CHAIN_TESTNET),
        )
        .sender(self.params.from.0)
        .max_gas_amount(options.max_gas_amount)
        .gas_unit_price(options.gas_unit_price);

        let from_local_account =
            LocalAccount::from_derive_path(DEFAULT_DERIVE_PATH_APTOS, mnemonic, 0).unwrap();
        let signed_txn = from_local_account.sign_with_transaction_builder(transaction_builder);

        let txn_payload = bcs::to_bytes(&signed_txn)
            .map_err(|_| TransactionError::Message("Serialization Error".to_string()))?;
        Ok(txn_payload)
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        utils::{from_derive_path, DEFAULT_DERIVE_PATH_APTOS},
        AptosFormat, AptosPublicKey, AptosTransaction, AptosTransactionParameters,
    };
    use anychain_core::PublicKey;
    #[test]
    fn test_aptos_transaction() {
        let mnemonic_alice =
            "provide stem law exchange laptop prison wrap alone frog skill subway tumble";
        let mnemonic_bob =
            "shoot island position soft burden budget tooth cruel issue economy destroy above";

        let secret_key_alice = from_derive_path(DEFAULT_DERIVE_PATH_APTOS, mnemonic_alice).unwrap();
        let public_key_alice = AptosPublicKey::from_secret_key(&secret_key_alice);
        let address_alice = public_key_alice.to_address(&AptosFormat::Standard).unwrap();

        let secret_key_bob = from_derive_path(DEFAULT_DERIVE_PATH_APTOS, mnemonic_bob).unwrap();
        let public_key_bob = AptosPublicKey::from_secret_key(&secret_key_bob);
        let address_bob = public_key_bob.to_address(&AptosFormat::Standard).unwrap();

        let amount = 1000;
        let params = AptosTransactionParameters {
            from: address_alice,
            to: address_bob,
            amount,
        };
        let tx = AptosTransaction::new(&params).unwrap();
        let txn = tx.to_signed_txn(mnemonic_alice);
        assert!(txn.is_ok());
    }
}
