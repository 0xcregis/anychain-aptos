use crate::{AptosAddress, AptosFormat, AptosPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use aptos_sdk::{
    crypto::{
        ed25519::{Ed25519PublicKey, Ed25519Signature},
        traits::signing_message,
    },
    move_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{ModuleId, TypeTag},
    },
    types::{
        chain_id::ChainId,
        transaction::SignedTransaction,
        transaction::{EntryFunction, RawTransaction, TransactionPayload},
    },
};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AptosTransactionParameters {
    pub from: AptosAddress,
    pub to: AptosAddress,
    pub amount: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub network: u8,
    pub now: u64, // seconds
    pub public_key: Vec<u8>,
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

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let raw_tx = self.build_raw_tx()?;
        match &self.signature {
            Some(sig) => {
                let pk = self.params.public_key.as_slice();
                let pk = Ed25519PublicKey::try_from(pk)
                    .map_err(|_| TransactionError::Message("crypto error".to_string()))?;
                let sig = Ed25519Signature::try_from(sig.as_slice())
                    .map_err(|_| TransactionError::Message("crypto error".to_string()))?;
                let signed_tx = SignedTransaction::new(raw_tx, pk, sig);
                let signed_tx = bcs::to_bytes(&signed_tx)
                    .map_err(|_| TransactionError::Message("Serialization Error".to_string()))?;
                Ok(signed_tx)
            }
            None => signing_message(&raw_tx)
                .map_err(|_| TransactionError::Message("aptos crypto error".to_string())),
        }
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

impl AptosTransaction {
    pub fn build_raw_tx(&self) -> Result<RawTransaction, TransactionError> {
        let module_name =
            Identifier::new("coin").map_err(|e| TransactionError::Message(e.to_string()))?;
        let function =
            Identifier::new("transfer").map_err(|e| TransactionError::Message(e.to_string()))?;
        let type_tag = TypeTag::from_str("0x1::aptos_coin::AptosCoin")
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let to = bcs::to_bytes(&self.params.to.0)
            .map_err(|_| TransactionError::Message("bcs error".to_string()))?;
        let amount = bcs::to_bytes(&self.params.amount)
            .map_err(|_| TransactionError::Message("bcs error".to_string()))?;
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, module_name),
            function,
            vec![type_tag],
            vec![to, amount],
        ));
        let chain_id = ChainId::new(self.params.network);
        let expiration = self.params.now + 10;

        Ok(RawTransaction::new(
            self.params.from.0,
            self.params.nonce,
            payload,
            self.params.gas_limit,
            self.params.gas_price,
            expiration,
            chain_id,
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_tx_gen() {}
}
