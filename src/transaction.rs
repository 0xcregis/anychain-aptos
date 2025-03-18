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
            Identifier::new("aptos_account").map_err(|e| TransactionError::Message(e.to_string()))?;
        
        // call "batch_transfer" for APT batch transfer
        // call "batch_transfer<CoinType>" for token batch transfer
        let function =
            Identifier::new("transfer").map_err(|e| TransactionError::Message(e.to_string()))?;
        
        // USDT = "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDT"
        // USDC = "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDC"
        let type_tag = TypeTag::from_str("0x1::aptos_coin::AptosCoin")
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        // use bcs::to_bytes(&vec![account1, account2, ...]) to serialize multiple recipients
        // use bcs::to_bytes(&vec![amount1, amount2, ...]) to serialize multiple amounts
        let to = bcs::to_bytes(&self.params.to.0)
            .map_err(|_| TransactionError::Message("bcs error".to_string()))?;
        let amount = bcs::to_bytes(&self.params.amount)
            .map_err(|_| TransactionError::Message("bcs error".to_string()))?;
        
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, module_name),
            function,
            vec![],
            vec![to, amount],
        ));
        let chain_id = ChainId::new(self.params.network);
        let expiration = self.params.now + 60;

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
    use std::time::{SystemTime, UNIX_EPOCH};

    use anychain_core::{Address, Transaction};
    use rand::{rngs::OsRng, TryRngCore};
    use crate::{AptosAddress, AptosFormat, AptosTransaction, AptosTransactionParameters};
    use ed25519_dalek::{SecretKey, ExpandedSecretKey, Signature};

    #[test]
    fn test_tx_gen() {
        let sk_from = [215u8, 129, 55, 157, 41, 22, 63, 25, 208, 37, 28, 225, 115, 237, 181, 127, 45, 91, 21, 61, 35, 74, 12, 13, 7, 157, 236, 54, 1, 30, 95, 139];
        let sk_from = ed25519_dalek::SecretKey::from_bytes(sk_from.as_slice()).unwrap();
        let from = AptosAddress::from_secret_key(&sk_from, &AptosFormat::Standard).unwrap();

        let pk = ed25519_dalek::PublicKey::from(&sk_from);
        let pk_bytes = pk.as_bytes().to_vec();

        let sk_to = [75u8, 175, 15, 72, 84, 215, 15, 161, 201, 20, 205, 106, 226, 255, 251, 29, 13, 48, 213, 30, 74, 50, 4, 137, 1, 208, 193, 201, 80, 21, 36, 244];
        let sk_to = ed25519_dalek::SecretKey::from_bytes(sk_to.as_slice()).unwrap();
        let to = AptosAddress::from_secret_key(&sk_to, &AptosFormat::Standard).unwrap();

        println!("from: {}\nto: {}", from, to);
        // from = 0xae5c0eb553f446267cafa1df9f635e8bc3bcc35611efb27754061f2255ee0784
        // to = 0xfd34ef79e24c375d135d3f0a289dffe3d2be17756db621f031d9c0e1efa7355f

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let tx = AptosTransactionParameters {
            from,
            to,
            amount: 10000000,
            nonce: 2,
            gas_limit: 5000,
            gas_price: 200,
            network: 2,
            now,
            public_key: pk_bytes,
        };

        let mut tx = AptosTransaction::new(&tx).unwrap();

        let msg = tx.to_bytes().unwrap();

        let xsk = ExpandedSecretKey::from(&sk_from);
        
        let sig = xsk.sign(&msg, &pk);
        let sig = sig.to_bytes().to_vec();

        let tx = tx.sign(sig, 0).unwrap();

        println!("{:?}", tx);
    }
}
