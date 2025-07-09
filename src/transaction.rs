use crate::{AptosAddress, AptosFormat, AptosPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use aptos_sdk::{
    crypto::{
        ed25519::{Ed25519PublicKey, Ed25519Signature},
        traits::signing_message,
    },
    move_types::{
        account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId,
    },
    types::{
        chain_id::ChainId,
        transaction::{EntryFunction, RawTransaction, SignedTransaction, TransactionPayload},
    },
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    pub inner: AccountAddress,
}

impl Object {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        bcs::to_bytes(self).map_err(|e| TransactionError::Message(e.to_string()))
    }

    pub fn deserialize(stream: &[u8]) -> Result<Self, TransactionError> {
        bcs::from_bytes::<Self>(stream).map_err(|e| TransactionError::Message(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Output {
    pub to: AptosAddress,
    pub amount: u64,
}

impl Output {
    pub fn serialize(outputs: &Vec<Self>) -> Result<(Vec<u8>, Vec<u8>), TransactionError> {
        let mut tos = vec![];
        let mut amounts = vec![];

        for output in outputs {
            tos.push(output.to.0);
            amounts.push(output.amount);
        }

        let tos = bcs::to_bytes(&tos).map_err(|e| TransactionError::Message(e.to_string()))?;
        let amounts =
            bcs::to_bytes(&amounts).map_err(|e| TransactionError::Message(e.to_string()))?;

        Ok((tos, amounts))
    }

    pub fn deserialize(streams: &[Vec<u8>]) -> Result<Vec<Self>, TransactionError> {
        let mut outputs = vec![];

        let tos = &streams[0];
        let amounts = &streams[1];

        let tos = bcs::from_bytes::<Vec<AccountAddress>>(tos)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let amounts = bcs::from_bytes::<Vec<u64>>(amounts)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let len = tos.len();

        if len != amounts.len() {
            return Err(TransactionError::Message(
                "account and balance number mismatch".to_string(),
            ));
        }

        for i in 0..len {
            let to = AptosAddress(tos[i]);
            let amount = amounts[i];
            outputs.push(Output { to, amount });
        }

        Ok(outputs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AptosTransactionParameters {
    pub token: Option<AptosAddress>,
    pub from: AptosAddress,
    pub outputs: Vec<Output>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub network: u8,
    pub now: u64, // seconds
    pub public_key: Vec<u8>,
}

impl AptosTransactionParameters {
    pub fn build_raw_tx(&self) -> Result<RawTransaction, TransactionError> {
        let module = Identifier::new("aptos_account")
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let module = ModuleId::new(AccountAddress::ONE, module);
        let (tos, amounts) = Output::serialize(&self.outputs)?;

        let payload = match &self.token {
            Some(token) => {
                let function = Identifier::new("batch_transfer_fungible_assets")
                    .map_err(|e| TransactionError::Message(e.to_string()))?;

                let token = Object { inner: token.0 }.serialize()?;

                TransactionPayload::EntryFunction(EntryFunction::new(
                    module,
                    function,
                    vec![],
                    vec![token, tos, amounts],
                ))
            }
            None => {
                let function = Identifier::new("batch_transfer")
                    .map_err(|e| TransactionError::Message(e.to_string()))?;

                TransactionPayload::EntryFunction(EntryFunction::new(
                    module,
                    function,
                    vec![],
                    vec![tos, amounts],
                ))
            }
        };

        let chain_id = ChainId::new(self.network);
        let expiration = self.now + 60;

        Ok(RawTransaction::new(
            self.from.0,
            self.nonce,
            payload,
            self.gas_limit,
            self.gas_price,
            expiration,
            chain_id,
        ))
    }
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
        let raw_tx = self.params.build_raw_tx()?;
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

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        let tx = bcs::from_bytes::<SignedTransaction>(stream)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let from = AptosAddress(tx.sender());
        let nonce = tx.sequence_number();
        let network = tx.chain_id().id();
        let gas_limit = tx.max_gas_amount();
        let gas_price = tx.gas_unit_price();

        if let TransactionPayload::EntryFunction(entry) = tx.payload() {
            let args = entry.args().to_vec();
            match args.len() {
                // we are handling an APT transfer
                2 => {
                    let outputs = Output::deserialize(&args)?;

                    Ok(AptosTransaction::new(&AptosTransactionParameters {
                        token: None,
                        from,
                        outputs,
                        nonce,
                        gas_limit,
                        gas_price,
                        network,
                        now: 0,
                        public_key: vec![],
                    })?)
                }
                // we are handling a token transfer
                3 => {
                    let token = Object::deserialize(&args[0])?;
                    let token = Some(AptosAddress(token.inner));
                    let outputs = Output::deserialize(&args[1..])?;

                    Ok(AptosTransaction::new(&AptosTransactionParameters {
                        token,
                        from,
                        outputs,
                        nonce,
                        gas_limit,
                        gas_price,
                        network,
                        now: 0,
                        public_key: vec![],
                    })?)
                }
                _ => Err(TransactionError::Message(
                    "illegal arg number for move call".to_string(),
                )),
            }
        } else {
            Err(TransactionError::Message(
                "deserialization error".to_string(),
            ))
        }
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        AptosAddress, AptosFormat, AptosPublicKey, AptosTransaction, AptosTransactionParameters,
        Output,
    };
    use anychain_core::{Address, Transaction};
    use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};

    #[test]
    fn test_tx_gen() {
        let sk_from = [
            215u8, 129, 55, 157, 41, 22, 63, 25, 208, 37, 28, 225, 115, 237, 181, 127, 45, 91, 21,
            61, 35, 74, 12, 13, 7, 157, 236, 54, 1, 30, 95, 139,
        ];
        let sk_from = SecretKey::from_bytes(sk_from.as_slice()).unwrap();
        let pk_from = PublicKey::from(&sk_from);
        let pk = pk_from.as_bytes().to_vec();
        let pk_from = AptosPublicKey(pk_from);
        let from = AptosAddress::from_public_key(&pk_from, &AptosFormat::Standard).unwrap();

        let sk_to = [
            75u8, 175, 15, 72, 84, 215, 15, 161, 201, 20, 205, 106, 226, 255, 251, 29, 13, 48, 213,
            30, 74, 50, 4, 137, 1, 208, 193, 201, 80, 21, 36, 244,
        ];
        let sk_to = SecretKey::from_bytes(sk_to.as_slice()).unwrap();
        let pk_to = PublicKey::from(&sk_to);
        let pk_to = AptosPublicKey(pk_to);
        let to = AptosAddress::from_public_key(&pk_to, &AptosFormat::Standard).unwrap();

        println!("from: {from}\nto: {to}");
        // from = 0xae5c0eb553f446267cafa1df9f635e8bc3bcc35611efb27754061f2255ee0784
        // to = 0xfd34ef79e24c375d135d3f0a289dffe3d2be17756db621f031d9c0e1efa7355f

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token = AptosAddress::from_str(
            "0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832",
        )
        .unwrap();

        let tx = AptosTransactionParameters {
            token: Some(token),
            from,
            outputs: vec![Output {
                to,
                amount: 10000000,
            }],
            nonce: 4,
            gas_limit: 5000,
            gas_price: 200,
            network: 2,
            now,
            public_key: pk,
        };

        let mut tx = AptosTransaction::new(&tx).unwrap();

        let msg = tx.to_bytes().unwrap();

        let xsk = ExpandedSecretKey::from(&sk_from);

        let sig = xsk.sign(&msg, &pk_from.0);
        let sig = sig.to_bytes().to_vec();

        let tx = tx.sign(sig, 0).unwrap();

        println!("{tx:?}");

        let tx = AptosTransaction::from_bytes(&tx).unwrap();

        println!("tx: {tx:?}");
    }
}
