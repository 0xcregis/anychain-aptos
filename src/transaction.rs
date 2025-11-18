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
use core::convert::TryFrom;
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

        let signature_result = Ed25519Signature::try_from(rs.as_slice());
        if signature_result.is_err() {
            return Err(TransactionError::Message("Invalid signature".to_string()));
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
    use ed25519_dalek::{
        Signature, SigningKey, VerifyingKey,
        hazmat::{self, ExpandedSecretKey},
    };
    use sha2::Sha512;

    #[test]
    fn test_tx_gen() {
        let sk_from = [
            215u8, 129, 55, 157, 41, 22, 63, 25, 208, 37, 28, 225, 115, 237, 181, 127, 45, 91, 21,
            61, 35, 74, 12, 13, 7, 157, 236, 54, 1, 30, 95, 139,
        ];
        // let sk_from = SecretKey::try_from(sk_from.as_slice()).unwrap();
        let sk_from: SigningKey = SigningKey::from_bytes(&sk_from);
        let pk_from = sk_from.verifying_key();
        let pk = pk_from.as_bytes().to_vec();
        let pk_from = AptosPublicKey(pk_from);
        let from = AptosAddress::from_public_key(&pk_from, &AptosFormat::Standard).unwrap();

        let sk_to = [
            75u8, 175, 15, 72, 84, 215, 15, 161, 201, 20, 205, 106, 226, 255, 251, 29, 13, 48, 213,
            30, 74, 50, 4, 137, 1, 208, 193, 201, 80, 21, 36, 244,
        ];
        // let sk_to = SecretKey::from_bytes(sk_to.as_slice()).unwrap();
        let sk_to: SigningKey = SigningKey::from_bytes(&sk_to);
        let pk_to = sk_to.verifying_key();
        let pk_to = AptosPublicKey(pk_to);
        let to = AptosAddress::from_public_key(&pk_to, &AptosFormat::Standard).unwrap();

        println!("from: {from}\nto: {to}");
        // from = 0xae5c0eb553f446267cafa1df9f635e8bc3bcc35611efb27754061f2255ee0784
        // to = 0xfd34ef79e24c375d135d3f0a289dffe3d2be17756db621f031d9c0e1efa7355f

        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now: u64 = 1763479230;

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

        let sk_from_clone = [
            215u8, 129, 55, 157, 41, 22, 63, 25, 208, 37, 28, 225, 115, 237, 181, 127, 45, 91, 21,
            61, 35, 74, 12, 13, 7, 157, 236, 54, 1, 30, 95, 139,
        ];
        let secret = ed25519_dalek::SecretKey::from(sk_from_clone);
        let xsk: ed25519_dalek::hazmat::ExpandedSecretKey = ExpandedSecretKey::from(&secret);
        let pk_here = VerifyingKey::from(&xsk);
        let _sig: Signature = hazmat::raw_sign::<Sha512>(&xsk, &msg, &pk_here);
        // let xsk = ExpandedSecretKey::from(&sk_from);
        // let sig = xsk.sign(&msg, &pk_from.0);
        // let sig = sig.to_bytes().to_vec();

        {
            let fake_sig: Vec<u8> = [
                9, 13, 152, 114, 226, 191, 19, 231, 14, 222, 192, 71, 85, 43, 69, 58, 254, 240,
                207, 172, 178, 202, 55, 51, 112, 197, 37, 227, 220, 114, 75, 5, 150, 121, 179, 114,
                249, 5, 153, 1, 232, 253, 248, 171, 75, 127, 44, 203, 157, 110, 248, 36, 160, 101,
                165, 186, 156, 208, 108, 111, 130, 82, 26, 41,
            ]
            .into();
            // let mut fake_sig: Vec<u8> = [0u8; 64].into();
            // dbg!(fake_sig.clone());
            // rand::thread_rng().fill(&mut fake_sig[..]);
            // dbg!(fake_sig.clone());

            let fake_tx = tx.sign(fake_sig, 0);
            assert!(fake_tx.is_err());
        }

        let signed_tx = tx.sign(_sig.to_vec(), 0);
        assert!(signed_tx.is_ok());
        // let signed_tx = tx.sign_ed25519(signature.to_bytes().to_vec()).unwrap();
        // let tx = tx.sign(sig, 0).unwrap();
        let signed_tx = signed_tx.unwrap();
        let expetced_tx: Vec<u8> = [
            174, 92, 14, 181, 83, 244, 70, 38, 124, 175, 161, 223, 159, 99, 94, 139, 195, 188, 195,
            86, 17, 239, 178, 119, 84, 6, 31, 34, 85, 238, 7, 132, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 13, 97, 112, 116, 111, 115, 95, 97, 99, 99, 111, 117, 110, 116, 30, 98, 97, 116, 99,
            104, 95, 116, 114, 97, 110, 115, 102, 101, 114, 95, 102, 117, 110, 103, 105, 98, 108,
            101, 95, 97, 115, 115, 101, 116, 115, 0, 3, 32, 105, 9, 31, 186, 181, 247, 214, 53,
            238, 122, 197, 9, 140, 240, 193, 239, 190, 49, 214, 143, 236, 15, 44, 213, 101, 232,
            209, 104, 218, 245, 40, 50, 33, 1, 253, 52, 239, 121, 226, 76, 55, 93, 19, 93, 63, 10,
            40, 157, 255, 227, 210, 190, 23, 117, 109, 182, 33, 240, 49, 217, 192, 225, 239, 167,
            53, 95, 9, 1, 128, 150, 152, 0, 0, 0, 0, 0, 136, 19, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 0,
            0, 0, 0, 250, 142, 28, 105, 0, 0, 0, 0, 2, 0, 32, 25, 87, 201, 60, 254, 75, 77, 177,
            156, 131, 137, 141, 80, 241, 172, 86, 115, 194, 245, 200, 117, 16, 236, 152, 139, 210,
            235, 208, 18, 236, 109, 80, 64, 251, 211, 156, 203, 4, 19, 198, 194, 175, 155, 191, 74,
            38, 197, 218, 115, 122, 149, 164, 239, 42, 165, 44, 154, 106, 57, 61, 18, 149, 139,
            212, 241, 55, 53, 195, 8, 173, 71, 97, 160, 180, 148, 235, 59, 214, 204, 72, 218, 87,
            171, 152, 199, 163, 231, 116, 251, 154, 172, 145, 72, 38, 89, 154, 8,
        ]
        .into();

        assert_eq!(signed_tx, expetced_tx);
        // dbg!("{tx:?}", signed_tx.clone());

        let _tx = AptosTransaction::from_bytes(&signed_tx).unwrap();
        dbg!("tx: {tx:?}", _tx);
    }
}
