use anychain_aptos::{
    utils::{from_derive_path, DEFAULT_DERIVE_PATH_APTOS},
    AptosFormat, AptosPublicKey,
};
use anychain_core::public_key::PublicKey;
use anyhow::{Context, Result};
use aptos_sdk::{
    coin_client::CoinClient,
    move_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{ModuleId, TypeTag},
    },
    rest_client::Client,
    transaction_builder::TransactionBuilder,
    types::chain_id::ChainId,
    types::chain_id::NamedChain,
    types::transaction::{EntryFunction, TransactionPayload},
    types::LocalAccount,
};
use once_cell::sync::Lazy;
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

// Testnet https://faucet.testnet.aptoslabs.com
// Devnet https://faucet.devnet.aptoslabs.com
static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_NODE_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://fullnode.testnet.aptoslabs.com"),
    )
    .unwrap()
});

#[tokio::main]
async fn main() -> Result<()> {
    let rest_client = Client::new(NODE_URL.clone());
    let coin_client = CoinClient::new(&rest_client);

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

    let chain_id_testnet = NamedChain::TESTNET.id();
    assert_eq!(2, chain_id_testnet);
    let chain_id_mainnet = NamedChain::MAINNET.id();
    assert_eq!(1, chain_id_mainnet);

    // Print account addresses.
    println!("\n=== Addresses ===");
    println!("Alice: {}", address_alice);
    println!("Bob: {}", address_bob);

    // Print initial balances.
    println!("\n=== Initial Balances ===");
    println!(
        "Alice: {:?}",
        coin_client
            .get_account_balance(&address_alice.0)
            .await
            .context("Failed to get Alice's account balance")?
    );
    println!(
        "Bob: {:?}",
        coin_client
            .get_account_balance(&address_bob.0)
            .await
            .context("Failed to get Bob's account balance")?
    );

    let amount: u64 = 1_000;
    let options = aptos_sdk::coin_client::TransferOptions::default();
    let transaction_builder = TransactionBuilder::new(
        TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()),
            Identifier::new("transfer").unwrap(),
            vec![TypeTag::from_str(options.coin_type).unwrap()],
            vec![
                bcs::to_bytes(&address_bob.0).unwrap(),
                bcs::to_bytes(&amount).unwrap(),
            ],
        )),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + options.timeout_secs,
        ChainId::new(chain_id_testnet),
    )
    .sender(address_alice.0)
    .max_gas_amount(options.max_gas_amount)
    .gas_unit_price(options.gas_unit_price);

    let alice_local_account =
        LocalAccount::from_derive_path(DEFAULT_DERIVE_PATH_APTOS, mnemonic_alice, 0).unwrap();
    let signed_txn = alice_local_account.sign_with_transaction_builder(transaction_builder);
    let txn_hash = rest_client
        .submit(&signed_txn)
        .await
        .context("Failed to submit transfer transaction")?
        .into_inner();

    rest_client
        .wait_for_transaction(&txn_hash)
        .await
        .context("Failed when waiting for the transfer transaction")?;

    // Print final balances.
    println!("\n=== Final Balances ===");
    println!(
        "Alice: {:?}",
        coin_client
            .get_account_balance(&address_alice.0)
            .await
            .context("Failed to get Alice's account balance")?
    );
    println!(
        "Bob: {:?}",
        coin_client
            .get_account_balance(&address_bob.0)
            .await
            .context("Failed to get Bob's account balance")?
    );

    /*
    === Addresses ===
    Alice: 0x906382a3bda854ffb73ea80e65977f4106cbfa4640c78eae736ae76783377f0b
    Bob: 0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30

    === Initial Balances ===
    Alice: 200000000
    Bob: 10199900

    === Final Balances ===
    Alice: 199998300
    Bob: 10200900
     */

    Ok(())
}
