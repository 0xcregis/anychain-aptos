# anychain-aptos

anychain-aptos is a Rust library that provides a simple and unified interface for interacting with the Aptos
blockchain.

## Features

- **Transaction Processing**: Functionality to create, sign, and broadcast transactions on the Aptos network
- **Integration with Aptos RPC API**: Interact with the Aptos RPC API for querying account information, transaction
  details, etc.
- **Wallet Management**: Creating and managing Aptos wallets, including keypair
  generation, public/private key management, etc.

## Installation

Add the following to your Cargo.toml file:

```toml
[dependencies]
anychain-aptos= "0.1.0"
```

Then, run cargo build to download and compile the library.

## Usage

```shell
cargo run --example transfer-coin
```

## License

anychain-aptos released under the MIT License. See the [LICENSE](LICENSE) file for more information. 