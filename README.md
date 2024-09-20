# Monero Wallet Address Generator

This Rust project allows you to generate Monero wallet addresses from 25-word seed phrases and private keys using the `curve25519-dalek` and `base58-monero` libraries. It only supports both mainnet and stagenet **Standard** addresses by specifying the network type.

## Features

- **Generate a 25-word Monero seed phrase** using cryptographically secure entropy.
- **Convert a 25-word Monero seed phrase** into private spend and view keys.
- **Derive a Monero address** from the seed phrase for both **mainnet** and **stagenet**.
- Use **Ed25519 elliptic curve cryptography** for key derivation.
- Supports different network prefixes for Monero mainnet and stagenet networks.

## Usage

You can generate a new Monero address by either using random entropy to generate a seed or by providing an existing 25-word seed phrase.

### Generate a New Monero Address

To generate a new Monero address along with a 25-word seed phrase:

```rust
use monero_wallet_generator::{Seed, Network, MainNet};

fn main() {
    let seed = Seed::generate();  // Generate a new seed
    let address = seed.get_address::<MainNet>();  // Generate address for mainnet
    
    println!("Seed words: {}", seed.to_string());
    println!("Monero Address: {}", address);
}
```

### Generate Address from Existing Seed Words

You can derive a Monero address from an existing 25-word seed phrase:

```rust
use monero_wallet_generator::{Seed, MainNet};

fn main() {
    let seed_words = "razor obnoxious entrance inroads saxophone among onward revamp scoop boxes point fawns rigid army badge icing frying voted biggest layout dehydrate acidic reinvest school inroads";
    let seed = Seed::from_seed_words(seed_words).unwrap();  // Restore from seed words
    let address = seed.get_address::<MainNet>().unwrap();  // Generate mainnet address
    
    println!("Recovered Address: {}", address);
}
```

### Specify Network (MainNet or Stagenet)

To generate or restore an address for stagenet instead of mainnet, you can specify the network type:

```rust
use monero_wallet_generator::{Seed, Stagenet};

fn main() {
    let seed_words = "razor obnoxious entrance inroads saxophone among onward revamp scoop boxes point fawns rigid army badge icing frying voted biggest layout dehydrate acidic reinvest school inroads";
    let seed = Seed::from_seed_words(seed_words).unwrap();
    let address = seed.get_address::<Stagenet>().unwrap();
    
    println!("Recovered Address (Stagenet): {}", address);
}
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## Acknowledgments

- Thanks to the Monero project for its open-source cryptography libraries.
- Built using `curve25519-dalek` and `base58-monero` libraries.