//  Copyright 2024. The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

mod error;
mod mnemonics;
mod network;

use base58_monero::base58;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use error::Error;
use mnemonics::{find_word_index, ENGLISH};
use network::Network;
use rand::{rngs::OsRng, RngCore};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub struct Seed {
    pub inner: [u8; 32],
    spend_key: PrivateKey,
    view_key: PrivateKey,
}

const TRIM_LENGTH: usize = 3;

#[derive(Debug)]
struct PrivateKey([u8; 32]);
type PublicKey = [u8; 32];

impl PrivateKey {
    pub fn inner(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_public_key(&self) -> PublicKey {
        let private = &Scalar::from_bytes_mod_order(*self.inner());
        let public = private * ED25519_BASEPOINT_TABLE;

        *public.compress().as_bytes()
    }
}

impl Seed {
    pub fn generate() -> Result<(Vec<String>, Self), Error> {
        let entropy = generate_entropy(); // Generate 32 random bytes
        let mut words = Vec::with_capacity(25);
        let length = ENGLISH.len();

        let mut current_bits = String::new();
        let entropy_bits = entropy
            .iter()
            .flat_map(|&b| format!("{:08b}", b).chars().collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // Step 2: Convert entropy to seed words
        for bit in entropy_bits {
            current_bits.push(bit);

            if (words.len() == 23 && current_bits.len() == 3) || (current_bits.len() == 11) {
                let index = usize::from_str_radix(&current_bits, 2).unwrap();
                let word_index = index % length;
                let word = ENGLISH[word_index].to_string();
                words.push(word);
                current_bits.clear();
            }
        }

        if words.len() != 24 {
            return Err(Error::DidntGenerateEnoughWords);
        }

        // Step 3: Calculate the checksum and add the checksum word
        let checksum_hash = keccak256(&entropy);
        let checksum_index = (checksum_hash[0] as usize) % length;
        let checksum_word = ENGLISH[checksum_index].to_string();
        words.push(checksum_word); // Add checksum word

        Ok((words.clone(), Self::from_seed_words(&words)?))
    }

    pub fn from_seed_words(seed_words: &[String]) -> Result<Self, Error> {
        let length = ENGLISH.len();
        let trimmed_words_list = ENGLISH
            .iter()
            .map(|w| w.chars().take(TRIM_LENGTH).collect())
            .collect::<Vec<String>>();
        let mut seed_words = seed_words.to_vec();

        if seed_words.len() != 25 {
            return Err(Error::NotEnoughSeedWords);
        }

        let _checksum = seed_words.pop();

        let mut buffer = vec![];
        let chunks = seed_words.chunks(3);
        for chunk in chunks {
            let w1 = find_word_index(
                &trimmed_words_list,
                &chunk[0].chars().take(TRIM_LENGTH).collect::<String>(),
            )?;
            let w2 = find_word_index(
                &trimmed_words_list,
                &chunk[1].chars().take(TRIM_LENGTH).collect::<String>(),
            )?;
            let w3 = find_word_index(
                &trimmed_words_list,
                &chunk[2].chars().take(TRIM_LENGTH).collect::<String>(),
            )?;

            let n = length;
            let x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);

            buffer.extend_from_slice(&u32::to_le_bytes(u32::try_from(x)?));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&buffer);

        let mut s = [0u8; 32];
        s.copy_from_slice(seed.as_slice());
        let spend_key = Scalar::from_bytes_mod_order(s).to_bytes();
        let view_key = Scalar::from_bytes_mod_order(keccak256(&spend_key)).to_bytes();

        Ok(Self {
            inner: seed,
            spend_key: PrivateKey(spend_key),
            view_key: PrivateKey(view_key),
        })
    }

    pub fn to_address<N: Network>(&self) -> Result<String, Error> {
        let mut bytes = vec![N::network_byte()];
        bytes.extend_from_slice(&self.spend_key.to_public_key());
        bytes.extend_from_slice(&self.view_key.to_public_key());

        let checksum_bytes = &bytes[0..65];
        let checksum = &keccak256(checksum_bytes);
        bytes.extend_from_slice(&checksum[0..4]);

        base58::encode(bytes.as_slice()).map_err(|e| Error::BadEncoding(e.to_string()))
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

fn generate_entropy() -> [u8; 32] {
    let mut entropy = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut entropy);
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Mainnet, Stagenet};

    #[test]
    fn generates_correct_mainnet_address_from_seeds() {
        #[rustfmt::skip]
        let seed_words = [
            "razor", "obnoxious", "entrance", "inroads", "saxophone", "among", "onward", "revamp",
            "scoop", "boxes", "point", "fawns", "rigid", "army", "badge", "icing", "frying",
            "voted", "biggest", "layout", "dehydrate", "acidic", "reinvest", "school", "inroads",
        ];
        let seed_words = seed_words.iter().map(|w| w.to_string()).collect::<Vec<String>>();

        let expected_address =
            "45Q1XvrXszmdK23braS6YZEJA3Ei6LoJNJ7J4GJqmSbFJXGowyxgj2V4yLh6vTeNv2c7EPov94bUZ22JupjH591hLAmYT5M";

        let seed = Seed::from_seed_words(&seed_words).unwrap();
        let address = seed.to_address::<Mainnet>().unwrap();

        assert_eq!(address, expected_address);
    }

    #[test]
    fn generates_correct_stagenet_address_from_seeds() {
        #[rustfmt::skip]
        let seed_words = [
            "dauntless", "unwind", "gourmet", "timber", "fugitive", "request", "gourmet", "devoid",
            "mechanic", "snug", "ornament", "equip", "puck", "puck", "water", "nugget", "maze",
            "dude", "arises", "hectare", "smog", "solved", "dummy", "enmity", "ornament"
        ];
        let seed_words = seed_words.iter().map(|w| w.to_string()).collect::<Vec<String>>();

        let expected_address =
            "56xCt2ZKdPE7Qfgjb4puy3FZYtsEaj2Ky6fHxFFUMe5TRiVD7BzAZcQXeNfju3tocjVChbjhWussg5R3Jr88EwamA4u9V6f";

        let seed = Seed::from_seed_words(&seed_words).unwrap();
        let address = seed.to_address::<Stagenet>().unwrap();

        assert_eq!(address, expected_address);
    }

    #[test]
    fn generates_new_seeds_with_address() {
        #[rustfmt::skip]
        let (words, seed) = Seed::generate().unwrap();

        let address = seed.to_address::<Stagenet>().unwrap();

        let new_seed = Seed::from_seed_words(&words).unwrap();
        let new_address = new_seed.to_address::<Stagenet>().unwrap();

        assert_eq!(address, new_address);
    }
}
