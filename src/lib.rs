use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub mod gadgets;

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Blocks {
    prevBlockHash: String,
    blockHashes: Vec<String>,
    blockHeaders: Vec<Vec<u8>>,
}

pub fn read_blocks(
    n_batch: usize,
    block_count: usize,
) -> (String, Vec<HashMap<String, serde_json::Value>>) {
    let btc_blocks: Blocks =
        serde_json::from_str(include_str!("data/btc-blocks.json")).expect("Failed reading JSON");
    let mut private_inputs = Vec::new();
    for i in 0..n_batch {
        let mut private_input = HashMap::new();
        private_input.insert(
            "blockHashes".to_string(),
            json!(btc_blocks.blockHashes[i * block_count..i * block_count + block_count]),
        );
        private_input.insert(
            "blockHeaders".to_string(),
            json!(btc_blocks.blockHeaders[i * block_count..i * block_count + block_count]),
        );
        private_inputs.push(private_input);
    }
    (btc_blocks.prevBlockHash, private_inputs)
}

/// Returns the block hash in hex, using the block header
/// Consists into hashing twice the block header using SHA256
pub fn get_block_hash(block_header: &Vec<u8>) -> String {
    let mut hasher_1 = Sha256::new();
    let mut hasher_2 = Sha256::new();

    hasher_1.update(block_header);
    let result = hasher_1.finalize();
    hasher_2.update(&result);
    let result = hasher_2.finalize();
    hex::encode(&result)
}

/// Returns the target as a BigUint
/// Target is computed from the "bits" field. The bits field is found in the 72..76 bytes of the block header
pub fn get_target(block_header: &Vec<u8>) -> BigUint {
    let target_bytes = &block_header[72..76];
    let exponent = target_bytes[3];
    let mantissa = BigUint::from_bytes_le(&target_bytes[0..3]);
    mantissa * BigUint::from(256 as u16).pow(exponent as u32 - 3)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::Num;

    /// Test block is in the same format as the one in the JSON file
    /// This JSON file is from the Nova scotia bitcoin example but in a different format
    pub fn get_test_block() -> Blocks {
        Blocks {
            prevBlockHash: "59a90c771a9e84e9372b0b223485273a19ba3e0ffc9005000000000000000000"
                .to_string(),
            blockHashes: vec![
                "927e2b48472ca6ba77505d42dbdb47ebff00bbaa9bf302000000000000000000".to_string(),
            ],
            blockHeaders: vec![vec![
                0, 96, 0, 32, 89, 169, 12, 119, 26, 158, 132, 233, 55, 43, 11, 34, 52, 133, 39, 58,
                25, 186, 62, 15, 252, 144, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 231, 201, 83, 209, 111,
                131, 58, 82, 228, 36, 108, 45, 229, 184, 9, 239, 35, 45, 16, 216, 248, 78, 41, 38,
                6, 253, 18, 250, 45, 11, 32, 9, 70, 45, 60, 97, 228, 72, 15, 23, 205, 130, 66, 166,
            ]],
        }
    }

    #[test]
    fn raw_verify_multiple_blocks() {
        let (_, blocks_batches) = read_blocks(80, 10);
        for batch in blocks_batches {
            let block_hashes =
                serde_json::from_value::<Vec<String>>(batch.get("blockHashes").unwrap().clone())
                    .unwrap();
            let block_headers =
                serde_json::from_value::<Vec<Vec<u8>>>(batch.get("blockHeaders").unwrap().clone())
                    .unwrap();
            for (block_hash, block_header) in block_hashes.iter().zip(block_headers) {
                // Simply checking that the block header hashes to the expected block hash
                // And that the target is equal to the expected target
                let block_hash_computed = get_block_hash(&block_header);
                assert_eq!(block_hash_computed, *block_hash);

                let target = get_target(&block_header);
                let bigint_block_hash = BigUint::from_str_radix(&block_hash, 16).unwrap();
                assert!(BigUint::from_bytes_be(&bigint_block_hash.to_bytes_le()) < target);
            }
        }
    }

    #[test]
    fn raw_verify_single_block() {
        let block = get_test_block();

        // 1. Check that the block header hashes to a value equal to the expected block hash
        let block_hash = get_block_hash(&block.blockHeaders[0]);
        assert_eq!(block_hash, block.blockHashes[0]);

        // 2. Check that the previous block hash equals what is within the 4..36 bytes of the block header
        let prev_block_hash = hex::encode(&block.blockHeaders[0][4..36]);
        assert_eq!(prev_block_hash, block.prevBlockHash);

        // 3. Check that the target is equal to the expected target
        let target = get_target(&block.blockHeaders[0]);
        let bigint_block_hash = BigUint::from_str_radix(&block.blockHashes[0], 16).unwrap();

        // 4. Check proof-of-work
        // need to reverse the block hash bytes order from le to be
        assert!(BigUint::from_bytes_be(&bigint_block_hash.to_bytes_le()) < target);
    }
}
