use crate::utils::{BlockHeaderVar, BlockVar};
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::cmp::Ordering;

use self::{
    block_header_hash_gadget::BlockHeaderHashGadget, calculate_target_gadget::BlockTargetGadget,
};

pub mod block_header_hash_gadget;
pub mod calculate_target_gadget;

pub struct BTCBlockCheckerGadget<F: PrimeField> {
    _f: std::marker::PhantomData<F>,
}

impl<F: PrimeField> BTCBlockCheckerGadget<F> {
    pub fn check_block(
        cs: ConstraintSystemRef<F>,
        block: BlockVar<F>,
    ) -> Result<(), SynthesisError> {
        // Check that block hash is equal to current block hash
        let computed_block_hash =
            BlockHeaderHashGadget::hash_block_header(block.block_header.clone())?;
        computed_block_hash.enforce_equal(&block.block_hash.hash)?;

        // Check that prev block hash is what is found within the block header
        block
            .prev_block_hash
            .hash
            .to_bytes()?
            .enforce_equal(&block.block_header.block_header[4..36])?;

        // Compute target
        let target = BlockTargetGadget::calculate_target(cs.clone(), block.block_header.clone())?;

        // Check pow
        block.block_hash.hash.to_bytes()?.to_constraint_field()?[0].enforce_cmp(
            &target,
            Ordering::Less,
            false,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_blocks;
    use crate::tests::get_test_block;
    use crate::utils::{Block, BlockHashVar, BlockVar};
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_vesta::Fr;

    #[test]
    fn check_multiple_blocks_in_r1cs() {
        // 5 batches of 5 blocks, i.e. 25 blocks in total are checked
        let (mut prev_block_hash, blocks_batches) = read_blocks(5, 5);
        for batch in blocks_batches {
            let block_hashes =
                serde_json::from_value::<Vec<String>>(batch.get("blockHashes").unwrap().clone())
                    .unwrap();
            let block_headers =
                serde_json::from_value::<Vec<Vec<u8>>>(batch.get("blockHeaders").unwrap().clone())
                    .unwrap();
            for (i, (block_hash, block_header)) in
                block_hashes.iter().zip(block_headers).enumerate()
            {
                let cs = ConstraintSystem::<Fr>::new_ref();
                let block = Block {
                    prev_block_hash: prev_block_hash.clone(),
                    block_hash: block_hash.clone(),
                    block_header: block_header.clone(),
                };
                let block_var =
                    BlockVar::new_variable(cs.clone(), || Ok(block), AllocationMode::Witness)
                        .unwrap();
                let res = BTCBlockCheckerGadget::<Fr>::check_block(cs.clone(), block_var);
                assert!(res.is_ok());
                assert!(cs.is_satisfied().unwrap());
                prev_block_hash = block_hash.clone();
            }
        }
    }

    #[test]
    fn check_single_block_in_r1cs() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let test_blocks = get_test_block();
        let block = Block {
            block_header: test_blocks.blockHeaders[0].clone(),
            block_hash: test_blocks.blockHashes[0].clone(),
            prev_block_hash: test_blocks.prevBlockHash.clone(),
        };
        let block_var =
            BlockVar::new_variable(cs.clone(), || Ok(block), AllocationMode::Witness).unwrap();
        BTCBlockCheckerGadget::<Fr>::check_block(cs.clone(), block_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn new_block_hash_and_block_hash_var() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();
        let block_hash_var = BlockHashVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_hash_var"),
            || Ok(&block.prevBlockHash),
            AllocationMode::Constant,
        );
        assert!(block_hash_var.is_ok());
    }

    #[test]
    fn prev_block_hash_from_block_header() {
        // Gets the previous block hash from the block header, compare it with the previous block hash value
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();
        let prev_block_hash_var = BlockHashVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_hash_var"),
            || Ok(&block.prevBlockHash),
            AllocationMode::Constant,
        )
        .unwrap()
        .hash
        .to_bytes()
        .unwrap();

        let block_header_var = &BlockHeaderVar::<Fr>::new_variable(
            cs,
            || Ok(&block.blockHeaders[0]),
            AllocationMode::Constant,
        )
        .unwrap()
        .block_header[4..36];

        let is_eq = prev_block_hash_var.is_eq(block_header_var).unwrap();
        assert!(is_eq.value().unwrap());
    }
}
