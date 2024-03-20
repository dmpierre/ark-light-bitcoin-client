use std::cmp::Ordering;

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::utils::{BlockHashVar, BlockHeaderVar};

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
        prev_block_hash: BlockHashVar<F>,
        block_hash: BlockHashVar<F>,
        block_header: BlockHeaderVar<F>,
    ) -> Result<(), SynthesisError> {
        // Check that block hash is equal to current block hash
        let computed_block_hash = BlockHeaderHashGadget::hash_block_header(block_header.clone())?;
        computed_block_hash.enforce_equal(&block_hash.hash)?;

        // Check that prev block hash is what is found within the block header
        prev_block_hash
            .hash
            .to_bytes()?
            .enforce_equal(&block_header.block_header[4..36])?;

        // Compute target
        let target = BlockTargetGadget::calculate_target(cs.clone(), block_header.clone())?;

        // Check pow
        block_hash.hash.to_bytes()?.to_constraint_field()?[0].enforce_cmp(
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
    use crate::tests::get_test_block;
    use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_vesta::Fr;

    #[test]
    fn check_block() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();

        let prev_block_hash_var = BlockHashVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_hash_var"),
            || Ok(&block.prevBlockHash),
            AllocationMode::Constant,
        )
        .unwrap();

        let block_hash_var = BlockHashVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_hash_var"),
            || Ok(&block.blockHashes[0]),
            AllocationMode::Constant,
        )
        .unwrap();

        let block_header_var = BlockHeaderVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_header_var"),
            || Ok(block.blockHeaders[0].clone()),
            AllocationMode::Constant,
        )
        .unwrap();

        BTCBlockCheckerGadget::<Fr>::check_block(
            cs.clone(),
            prev_block_hash_var,
            block_hash_var,
            block_header_var,
        )
        .unwrap();

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
