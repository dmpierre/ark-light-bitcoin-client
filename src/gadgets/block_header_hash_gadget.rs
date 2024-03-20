use std::marker::PhantomData;

use super::BlockHeaderVar;
use ark_crypto_primitives::crh::{
    sha256::constraints::{DigestVar, Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;

// A gadget to hash the header of a block
#[derive(Debug, Clone)]
pub struct BlockHeaderHashGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> BlockHeaderHashGadget<F> {
    // The header of a block is hashed twice using SHA256
    // See: https://developer.bitcoin.org/reference/block_chain.html#block-headers
    pub fn hash_block_header(header: BlockHeaderVar<F>) -> Result<DigestVar<F>, SynthesisError> {
        let unit_var = UnitVar::default();
        let sha256_1 = Sha256Gadget::evaluate(&unit_var, &header.block_header)?;
        let sha256_2 = Sha256Gadget::evaluate(&unit_var, &sha256_1.0)?;
        Ok(sha256_2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gadgets::{BlockHashVar, BlockHeader},
        tests::get_test_block,
    };
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_vesta::Fr;

    #[test]
    fn block_header_hash_gadget() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();
        let block_header = BlockHeader {
            block_header: block.blockHeaders[0].clone(),
        };
        let block_header_var = BlockHeaderVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_header_var"),
            || Ok(&block_header),
            AllocationMode::Witness,
        )
        .unwrap();
        let computed_block_header_hash =
            BlockHeaderHashGadget::<Fr>::hash_block_header(block_header_var).unwrap();
        let expected_block_header_hash = BlockHashVar::new_variable(
            cs,
            || Ok(block.blockHashes[0].clone()),
            AllocationMode::Witness,
        )
        .unwrap()
        .hash;

        let eq = computed_block_header_hash
            .is_eq(&expected_block_header_hash)
            .unwrap();

        assert!(eq.value().unwrap());
    }
}
