use std::borrow::Borrow;

use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use num_bigint::BigUint;
use num_traits::Num;

pub mod block_header_hash_gadget;
pub mod calculate_target_gadget;
pub mod eq_block_hash_gadget;

pub struct BlockHashVar<F: PrimeField> {
    pub hash: DigestVar<F>,
}

impl<F: PrimeField> AllocVar<String, F> for BlockHashVar<F> {
    fn new_variable<T: Borrow<String>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let hash = f()?;
        let hash_bytes = BigUint::from_str_radix(hash.borrow(), 16)
            .expect("Couldn't parse hash string to BigUint")
            .to_bytes_be();
        let hash = DigestVar::new_variable(cs, || Ok(&hash_bytes), mode)?;
        Ok(Self { hash })
    }
}

// A struct which holds the block header as an array of Fp
pub struct BlockHeader {
    pub block_header: Vec<u8>,
}

/// This is the R1CS equivalent of the BlockHeader struct
pub struct BlockHeaderVar<F: PrimeField> {
    pub block_header: Vec<UInt8<F>>,
}

impl<F: PrimeField> AllocVar<BlockHeader, F> for BlockHeaderVar<F> {
    // Beware that a block header will always be allocated as witness
    // The `mode` parameter is ignored
    fn new_variable<T: Borrow<BlockHeader>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let block_header = f()?.borrow().block_header.clone();
        let block_header = UInt8::new_witness_vec(cs, &block_header)?;
        Ok(Self { block_header })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::get_test_block;
    use ark_r1cs_std::{eq::EqGadget, R1CSVar, ToBytesGadget};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_vesta::Fr;

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
    fn new_block_header_and_block_header_var() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();
        let block_header = BlockHeader {
            block_header: block.blockHeaders[0].clone(),
        };
        let block_header_var = BlockHeaderVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_header_var"),
            || Ok(&block_header),
            AllocationMode::Constant,
        );
        assert!(block_header_var.is_ok());
    }

    #[test]
    fn prev_block_hash_from_block_header() {
        // Gets the previous block hash from the block header, compare it with the previous block hash value
        let cs = ConstraintSystem::<Fr>::new_ref();
        let block = get_test_block();
        let block_header = BlockHeader {
            block_header: block.blockHeaders[0].clone(),
        };
        let prev_block_hash_var = BlockHashVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_hash_var"),
            || Ok(&block.prevBlockHash),
            AllocationMode::Constant,
        )
        .unwrap()
        .hash
        .to_bytes()
        .unwrap();

        let block_header_var =
            &BlockHeaderVar::<Fr>::new_variable(cs, || Ok(&block_header), AllocationMode::Constant)
                .unwrap()
                .block_header[4..36];

        let is_eq = prev_block_hash_var.is_eq(block_header_var).unwrap();
        assert!(is_eq.value().unwrap());
    }
}
