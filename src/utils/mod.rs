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

#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct BlockHeaderVar<F: PrimeField> {
    pub block_header: Vec<UInt8<F>>,
}

impl<F: PrimeField> AllocVar<Vec<u8>, F> for BlockHeaderVar<F> {
    // Beware that a block header will always be allocated as witness
    // The `mode` parameter is ignored
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let block_header = f()?.borrow().clone();
        let block_header = UInt8::new_witness_vec(cs, &block_header)?;
        Ok(Self { block_header })
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub block_header: Vec<u8>,
    pub block_hash: String,
    pub prev_block_hash: String,
}

#[derive(Clone, Debug)]
pub struct BlockVar<F: PrimeField> {
    pub block_header: BlockHeaderVar<F>,
    pub block_hash: BlockHashVar<F>,
    pub prev_block_hash: BlockHashVar<F>,
}

impl<F: PrimeField> AllocVar<Block, F> for BlockVar<F> {
    fn new_variable<T: Borrow<Block>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let block = f()?;
        let block_header =
            BlockHeaderVar::new_variable(cs.clone(), || Ok(&block.borrow().block_header), mode)?;
        let block_hash =
            BlockHashVar::new_variable(cs.clone(), || Ok(&block.borrow().block_hash), mode)?;
        let prev_block_hash =
            BlockHashVar::new_variable(cs.clone(), || Ok(&block.borrow().prev_block_hash), mode)?;
        Ok(Self {
            block_header,
            block_hash,
            prev_block_hash,
        })
    }
}
