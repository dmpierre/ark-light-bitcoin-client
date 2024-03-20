use std::marker::PhantomData;

use super::BlockHeaderVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
    ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// A gadget to calculate the target pow value from the bits field of the block header
#[derive(Clone, Debug)]
pub struct BlockTargetGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> BlockTargetGadget<F> {
    // The target is calculated from the bits field of the block header
    // Target is computed from the "bits" field. The bits field is found in the 72..76 bytes of the block header
    pub fn calculate_target(
        cs: ConstraintSystemRef<F>,
        header: BlockHeaderVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut bits = UInt8::new_witness_vec(cs.clone(), &vec![0u8; 4])?;
        bits.clone_from_slice(&header.block_header[72..76]);

        // Compute base^{exponent}
        let exponent = &[bits[3].clone()].to_constraint_field()?[0];
        let three = FpVar::<F>::new_constant(cs.clone(), F::from(3 as u8))?;
        let exponent = exponent - three;
        let base_exponent = Base256Gadget::calculate_base256_exponent(cs.clone(), exponent)?;

        // Compute the mantissa
        let mantissa = &bits[0..3].to_constraint_field()?[0];

        // Compute target
        let target = mantissa * base_exponent;

        Ok(target)
    }
}

// A gadget to calculate 256^{exponent} for a given exponent
#[derive(Clone, Debug)]
pub struct Base256Gadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Base256Gadget<F> {
    pub fn calculate_base256_exponent(
        cs: ConstraintSystemRef<F>,
        exponent: FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut result = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1 as u16)))?;
        let mut base = FpVar::<F>::new_constant(cs.clone(), F::from(256 as u16))?;
        let exponent_bits = exponent.to_bits_le()?;
        for bit in exponent_bits {
            let result_if_true = result.clone() * base.clone();
            let result_if_false = result.clone();
            result = bit.select(&result_if_true, &result_if_false)?;
            base.square_in_place()?;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{Field, PrimeField};
    use ark_r1cs_std::{
        alloc::{AllocVar, AllocationMode},
        fields::fp::FpVar,
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_vesta::Fr;
    use num_bigint::BigUint;

    use crate::{
        gadgets::{BlockHeader, BlockHeaderVar},
        tests::get_test_block,
    };

    use crate::get_target;

    #[test]
    fn calculate_base256_exponent() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let exponent = Fr::from(3 as u64);
        let exponent_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(exponent)).unwrap();
        let computed = super::Base256Gadget::calculate_base256_exponent(cs.clone(), exponent_var)
            .unwrap()
            .value()
            .unwrap();

        let expected = Fr::from(256).pow(exponent.into_bigint());

        assert_eq!(computed, expected);
    }

    #[test]
    fn calculate_target() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let block = get_test_block();
        let expected_target = get_target(&block.blockHeaders[0]);

        let block_header = BlockHeader {
            block_header: block.blockHeaders[0].clone(),
        };
        let block_header_var = BlockHeaderVar::<Fr>::new_variable(
            ark_relations::ns!(cs, "new_block_header_var"),
            || Ok(&block_header),
            AllocationMode::Witness,
        )
        .unwrap();

        let computed_target =
            super::BlockTargetGadget::calculate_target(cs.clone(), block_header_var)
                .unwrap()
                .value()
                .unwrap();

        assert_eq!(computed_target, expected_target.into());
    }
}
