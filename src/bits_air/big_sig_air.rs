use std::{array, borrow::Borrow};

use derive::AlignedBorrow;
use openvm_stark_backend::{interaction::InteractionBuilder, rap::{BaseAirWithPublicValues, PartitionedBaseAir}};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use crate::chips::byte::ByteLookupChip;

use crate::{bits_air::{rotr_air::RightRotateGadget, xor_air::Xor3Gadget}, constants::U32_LIMBS};

const BUS_INDEX: u16 = 10;

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct BigSigmaCols<T> {
    pub input: [T; U32_LIMBS],
    pub rrots: [RightRotateGadget<T>; 3],
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_BIG_SIGMA_COLS: usize = size_of::<BigSigmaCols<u8>>();


#[derive(Debug)]
pub struct BigSigma0Air {
}

impl BigSigma0Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_BIG_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_BIG_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<BigSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig0_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}

impl<F> BaseAir<F> for BigSigma0Air {
    fn width(&self) -> usize {
        NUM_BIG_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for BigSigma0Air {}

impl<F> PartitionedBaseAir<F> for BigSigma0Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for BigSigma0Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BigSigmaCols<AB::Var> = (*local).borrow();

        
        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(builder, BUS_INDEX, input.clone(), 2, &local.rrots[0]);
        RightRotateGadget::<AB::F>::eval::<AB>(builder, BUS_INDEX, input.clone(), 13, &local.rrots[1]);
        RightRotateGadget::<AB::F>::eval(builder, BUS_INDEX, input.clone(), 22, &local.rrots[2]);
        Xor3Gadget::<AB::F>::eval(builder, BUS_INDEX, local.rrots[0].value, local.rrots[1].value, local.rrots[2].value, &local.xor3);
    }
}


fn generate_sig0_trace_rows<F: PrimeField32>(
    row: &mut BigSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 2);
    let y = row.rrots[1].populate(byte_lookup, input, 13);
    let z = row.rrots[2].populate(byte_lookup, input, 22);

    row.xor3.populate(byte_lookup, x, y, z);
}


#[derive(Debug)]
pub struct BigSigma1Air {
}

impl BigSigma1Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_BIG_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_BIG_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<BigSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig1_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}

impl<F> BaseAir<F> for BigSigma1Air {
    fn width(&self) -> usize {
        NUM_BIG_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for BigSigma1Air {}

impl<F> PartitionedBaseAir<F> for BigSigma1Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for BigSigma1Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BigSigmaCols<AB::Var> = (*local).borrow();

        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(builder, BUS_INDEX, input.clone(), 6, &local.rrots[0]);
        RightRotateGadget::<AB::F>::eval::<AB>(builder, BUS_INDEX, input.clone(), 11, &local.rrots[1]);
        RightRotateGadget::<AB::F>::eval(builder, BUS_INDEX, input.clone(), 25, &local.rrots[2]);
        Xor3Gadget::<AB::F>::eval(builder, BUS_INDEX, local.rrots[0].value, local.rrots[1].value, local.rrots[2].value, &local.xor3);
    }
}


fn generate_sig1_trace_rows<F: PrimeField32>(
    row: &mut BigSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 6);
    let y = row.rrots[1].populate(byte_lookup, input, 11);
    let z = row.rrots[2].populate(byte_lookup, input, 25);

    row.xor3.populate(byte_lookup, x, y, z);
}
