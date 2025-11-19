use std::{array, borrow::Borrow};

use openvm_stark_backend::{interaction::InteractionBuilder, rap::{BaseAirWithPublicValues, PartitionedBaseAir}};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_sha512::chips::byte::ByteLookupChip;

use crate::{bits_air::{rotr_air::RightRotateCols, sr_air::ShiftRightCols, xor_air::Xor3Cols}, constants::U32_LIMBS};

const BYTE_XOR_BUS: u16 = 10;
const BYTE_SHR_CARRY_BUS: u16 = 11;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SmallSigmaCols<T> {
    pub input: [T; U32_LIMBS],
    pub rrots: [RightRotateCols<T>; 2],
    pub sr: ShiftRightCols<T>,
    pub xor3: Xor3Cols<T>,
}

pub const NUM_SMALL_SIGMA_COLS: usize = size_of::<SmallSigmaCols<u8>>();

impl<F> Borrow<SmallSigmaCols<F>> for [F] {
    fn borrow(&self) -> &SmallSigmaCols<F> {
        debug_assert_eq!(self.len(), NUM_SMALL_SIGMA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<SmallSigmaCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

#[derive(Debug)]
pub struct SmallSigma0Air {
}

impl SmallSigma0Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig0_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}

impl<F> BaseAir<F> for SmallSigma0Air {
    fn width(&self) -> usize {
        NUM_SMALL_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for SmallSigma0Air {}

impl<F> PartitionedBaseAir<F> for SmallSigma0Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for SmallSigma0Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SmallSigmaCols<AB::Var> = (*local).borrow();

        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateCols::<AB::F>::eval::<AB>(builder, BYTE_SHR_CARRY_BUS, input.clone(), 7, &local.rrots[0]);
        RightRotateCols::<AB::F>::eval::<AB>(builder, BYTE_SHR_CARRY_BUS, input.clone(), 18, &local.rrots[0]);
        ShiftRightCols::<AB::F>::eval(builder, BYTE_SHR_CARRY_BUS, input.clone(), 3, &local.sr);
        
        let x = [
            local.rrots[0].value[0].into(),
            local.rrots[0].value[1].into(),
            local.rrots[0].value[2].into(),
            local.rrots[0].value[3].into(),
        ];
        let y = [
            local.rrots[1].value[0].into(),
            local.rrots[1].value[1].into(),
            local.rrots[1].value[2].into(),
            local.rrots[1].value[3].into(),
        ];
        let z = [
            local.sr.value[0].into(),
            local.sr.value[1].into(),
            local.sr.value[2].into(),
            local.sr.value[3].into(),
        ];
        Xor3Cols::<AB::F>::eval(builder, BYTE_XOR_BUS, x, y, z, &local.xor3);
    }
}

fn generate_sig0_trace_rows<F: PrimeField32>(
    row: &mut SmallSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 7);
    let y = row.rrots[1].populate(byte_lookup, input, 18);
    let z = row.sr.populate(byte_lookup, input, 3);

    row.xor3.populate(byte_lookup, x, y, z);
}

#[derive(Debug)]
pub struct SmallSigma1Air {}

impl SmallSigma1Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig1_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}


impl<F> BaseAir<F> for SmallSigma1Air {
    fn width(&self) -> usize {
        NUM_SMALL_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for SmallSigma1Air {}

impl<F> PartitionedBaseAir<F> for SmallSigma1Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for SmallSigma1Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SmallSigmaCols<AB::Var> = (*local).borrow();

        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateCols::<AB::F>::eval::<AB>(builder, BYTE_SHR_CARRY_BUS, input.clone(), 7, &local.rrots[0]);
        RightRotateCols::<AB::F>::eval::<AB>(builder, BYTE_SHR_CARRY_BUS, input.clone(), 18, &local.rrots[0]);
        ShiftRightCols::<AB::F>::eval(builder, BYTE_SHR_CARRY_BUS, input.clone(), 3, &local.sr);
        
        let x = [
            local.rrots[0].value[0].into(),
            local.rrots[0].value[1].into(),
            local.rrots[0].value[2].into(),
            local.rrots[0].value[3].into(),
        ];
        let y = [
            local.rrots[1].value[0].into(),
            local.rrots[1].value[1].into(),
            local.rrots[1].value[2].into(),
            local.rrots[1].value[3].into(),
        ];
        let z = [
            local.sr.value[0].into(),
            local.sr.value[1].into(),
            local.sr.value[2].into(),
            local.sr.value[3].into(),
        ];
        Xor3Cols::<AB::F>::eval(builder, BYTE_XOR_BUS, x, y, z, &local.xor3);
    }
}

fn generate_sig1_trace_rows<F: PrimeField32>(
    row: &mut SmallSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 17);
    let y = row.rrots[1].populate(byte_lookup, input, 19);
    let z = row.sr.populate(byte_lookup, input, 10);

    row.xor3.populate(byte_lookup, x, y, z);
}