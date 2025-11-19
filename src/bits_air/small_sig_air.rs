use std::{array, borrow::Borrow};

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use crate::{bits_air::{rotr_air::RightRotateAir, sr_air::ShiftRightAir}, constants::U32_LIMBS};

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SmallSigma0Cols<T> {
    pub input: [T; U32_LIMBS],
    pub rrots: [RightRotateAir<T>; 2],
    pub sr: ShiftRightAir<T>,

}

pub const NUM_SMALL_SIGMA0_COLS: usize = size_of::<SmallSigma0Cols<u8>>();

#[derive(Debug)]
pub struct SmallSigma0Air {
    
}

impl SmallSigma0Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA0_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA0_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigma0Cols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig0_trace_rows(&mut rows[0], input);
        trace
    }
}

fn generate_sig0_trace_rows<F: PrimeField32>(
    row: &mut SmallSigma0Cols<F>,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    row.rrots[0].populate(input, 7);
    row.rrots[1].populate(input, 18);
    row.sr.populate(input, 3);


}


#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SmallSigma1Cols<T> {
    pub input: [T; U32_LIMBS],
    pub rrots: [RightRotateAir<T>; 2],
    pub sr: ShiftRightAir<T>,
}

pub const NUM_SMALL_SIGMA1_COLS: usize = size_of::<SmallSigma1Cols<u8>>();

#[derive(Debug)]
pub struct SmallSigma1Air {}

impl SmallSigma1Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA1_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA1_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigma1Cols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig1_trace_rows(&mut rows[0], input);
        trace
    }
}

fn generate_sig1_trace_rows<F: PrimeField32>(
    row: &mut SmallSigma1Cols<F>,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(| i | F::from_canonical_u8(input_bytes[i]));

    row.rrots[0].populate(input, 17);
    row.rrots[1].populate(input, 19);
    row.sr.populate(input, 10);

}