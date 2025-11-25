use std::{array, iter::repeat_n};

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use crate::{
    chips::byte::ByteLookupChip, columns::{NUM_SHA_COLS, ShaCols}, constants::{NUM_ROUNDS, NUM_ROUNDS_MIN_1, SHA256_H, SHA256_K, U32_LIMBS}, utils::{big_sig1, ch, limbs_into_u32, maj}
};

pub fn generate_trace_rows<F: PrimeField32>(
    inputs: Vec<[u8; 64]>,
    byte_lookup: &ByteLookupChip,
    extra_capacity_bits: usize,
) -> RowMajorMatrix<F> {
    let num_rows = (inputs.len() * NUM_ROUNDS).next_power_of_two();
    let trace_length = num_rows * NUM_SHA_COLS;

    // We allocate extra_capacity_bits now as this will be needed by the dft.
    let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
    long_trace.truncate(trace_length);

    let mut trace = RowMajorMatrix::new(long_trace, NUM_SHA_COLS);
    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<ShaCols<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), num_rows);

    let num_padding_inputs = num_rows.div_ceil(NUM_ROUNDS) - inputs.len();
    let padded_inputs = inputs
        .into_par_iter()
        .chain(repeat_n([0; 64], num_padding_inputs));

    rows.par_chunks_mut(NUM_ROUNDS)
        .zip(padded_inputs)
        .for_each(|(row, input)| {
            generate_trace_rows_for_block(row, byte_lookup, input);
        });

    trace
}

pub fn generate_trace_rows_for_block<F: PrimeField32>(
    rows: &mut [ShaCols<F>],
    byte_lookup: &ByteLookupChip,
    input_block: [u8; 64],
) {
    rows[0].input_block = array::from_fn(|i| F::from_canonical_u8(input_block[i]));
    let mut buf = [0u32; 64];
    for i in 0..NUM_ROUNDS {
        if i < 16 {
            let j = i * 4;
            buf[i] = (input_block.as_ref()[j] as u32) << 24
                | (input_block.as_ref()[j + 1] as u32) << 16
                | (input_block.as_ref()[j + 2] as u32) << 8
                | (input_block.as_ref()[j + 3] as u32);
        } else {
            let v1 = buf[i - 2];
            let t1 = v1.rotate_right(17) ^ v1.rotate_right(19) ^ (v1 >> 10);
            rows[i].small_sig1[i-16].populate(byte_lookup, v1);
            let v2 = buf[i - 15];
            let t2 = v2.rotate_right(7) ^ v2.rotate_right(18) ^ (v2 >> 3);
            rows[i].small_sig0[i-16].populate(byte_lookup, v2);
            buf[i] = t1
                .wrapping_add(buf[i - 7])
                .wrapping_add(t2)
                .wrapping_add(buf[i - 16]);
            rows[i].add_small_sig[i-16].populate(
                byte_lookup,
                [t1, buf[i - 7], t2, buf[i - 16]],
            );
        }
    }

    let buf_u8: [[u8; U32_LIMBS]; 64] = array::from_fn(|i| buf[i].to_le_bytes());

    let prev_seed: [[u8; U32_LIMBS]; 8] = array::from_fn(|i| SHA256_H[i].to_le_bytes());
    rows[0].prev_seed =
        array::from_fn(|i| array::from_fn(|j| F::from_canonical_u8(prev_seed[i][j])));

    for round in 0..NUM_ROUNDS {
        if round != 0 {
            rows[round].prev_seed = rows[round - 1].seed;
            rows[round].input_block = array::from_fn(|_| F::ZERO);
        }
        rows[round].buf =
            array::from_fn(|i| array::from_fn(|j| F::from_canonical_u8(buf_u8[i][j])));

        generate_trace_row_for_round(&mut rows[round], round);
    }

    rows[NUM_ROUNDS_MIN_1].final_hash = array::from_fn(|i| {
        array::from_fn(|j| {
            let x_32 = limbs_into_u32(rows[NUM_ROUNDS_MIN_1].seed.map(|f| f[j].as_canonical_u32()));
            let y_32 = limbs_into_u32(rows[0].prev_seed.map(|f| f[j].as_canonical_u32()));
            F::from_canonical_u8(x_32.wrapping_add(y_32).to_le_bytes()[i])
        })
    });
}

// permute
pub fn generate_trace_row_for_round<F: PrimeField32>(row: &mut ShaCols<F>, round: usize) {
    row.step_flags[round] = F::ONE;
    row.final_hash = array::from_fn(|_| array::from_fn(|_| F::ZERO));

    let t1 = [
        limbs_into_u32(row.prev_seed[7].map(|f| f.as_canonical_u32())),
        big_sig1(limbs_into_u32(
            row.prev_seed[4].map(|f| f.as_canonical_u32()),
        )),
        ch(
            limbs_into_u32(row.prev_seed[4].map(|f| f.as_canonical_u32())),
            limbs_into_u32(row.prev_seed[5].map(|f| f.as_canonical_u32())),
            limbs_into_u32(row.prev_seed[6].map(|f| f.as_canonical_u32())),
        ),
        SHA256_K[round],
        limbs_into_u32(row.buf[round].map(|f| f.as_canonical_u32())),
    ];
    let t1_sum: u32 = t1.iter().fold(0, |acc, &num| acc.wrapping_add(num));

    let t2 = [
        big_sig1(limbs_into_u32(
            row.prev_seed[0].map(|f| f.as_canonical_u32()),
        )),
        maj(
            limbs_into_u32(row.prev_seed[0].map(|f| f.as_canonical_u32())),
            limbs_into_u32(row.prev_seed[1].map(|f| f.as_canonical_u32())),
            limbs_into_u32(row.prev_seed[2].map(|f| f.as_canonical_u32())),
        ),
    ];
    let t2_sum: u32 = t2.iter().fold(0, |acc, &num| acc.wrapping_add(num));

    let e = array::from_fn(|i| {
        F::from_canonical_u8(
            limbs_into_u32(row.prev_seed[3].map(|f| f.as_canonical_u32()))
                .wrapping_add(t1_sum)
                .to_le_bytes()[i],
        )
    });

    let a: [F; 4] =
        array::from_fn(|i| F::from_canonical_u8(t1_sum.wrapping_add(t2_sum).to_le_bytes()[i]));

    row.seed = [
        row.prev_seed[6],
        row.prev_seed[5],
        row.prev_seed[4],
        e,
        row.prev_seed[2],
        row.prev_seed[1],
        row.prev_seed[0],
        a,
    ];
}
