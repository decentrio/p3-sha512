use std::{array, borrow::BorrowMut, iter::repeat_n};

use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use crate::{
    chips::byte::ByteLookupChip,
    columns::{NUM_SHA_COLS, ShaCols},
    constants::{NUM_ROUNDS, NUM_ROUNDS_MIN_1, NUM_ROUNDS_PER_ROW, SHA256_H, SHA256_K, U32_LIMBS},
    encoder::encoder::Encoder,
    utils::{big_sig0, big_sig1, ch, compose, limbs_into_u32, maj},
};

use crate::utils::get_flag_pt_array;

pub fn generate_trace_rows<F: PrimeField32>(
    inputs: Vec<[u8; 64]>,
    encoder: &Encoder,
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

    let mut prev_block_seed = SHA256_H;
    rows.par_chunks_mut(NUM_ROUNDS)
        .zip(padded_inputs)
        .for_each(|(row, input)| {
            generate_trace_rows_for_block(row, encoder, byte_lookup, input, prev_block_seed);
            prev_block_seed = array::from_fn(|i| {
                compose(row[NUM_ROUNDS_MIN_1].final_hash[i].map(|x| x.as_canonical_u32()))
            })
        });

    trace
}

pub fn generate_trace_rows_for_block<F: PrimeField32>(
    rows: &mut [ShaCols<F>],
    encoder: &Encoder,
    byte_lookup: &ByteLookupChip,
    input_block: [u8; 64],
    prev_block_seed: [u32; 8],
) {
    let mut buf = [0u32; 64];
    for i in 0..NUM_ROUNDS {
        if i < 4 {
            for j in 0..NUM_ROUNDS_PER_ROW {
                let k = i * 4 + j;
                buf[k] = (input_block.as_ref()[k * 4] as u32) << 24
                    | (input_block.as_ref()[k * 4 + 1] as u32) << 16
                    | (input_block.as_ref()[k * 4 + 2] as u32) << 8
                    | (input_block.as_ref()[k * 4 + 3] as u32);
                if i == 0 {
                    rows[i].small_sig1[j].populate(byte_lookup, 0);
                    rows[i].small_sig0[j].populate(byte_lookup, 0);
                }
                rows[i].sum_small_sig[j].populate(byte_lookup, [0, 0, 0, 0]);
            }
        } else {
            for j in 0..NUM_ROUNDS_PER_ROW {
                let k = i * 4 + j;
                let v1 = buf[k - 2];
                let v2 = buf[k - 15];

                // update value to columns
                let t1 = rows[i].small_sig1[j].populate(byte_lookup, v1);
                let t2 = rows[i].small_sig0[j].populate(byte_lookup, v2);
                buf[k] = rows[i]
                    .sum_small_sig[j]
                    .populate(byte_lookup, [buf[k - 7], buf[k - 16], t1, t2]);
            }
        }

        // filling w_3 and intermed_4 here and the rest later
        if i > 0 {
            for j in 0..NUM_ROUNDS_PER_ROW {
                let idx = i * NUM_ROUNDS_PER_ROW + j;
                let w_4 = buf[idx - 4].to_le_bytes();
                let sig_0_w_3 = rows[i].small_sig0[j].populate(byte_lookup, buf[idx-3]).to_le_bytes();
                rows[i].intermed_4[j] =
                    array::from_fn(|k| F::from_canonical_u8(w_4[k] + sig_0_w_3[k]));
                if j < NUM_ROUNDS_PER_ROW - 1 {
                    let w_3 = buf[idx - 3];
                    rows[i].w_3[j] = w_3.to_le_bytes().map(F::from_canonical_u8);
                }
            }
        }
    }

    let buf_u8: [[u8; U32_LIMBS]; 64] = array::from_fn(|i| buf[i].to_le_bytes());

    let prev_block_seed: [[u8; U32_LIMBS]; 8] =
        array::from_fn(|i| prev_block_seed[i].to_le_bytes());

    rows[0].prev_seed =
        array::from_fn(|i| array::from_fn(|j| F::from_canonical_u8(prev_block_seed[i][j])));

    for round in 0..NUM_ROUNDS {
        if round != 0 {
            rows[round].prev_seed = rows[round - 1].seed;
        }

        rows[round].input_block = array::from_fn(|i| F::from_canonical_u8(input_block[i]));
        rows[round].buf =
            array::from_fn(|i| array::from_fn(|j| F::from_canonical_u8(buf_u8[i][j])));
        rows[round].prev_block_seed =
            array::from_fn(|i| array::from_fn(|j| F::from_canonical_u8(prev_block_seed[i][j])));
        generate_trace_row_for_round(&mut rows[round], encoder, byte_lookup, round);
        for i in 0..8 {
            rows[round].sum_final[i].populate(
                byte_lookup,
                [
                    compose(rows[round].seed[i].map(|x| x.as_canonical_u32())),
                    compose(rows[round].prev_block_seed[i].map(|x| x.as_canonical_u32())),
                ],
            );
        }
    }

    for i in 0..NUM_ROUNDS {
        let local_cols = rows[i].borrow_mut();
        let next_cols = rows[i + 1].borrow_mut();

        if i > 0 {
            for j in 0..NUM_ROUNDS_PER_ROW {
                next_cols.intermed_8[j] = local_cols.intermed_4[j];
            }
        }
    }
    for i in 0..8 {
        rows[NUM_ROUNDS_MIN_1].final_hash[i] = rows[NUM_ROUNDS_MIN_1].sum_final[i].value;
    }
}

// permute
pub fn generate_trace_row_for_round<F: PrimeField32>(
    row: &mut ShaCols<F>,
    encoder: &Encoder,
    byte_lookup: &ByteLookupChip,
    round: usize,
) {
    row.step_flags[round] = F::ONE;
    if round < 4 {
        row.first_16_steps = F::ONE
    }
    row.final_hash = array::from_fn(|_| array::from_fn(|_| F::ZERO));
    row.round_idx = get_flag_pt_array(encoder, round).map(F::from_canonical_u32);
    let mut seed_a = vec![row.prev_seed[0]];
    let mut seed_e = vec![row.prev_seed[4]];

    let mut ch_inputs = vec![row.prev_seed[6], row.prev_seed[5], row.prev_seed[4]];
    let mut maj_inputs = vec![row.prev_seed[2], row.prev_seed[1], row.prev_seed[0]];

    for i in 0..NUM_ROUNDS_PER_ROW -1 {
        let t1 = [
            SHA256_K[round * 4 + i],
            limbs_into_u32(row.buf[round * 4 + i].map(|f| f.as_canonical_u32())),
            // h -> g -> f depends on which rounds
            limbs_into_u32(row.prev_seed[7 - i].map(|f| f.as_canonical_u32())),
            row.big_sig1[i].populate(
                byte_lookup,
                limbs_into_u32(seed_e[i].map(|f| f.as_canonical_u32())),
            ),
            row.ch[i].populate(
                byte_lookup,
                limbs_into_u32(ch_inputs[0].map(|f| f.as_canonical_u32())),
                limbs_into_u32(ch_inputs[1].map(|f| f.as_canonical_u32())),
                limbs_into_u32(ch_inputs[2].map(|f| f.as_canonical_u32())),
            ),
        ];
        let t1_sum: u32 = row.sum_t1[i].populate(byte_lookup, t1);

        let t2 = [
            row.big_sig0[i].populate(
                byte_lookup,
                limbs_into_u32(seed_a[i].map(|f| f.as_canonical_u32())),
            ),
            row.maj[i].populate(
                byte_lookup,
                limbs_into_u32(maj_inputs[0].map(|f| f.as_canonical_u32())),
                limbs_into_u32(maj_inputs[1].map(|f| f.as_canonical_u32())),
                limbs_into_u32(maj_inputs[2].map(|f| f.as_canonical_u32())),
            ),
        ];
        let t2_sum: u32 = row.sum_t2[i].populate(byte_lookup, t2);

        let e = row
            .sum_e[i]
            .populate(
                byte_lookup,
                [
                    limbs_into_u32(row.prev_seed[3 - i].map(|f| f.as_canonical_u32())),
                    t1_sum,
                ],
            )
            .to_le_bytes()
            .map(|i| F::from_canonical_u8(i));

        let a: [F; 4] = row
            .sum_a[i]
            .populate(byte_lookup, [t1_sum, t2_sum])
            .to_le_bytes()
            .map(|i| F::from_canonical_u8(i));

        seed_a.push(a);
        seed_e.push(e);
        ch_inputs.remove(0);
        ch_inputs.push(e);
        maj_inputs.remove(0);
        maj_inputs.push(a);
    }

    row.a = seed_a.clone().try_into().unwrap();
    row.e = seed_e.clone().try_into().unwrap();

    row.seed = [
        seed_a[3],
        seed_a[2],
        seed_a[1],
        seed_a[0],
        seed_e[3],
        seed_e[2],
        seed_e[1],
        seed_e[0],
    ];
}
