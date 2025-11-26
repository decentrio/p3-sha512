use core::array;
use core::borrow::Borrow;
use std::ops::Add;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, FieldArray, PrimeField, PrimeField32};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::bits_air::big_sig_air::{BigSigma0Cols, BigSigma1Cols};
use crate::bits_air::ch_air::ChooseCols;
use crate::bits_air::maj_air::MajorCols;
use crate::bits_air::small_sig_air::{SmallSigma0Cols, SmallSigma1Cols};
use crate::bits_air::vanilla_rotr_air::RightRotateAir;
use crate::builder::ChipBuilder;
use crate::chips::byte::ByteLookupChip;
use crate::columns::{NUM_SHA_COLS, ShaCols};
use crate::constants::{NUM_ROUNDS, NUM_ROUNDS_MIN_1, SHA256_K, U32_BITS, U32_LIMBS};
use crate::gadgets::add::AddGadget;
use crate::generation::generate_trace_rows;

const BUS_INDEX: u16 = 10;

/// Assumes the field size is at least 16 bits.
#[derive(Debug)]
pub struct ShaAir {}

impl ShaAir {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        num_hashes: usize,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let mut rng = StdRng::seed_from_u64(1);
        let inputs = (0..num_hashes)
            .map(|_| {
                let mut bytes = [0u8; 64];
                rng.fill(&mut bytes);
                bytes
            })
            .collect();
        generate_trace_rows(inputs, byte_lookup, extra_capacity_bits)
    }
}

impl<F> BaseAir<F> for ShaAir {
    fn width(&self) -> usize {
        NUM_SHA_COLS
    }
}

impl<AB: ChipBuilder<F: PrimeField32>> Air<AB> for ShaAir {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        eval_round_flags(builder);

        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ShaCols<AB::Var> = (*local).borrow();
        let next: &ShaCols<AB::Var> = (*next).borrow();

        let first_step = local.step_flags[0].clone();
        let final_step = local.step_flags[NUM_ROUNDS_MIN_1].clone();
        let not_first_step = AB::Expr::ONE - first_step;
        let not_final_step = AB::Expr::ONE - final_step;

        // If this is not the first step, assert all value in input_block must be zero.
        for i in 0..64 {
            builder
                .when(not_first_step.clone())
                .assert_zero(local.input_block[i].clone());
        }

        for i in 0..8 {
            for j in 0..U32_LIMBS {
                // If this is not the final step, the local seed and next prev_seed must match.
                builder
                    .when_transition()
                    .when(not_final_step.clone())
                    .assert_zero(local.seed[i][j].clone() - next.prev_seed[i][j].clone());
                // If this is not the final step, the final hash must be zeros.
                builder
                    .when(not_final_step.clone())
                    .assert_zero(local.final_hash[i][j]);
            }
        }

        // The export flag must be 0 or 1.
        builder.assert_bool(local.export.clone());

        // If this is not the final step, the export flag must be off.
        builder
            .when(not_final_step.clone())
            .assert_zero(local.export.clone());

        for i in 0..NUM_ROUNDS {
            if i < 16 {
                // assert all values in buf from 0 to 16 is equal to input block little endian
                for ele in local.buf[i] {
                    builder.when(local.first_16_steps.clone()).assert_bool(ele);
                }

                for j in 0..U32_LIMBS {
                    builder.when(local.first_16_steps.clone()).assert_zero(
                        local.buf[i][j].clone() - local.input_block[i * 4 + j].clone(),
                    );
                }
            } else {
                // TODO: constraint first row
                let v1 = [
                    local.buf[i - 2][0].clone().into(),
                    local.buf[i - 2][1].clone().into(),
                    local.buf[i - 2][2].clone().into(),
                    local.buf[i - 2][3].clone().into(),
                ];
                SmallSigma1Cols::<AB::F>::eval::<AB>(
                    builder,
                    BUS_INDEX,
                    v1,
                    local.small_sig1.borrow(),
                );
                let v2 = [
                    local.buf[i - 15][0].clone().into(),
                    local.buf[i - 15][1].clone().into(),
                    local.buf[i - 15][2].clone().into(),
                    local.buf[i - 15][3].clone().into(),
                ];
                SmallSigma0Cols::<AB::F>::eval::<AB>(
                    builder,
                    BUS_INDEX,
                    v2,
                    local.small_sig0.borrow(),
                );

                let add_input = [
                    local.small_sig1.xor3.value,
                    local.buf[i - 7],
                    local.small_sig0.xor3.value,
                    local.buf[i - 16],
                ];
                AddGadget::<AB::F, 4>::eval::<AB>(
                    builder,
                    BUS_INDEX,
                    add_input,
                    &local.sum_small_sig,
                );
                for j in 0..U32_LIMBS {
                    builder.when(AB::Expr::ONE - local.first_16_steps).assert_eq(
                        local.buf[i][j].clone(),
                        local.sum_small_sig.value[j].clone(),
                    );
                }
            }
        }

        BigSigma1Cols::<AB::F>::eval::<AB>(
            builder, 
            BUS_INDEX, 
            local.prev_seed[4], 
            local.big_sig1.borrow()
        );

        ChooseCols::<AB::F>::eval::<AB>(
            builder, 
            BUS_INDEX, 
            local.prev_seed[4], 
            local.prev_seed[5], 
            local.prev_seed[6],
            local.ch.borrow()
        );

        BigSigma0Cols::<AB::F>::eval::<AB>(
            builder, 
            BUS_INDEX, 
            local.prev_seed[0], 
            local.big_sig0.borrow()
        );

        MajorCols::<AB::F>::eval::<AB>(
            builder, 
            BUS_INDEX, 
            local.prev_seed[0], 
            local.prev_seed[1], 
            local.prev_seed[2],
            local.maj.borrow()
        );

        for i in 0..NUM_ROUNDS {
            // TODO: Add gadget with choosen round
            // let t1 = [
            //     local.prev_seed[7],
            //     local.big_sig1.xor3.value,
            //     local.ch.value,
            //     AB::Expr::from_canonical_u32(SHA256_K[])
            // ]
            // AddGadget::<AB::F, 5>::eval::<AB>(
            //     builder, 
            //     BUS_INDEX, 
            //     t1, 
            //     cols
            // );
        }
    }
}

#[inline]
pub(crate) fn eval_round_flags<AB: AirBuilder>(builder: &mut AB) {
    // Access the main trace matrix.
    let main = builder.main();

    // Get the local (current) row and the next row slices.
    let (local, next) = (main.row_slice(0), main.row_slice(1));

    // Cast slices into typed Keccak column references.
    let local: &ShaCols<AB::Var> = (*local).borrow();
    let next: &ShaCols<AB::Var> = (*next).borrow();

    // Initially, the first step flag should be 1 while the others should be 0.
    //
    // Constraint: In the first row, the first flag is 1.
    builder
        .when_first_row()
        .assert_one(local.step_flags[0].clone());
    // Constraint: In the first row, all other flags are 0.

    for i in 1..NUM_ROUNDS {
        builder
            .when_first_row()
            .assert_zero(local.step_flags[i].clone());
    }

    // Constraint: In all transitions, flags rotate forward.
    //
    // Formally, for each flag i in the local row, it should equal the next row's flag at (i + 1) mod NUM_ROUNDS.
    //
    // This ensures that exactly one flag "moves forward" each step in a cyclic manner.

    for i in 0..NUM_ROUNDS {
        builder.when_transition().assert_zero(
            local.step_flags[i].clone() - next.step_flags[(i + 1) % NUM_ROUNDS].clone(),
        );
    }
}

fn try_clone_array<T: Clone, const N: usize>(slice: &[T]) -> [T; N] {
    // Check at runtime that the length is correct (should always hold).
    assert!(slice.len() == N, "Incorrect length");

    // Clone each element into a new array.
    array::from_fn(|i| slice[i].clone())
}
