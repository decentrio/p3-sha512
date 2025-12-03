use crate::{
    builder::ChipBuilder,
    chips::byte::{ByteLookupChip, ByteLookupOp},
};
use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::Field;

use crate::constants::U32_LIMBS;

use p3_field::FieldAlgebra;

/// A set of columns needed to compute the add of two words.
#[derive(Clone, Copy, Debug, AlignedBorrow)]
#[repr(C)]
pub struct AddGadget<T, const N: usize> {
    /// The result of `a + b`.
    pub value: [T; U32_LIMBS],

    /// Trace.
    pub is_carry: [[T; U32_LIMBS]; N],
    /// The carry for the `n`th limb.
    pub carry: [T; U32_LIMBS],
}

impl<F: Field, const N: usize> AddGadget<F, N> {
    pub fn populate(&mut self, lookup: &ByteLookupChip, inputs_u32: [u32; N]) -> u32 {
        let expected = inputs_u32.iter().fold::<u32, _>(0, |acc, x| acc.wrapping_add(*x));
        // let expected: u32 = inputs_u32.iter().sum();
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        let inputs = inputs_u32
            .iter()
            .map(|&x| x.to_le_bytes())
            .collect::<Vec<[u8; U32_LIMBS]>>();

        let base = 256;
        let mut carry = [0u8; 5];
        for i in 0..U32_LIMBS {
            let mut column_sum = inputs.iter().map(|input| input[i] as u32).sum::<u32>();
            if i > 0 {
                column_sum += carry[i - 1] as u32;
            }
            carry[i] = (column_sum / base) as u8;
            self.is_carry
                .iter_mut()
                .enumerate()
                .for_each(|(j, is_carry_col)| {
                    is_carry_col[i] = F::from_bool(carry[i] == j as u8);
                });
            self.carry[i] = F::from_canonical_u8(carry[i]);
            debug_assert!(carry[i] <= (N - 1) as u8);
            debug_assert_eq!(self.value[i], F::from_canonical_u32(column_sum % base));
        }

        {
            let mut inputs_and_result = inputs.clone();
            inputs_and_result.push(expected.to_le_bytes());

            inputs_and_result
                .into_iter()
                .for_each(|bytes| lookup.request_u8_range_checks(bytes));
        }
        expected
    }

    pub fn eval<AB: ChipBuilder>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        inputs: [[impl Into<AB::Expr> + Clone; U32_LIMBS]; N],
        cols: &AddGadget<AB::Var, N>,
    ) {
        // Range check each byte.
        {
            inputs.iter().for_each(|bytes| {
                builder.slice_range_check_u8(lookup_bus, bytes);
            });
            builder.slice_range_check_u8(lookup_bus, &cols.value);
        }
        // Each value in is_carry_{0,1,2,3,4} is 0 or 1, and exactly one of them is 1 per digit.
        {
            for i in 0..U32_LIMBS {
                let mut is_carry_sum = AB::Expr::ZERO;
                for j in 0..N {
                    // Assert booleanity.
                    let is_carry = &cols.is_carry[j][i];
                    is_carry_sum = is_carry_sum + is_carry.clone();
                    builder.assert_bool(is_carry.clone());
                }
                builder.assert_eq(is_carry_sum, AB::Expr::ONE);
            }
        }
        // Calculates carry from is_carry_{0,1,2,...,N-1}.
        {
            for i in 0..U32_LIMBS {
                builder.assert_eq(
                    cols.carry[i],
                    cols.is_carry.iter().enumerate().fold(
                        AB::Expr::ZERO,
                        |acc, (j, is_carry_col)| {
                            acc + is_carry_col[i].clone() * AB::F::from_canonical_u32(j as u32)
                        },
                    ),
                );
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            let base = AB::F::from_canonical_u32(256);
            for i in 0..U32_LIMBS {
                let mut overflow = AB::Expr::ZERO;
                for input in inputs.iter() {
                    overflow += input[i].clone().into();
                }
                overflow -= cols.value[i].into();

                if i > 0 {
                    overflow += cols.carry[i - 1].into();
                }
                builder.assert_eq(cols.carry[i] * base, overflow.clone());
            }
        }
    }
}

pub mod tests {
    use std::{borrow::Borrow, sync::Arc, vec};

    use openvm_stark_backend::{
        AirRef,
        interaction::{BusIndex, InteractionBuilder},
        prover::types::{AirProvingContext, ProvingContext},
        rap::{BaseAirWithPublicValues, PartitionedBaseAir},
    };
    use openvm_stark_sdk::{
        config::{FriParameters, baby_bear_keccak::BabyBearKeccakEngine, setup_tracing},
        engine::{StarkEngine, StarkFriEngine},
        utils::create_seeded_rng,
    };
    use p3_air::{Air, BaseAir};
    use p3_field::{FieldAlgebra, PrimeField32};
    use p3_matrix::{Matrix, dense::RowMajorMatrix};
    use rand::Rng;

    use crate::{builder::ChipBuilder, chips::byte::ByteLookupChip, gadgets::add::AddGadget};

    const BYTE_XOR_BUS: BusIndex = 10;
    const LOG_BLOWUP: usize = 2;

    #[derive(Debug)]
    pub struct ExampleAir<const N: usize> {
        inputs: [u32; N],
    }

    impl<const N: usize> ExampleAir<N> {
        pub fn generate_trace_rows<F: PrimeField32>(
            &mut self,
            rng: &mut impl Rng,
            byte_lookup: &ByteLookupChip,
            extra_capacity_bits: usize,
        ) -> RowMajorMatrix<F> {
            let trace_length = size_of::<AddGadget<u8, N>>();
            let num_rows = 500000usize.next_power_of_two();
            let mut long_trace = F::zero_vec((trace_length * num_rows) << extra_capacity_bits);

            println!(
                "Generating right rotate trace... {:?}",
                (trace_length * num_rows) << extra_capacity_bits
            );
            long_trace.truncate(trace_length * num_rows);

            let mut trace = RowMajorMatrix::new(long_trace, trace_length);

            let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<AddGadget<F, N>>() };
            assert!(prefix.is_empty(), "Alignment should match");
            assert!(suffix.is_empty(), "Alignment should match");
            assert_eq!(rows.len(), num_rows);

            let mut inputs = [0u32; N];
            inputs.iter_mut().for_each(|input| {
                *input = rng.gen_range(0..u32::MAX / N as u32 - 1);
            });

            for row in rows.iter_mut() {
                row.populate(byte_lookup, inputs);
            }
            self.inputs = inputs;
            trace
        }
    }

    impl<F, const N: usize> BaseAir<F> for ExampleAir<N> {
        fn width(&self) -> usize {
            size_of::<AddGadget<u8, N>>()
        }
    }

    impl<F, const N: usize> BaseAirWithPublicValues<F> for ExampleAir<N> {}

    impl<F, const N: usize> PartitionedBaseAir<F> for ExampleAir<N> {}

    impl<AB: ChipBuilder<F: PrimeField32>, const N: usize> Air<AB> for ExampleAir<N> {
        #[inline]
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &AddGadget<AB::Var, N> = (*local).borrow();

            let inputs = self.inputs.map(|input| {
                let bytes = input.to_le_bytes();
                bytes.map(|b| AB::Expr::from_canonical_u8(b))
            });

            AddGadget::<AB::F, N>::eval(builder, BYTE_XOR_BUS, inputs, local);
        }
    }

    #[test]
    fn test_add() {
        // WARNING: Use a real cryptographic PRNG in applications!!
        setup_tracing();

        let mut rng = create_seeded_rng();
        let byte_chip = ByteLookupChip::new(BYTE_XOR_BUS);

        let mut air = ExampleAir::<5> { inputs: [0u32; 5] };

        let trace = air.generate_trace_rows(&mut rng, &byte_chip, LOG_BLOWUP);
        let byte_trace = byte_chip.generate_trace();

        let mut all_chips: Vec<AirRef<_>> = vec![];

        all_chips.push(Arc::new(air));
        all_chips.push(Arc::new(byte_chip.air));

        let all_traces = vec![trace, byte_trace];

        let engine = BabyBearKeccakEngine::new(
            FriParameters::standard_with_100_bits_conjectured_security(LOG_BLOWUP),
        );
        let mut keygen_builder = engine.keygen_builder();

        let ctxs = all_chips
            .into_iter()
            .map(|air| keygen_builder.add_air(air))
            .zip(all_traces.into_iter())
            .map(|(id, trace)| (id, AirProvingContext::simple_no_pis(Arc::new(trace))))
            .collect::<Vec<_>>();

        let pk = keygen_builder.generate_pk();

        engine
            .prove_then_verify(&pk, ProvingContext::new(ctxs))
            .unwrap();
    }
}
