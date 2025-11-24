use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::Field;
use crate::{
    builder::ChipBuilder,
    chips::byte::{ByteLookupChip, ByteLookupOp},
};

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
    pub fn populate(&mut self, lookup: &mut ByteLookupChip, inputs_u32: [u32; N]) -> u32 {
        let expected = inputs_u32.iter().sum::<u32>();
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);

        let inputs = inputs_u32
            .iter()
            .map(|&x| x.to_le_bytes())
            .collect::<Vec<[u8; U32_LIMBS]>>();

        let base = 256;
        let mut carry = [0u8; N];
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
        inputs: [[AB::Var; U32_LIMBS]; N],
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
                    let is_carry = &cols.is_carry[i][j].clone();
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
                    cols.is_carry.iter().enumerate().fold(AB::Expr::ZERO, |acc, (j, is_carry_col)| {
                        acc + is_carry_col[i].clone() * AB::F::from_canonical_u32(j as u32)
                    })
                );             
            }
        }

        // Compare the sum and summands by looking at carry.
        {
            let base = AB::F::from_canonical_u32(256);
            for i in 0..U32_LIMBS {
                let mut overflow = AB::Expr::ZERO;
                for input in inputs {
                    overflow += input[i].clone().into();
                }
                overflow -= cols.value[i].clone().into();

                if i > 0 {
                    overflow += cols.carry[i - 1].clone().into();
                }
                builder.assert_eq(cols.carry[i] * base, overflow.clone());
            }
        }
    }
}
