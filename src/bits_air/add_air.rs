use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::Field;
use p3_sha512::{
    builder::ChipBuilder,
    chips::byte::{ByteLookupChip, ByteLookupOp},
};

use crate::constants::U32_LIMBS;

use p3_field::FieldAlgebra;

/// A set of columns needed to compute the add of two words.
#[derive(Clone, Copy, Debug, Default, AlignedBorrow)]
#[repr(C)]
pub struct AddGadget<T> {
    /// The result of `a + b`.
    pub value: [T; U32_LIMBS],

    /// Trace.
    pub carry: [T; 3],
}

impl<F: Field> AddGadget<F> {
    pub fn populate(&mut self, lookup: &mut ByteLookupChip, a_u32: u32, b_u32: u32) -> u32 {
        let expected = a_u32.wrapping_add(b_u32);
        self.value = expected.to_le_bytes().map(F::from_canonical_u8);
        let a = a_u32.to_le_bytes();
        let b = b_u32.to_le_bytes();

        let mut carry = [0u8, 0u8, 0u8];
        if (a[0] as u32) + (b[0] as u32) > 255 {
            carry[0] = 1;
            self.carry[0] = F::ONE;
        }
        if (a[1] as u32) + (b[1] as u32) + (carry[0] as u32) > 255 {
            carry[1] = 1;
            self.carry[1] = F::ONE;
        }
        if (a[2] as u32) + (b[2] as u32) + (carry[1] as u32) > 255 {
            carry[2] = 1;
            self.carry[2] = F::ONE;
        }

        let base = 256u32;
        let overflow = a[0]
            .wrapping_add(b[0])
            .wrapping_sub(expected.to_le_bytes()[0]) as u32;
        debug_assert_eq!(overflow.wrapping_mul(overflow.wrapping_sub(base)), 0);

        // Range check
        {
            lookup.request_u8_range_checks(a);
            lookup.request_u8_range_checks(b);
            lookup.request_u8_range_checks(expected.to_le_bytes());
        }
        expected
    }

    pub fn eval<AB: ChipBuilder>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        a: [AB::Var; U32_LIMBS],
        b: [AB::Var; U32_LIMBS],
        cols: &AddGadget<AB::Var>,
    ) {
        let one = AB::Expr::ONE;
        let base = AB::F::from_canonical_u32(256);

        // For each limb, assert that difference between the carried result and the non-carried
        // result is either zero or the base.
        let overflow_0 = a[0] + b[0] - cols.value[0];
        let overflow_1 = a[1] + b[1] - cols.value[1] + cols.carry[0];
        let overflow_2 = a[2] + b[2] - cols.value[2] + cols.carry[1];
        let overflow_3 = a[3] + b[3] - cols.value[3] + cols.carry[2];
        builder.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
        builder.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
        builder.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
        builder.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));

        // If the carry is one, then the overflow must be the base.
        builder.assert_zero(cols.carry[0] * (overflow_0.clone() - base));
        builder.assert_zero(cols.carry[1] * (overflow_1.clone() - base));
        builder.assert_zero(cols.carry[2] * (overflow_2.clone() - base));

        // If the carry is not one, then the overflow must be zero.
        builder.assert_zero((cols.carry[0] - one.clone()) * overflow_0.clone());
        builder.assert_zero((cols.carry[1] - one.clone()) * overflow_1.clone());
        builder.assert_zero((cols.carry[2] - one.clone()) * overflow_2.clone());

        // Assert that the carry is either zero or one.
        builder.assert_bool(cols.carry[0]);
        builder.assert_bool(cols.carry[1]);
        builder.assert_bool(cols.carry[2]);

        // Range check each byte.
        {
            builder.slice_range_check_u8(lookup_bus, &a);
            builder.slice_range_check_u8(lookup_bus, &b);
            builder.slice_range_check_u8(lookup_bus, &cols.value);
        }
    }
}
