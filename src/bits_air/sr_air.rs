use core::borrow::Borrow;

use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_air::AirBuilder;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_sha512::chips::byte::{ByteLookupChip, ByteLookupOp};

use crate::constants::U32_LIMBS;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightCols<T> {
    /// The output value.
    pub value: [T; U32_LIMBS],

    // /// The c_mod == 0 condition of `shrcarry` on each byte of a word.
    // pub c_mod_is_zero: [T; U32_LIMBS],

    // /// b << (8 - c_mod) of `shrcarry` on each byte of a word.
    // pub left_aligned_carry: [T; U32_LIMBS],

    // /// b - (b >> c_mod) << c_mod of `shrcarry` on each byte of a word.
    // pub shift_remainder: [T; U32_LIMBS],
    // pub shift_overflow: [T; U32_LIMBS],

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: [T; U32_LIMBS],

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: [T; U32_LIMBS],
}


pub const NUM_SHIFT_RIGHT_COLS: usize = size_of::<ShiftRightCols<u8>>();

impl<F: PrimeField32> ShiftRightCols<F> {
    pub const fn nb_bytes_to_shift(rotation: usize) -> usize {
        rotation / 8
    }

    pub const fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 8
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (8 - nb_bits_to_shift)
    }

    pub fn populate(&mut self, lookup: &ByteLookupChip, input: u32, rotation: usize) -> u32 {
        let input_bytes = input.to_le_bytes().map(F::from_canonical_u8);
        let expected = input >> rotation;

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_canonical_u32(Self::carry_multiplier(rotation));

        let mut input_bytes_rotated = [F::ZERO; U32_LIMBS];
        for i in 0..U32_LIMBS {
            if i + nb_bytes_to_shift < U32_LIMBS {
                input_bytes_rotated[i] = input_bytes[(i + nb_bytes_to_shift) % U32_LIMBS];
            }
        }

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::ZERO;
        let mut last_carry = F::ZERO;
        for i in (0..U32_LIMBS).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;
            // self.shift_overflow[i] = F::ZERO;

            // let (shift, carry) = {
            //     let c_mod = c & 0x7;
            //     if c_mod != 0 {
            //         let res = b >> c_mod;
            //         let remainder = b - (res << c_mod);
            //         let carry = (b << (8 - c_mod)) >> (8 - c_mod);
            //         self.c_mod_is_zero[i] = F::ZERO;
            //         self.left_aligned_carry[i] = F::from_canonical_u8(b << (8 - c_mod));
            //         if ((b as u32) << (8 - c_mod)) > 255 {
            //             self.shift_overflow[i] =
            //                 F::from_canonical_u8(((b as u32) << (8 - c_mod) >> 8) as u8);
            //         }
            //         self.shift_remainder[i] = F::from_canonical_u8(remainder);
            //         (res, carry)
            //     } else {
            //         self.c_mod_is_zero[i] = F::ONE;
            //         self.left_aligned_carry[i] = F::ZERO;
            //         (b, 0u8)
            //     }
            // };


            let req = lookup.request(b, c, ByteLookupOp::ShrCarry);
            let shift = req[0];
            let carry = req[1];

            self.shift[i] = F::from_canonical_u8(shift);
            self.carry[i] = F::from_canonical_u8(carry);

            if i == U32_LIMBS - 1 {
                first_shift = self.shift[i];
            } else {
                self.value[i] = self.shift[i] + last_carry * carry_multiplier;
            }

            last_carry = self.carry[i];
        }

        // For the first byte, we didn't know the last carry so compute the rotated byte here.
        self.value[U32_LIMBS - 1] = first_shift;

        // Check that the value is correct.
        assert_eq!(
            u32::from_le_bytes(self.value.map(|x| x.to_string().parse::<u8>().unwrap())),
            expected
        );

        expected
    }

    pub fn eval<AB: InteractionBuilder>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        input: [AB::Expr; U32_LIMBS],
        rotation: usize,
        cols: &ShiftRightCols<AB::Var>,
    ) {
        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated: [<AB as AirBuilder>::Expr; U32_LIMBS] = std::array::from_fn(|i| {
            if i + nb_bytes_to_shift < U32_LIMBS {
                input[(i + nb_bytes_to_shift) % U32_LIMBS].clone().into()
            } else {
                AB::Expr::ZERO
            }
        });

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = AB::Expr::ZERO;
        let mut last_carry = AB::Expr::ZERO;
        for i in (0..U32_LIMBS).rev() {
            let b = input_bytes_rotated[i].clone();
            let c = nb_bits_to_shift as u8;
            let mut interaction_data: Vec<AB::Expr> = Vec::new();

            interaction_data.push(b);
            interaction_data.push(AB::Expr::from_canonical_u8(c));
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::ShrCarry as u8));
            interaction_data.push(cols.shift[i].into());
            interaction_data.push(cols.carry[i].into());

            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);

            // let c_mod = (nb_bits_to_shift & 0x07) as u8;

            // let c_mod_not_zero = AB::Expr::ONE - cols.c_mod_is_zero[i].clone();
            // // assert when c_mod is zero
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(AB::F::from_canonical_u8(c_mod));
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_eq(input_bytes_rotated[i].clone(), cols.shift[i].clone());
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(cols.carry[i].clone());
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(cols.left_aligned_carry[i].clone());
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(cols.shift_overflow[i].clone());

            // // assert when c_mod is not zero
            // let left_shift_amount = 8 - c_mod;
            // builder.when(c_mod_not_zero.clone()).assert_eq(
            //     input_bytes_rotated[i].clone(),
            //     cols.shift[i].clone().into().mul_2exp_u64(c_mod as u64)
            //         + cols.shift_remainder[i].clone(),
            // );
            // builder.when(c_mod_not_zero.clone()).assert_eq(
            //     cols.left_aligned_carry[i].clone()
            //         + cols.shift_overflow[i].clone().into().mul_2exp_u64(8),
            //     input_bytes_rotated[i]
            //         .clone()
            //         .mul_2exp_u64(left_shift_amount as u64),
            // );
            // builder.when(c_mod_not_zero).assert_eq(
            //     cols.carry[i]
            //         .clone()
            //         .into()
            //         .mul_2exp_u64(left_shift_amount as u64),
            //     cols.left_aligned_carry[i].clone(),
            // );

            // // assert when c_mod is zero
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_eq(cols.shift[i].clone(), input_bytes_rotated[i].clone());
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(cols.carry[i].clone());
            // builder
            //     .when(cols.c_mod_is_zero[i].clone())
            //     .assert_zero(cols.left_aligned_carry[i].clone());
            if i == U32_LIMBS - 1 {
                first_shift = cols.shift[i].clone().into();
            } else {
                builder.assert_eq(
                    cols.value[i].clone(),
                    cols.shift[i].clone() + last_carry * carry_multiplier.clone(),
                );
            }

            last_carry = cols.carry[i].clone().into();
        }

        // For the first byte, we didn't know the last carry so compute the rotated byte here.
        builder.assert_eq(
            cols.value[U32_LIMBS - 1].clone(),
            first_shift,
        );
    }
}

impl<F> Borrow<ShiftRightCols<F>> for [F] {
    fn borrow(&self) -> &ShiftRightCols<F> {
        debug_assert_eq!(self.len(), NUM_SHIFT_RIGHT_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ShiftRightCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
