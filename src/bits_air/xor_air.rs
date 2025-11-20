use core::borrow::Borrow;

use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_air::AirBuilder;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_sha512::chips::byte::{ByteLookupChip, ByteLookupOp, utils::shr_carry};

use crate::constants::U32_LIMBS;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Xor3Cols<T> {
    /// The result of `x ^ y`.
    pub xor_xy: [T; U32_LIMBS],
    /// The final result.
    pub value: [T; U32_LIMBS],
}
pub const NUM_XOR_COLS: usize = size_of::<Xor3Cols<u8>>();

impl<F: PrimeField32> Xor3Cols<F> {
    pub fn populate(&mut self, lookup: &ByteLookupChip, x: u32, y: u32, z: u32) -> u32 {
        let expected = x ^ y ^ z;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        let z_bytes = z.to_le_bytes();
        for i in 0..U32_LIMBS {
            let req = lookup.request(x_bytes[i], y_bytes[i], ByteLookupOp::Xor);
            let xor_xy = req[0];
            self.xor_xy[i] = F::from_canonical_u8(req[0]);
            let req = lookup.request(xor_xy, z_bytes[i], ByteLookupOp::Xor);
            self.value[i] = F::from_canonical_u8(req[0]);
        }
        expected
    }

    pub fn eval<AB: InteractionBuilder>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        x: impl IntoIterator<Item = impl Into<AB::Expr>>,
        y: impl IntoIterator<Item = impl Into<AB::Expr>>,
        z: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &Xor3Cols<AB::Var>,
    ) {
        let mut x_iter = x.into_iter();
        let mut y_iter = y.into_iter();
        let mut z_iter = z.into_iter();
        for i in 0..U32_LIMBS {
            let mut interaction_data: Vec<AB::Expr> = Vec::new();
            interaction_data.push(x_iter.nth(i).unwrap().into().clone());
            interaction_data.push(y_iter.nth(i).unwrap().into().clone());
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::Xor as u8));
            interaction_data.push(cols.xor_xy[i].clone().into());
            interaction_data.push(AB::Expr::ZERO);
            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);
        
            let mut interaction_data: Vec<AB::Expr> = Vec::new();
            interaction_data.push(cols.xor_xy[i].clone().into());
            interaction_data.push(z_iter.nth(i).unwrap().into().clone());
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::Xor as u8));
            interaction_data.push(cols.value[i].clone().into());
            interaction_data.push(AB::Expr::ZERO);
            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);
        }
    }
}

impl<F> Borrow<Xor3Cols<F>> for [F] {
    fn borrow(&self) -> &Xor3Cols<F> {
        debug_assert_eq!(self.len(), NUM_XOR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Xor3Cols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}