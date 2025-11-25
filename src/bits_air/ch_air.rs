use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::{PrimeField32, FieldAlgebra};

use crate::{chips::byte::{ByteLookupChip, ByteLookupOp}, constants::U32_LIMBS, utils::ch};

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct ChooseCols<T> {
    pub and_xy: [T; U32_LIMBS],
    pub andn_xz: [T; U32_LIMBS],
    pub value: [T; U32_LIMBS],
}

pub const NUM_CHOOSE_COLS: usize = size_of::<ChooseCols<u8>>();

impl<F: PrimeField32> ChooseCols<F> {
    pub fn populate(&mut self, lookup: &ByteLookupChip, x: u32, y: u32, z: u32) -> u32 {
        let expected = ch(x, y, z);
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        let z_bytes = z.to_le_bytes();

        for i in 0..U32_LIMBS {
            let req = lookup.request(x_bytes[i], y_bytes[i], ByteLookupOp::And);
            let and_xy = req[0];
            self.and_xy[i] = F::from_canonical_u8(and_xy);

            let req = lookup.request(1 - x_bytes[i], z_bytes[i], ByteLookupOp::And);
            let andn_xz = req[0];
            self.andn_xz[i] = F::from_canonical_u8(andn_xz);

            let req = lookup.request(and_xy, andn_xz, ByteLookupOp::Xor);
            self.value[i] = F::from_canonical_u8(req[0])
        }
        expected
    }

    pub fn eval<AB: InteractionBuilder> (
        builder: &mut AB,
        lookup_bus: BusIndex,
        x: impl IntoIterator<Item = impl Into<AB::Expr>>,
        y: impl IntoIterator<Item = impl Into<AB::Expr>>,
        z: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &ChooseCols<AB::Var>,
    ) {
        let mut x_iter = x.into_iter();
        let mut y_iter = y.into_iter();
        let mut z_iter = z.into_iter();
        for i in 0..U32_LIMBS {
            let x_i = x_iter.next().unwrap().into();
            
            let mut interaction_data: Vec<AB::Expr> = Vec::new();
            interaction_data.push(x_i.clone());
            interaction_data.push(y_iter.next().unwrap().into().clone());
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::And as u8));
            interaction_data.push(cols.and_xy[i].clone().into());
            interaction_data.push(AB::Expr::ZERO);
            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);

            let mut interaction_data: Vec<AB::Expr> = Vec::new();
            interaction_data.push(AB::Expr::ONE - x_i);
            interaction_data.push(z_iter.next().unwrap().into().clone());
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::And as u8));
            interaction_data.push(cols.andn_xz[i].clone().into());
            interaction_data.push(AB::Expr::ZERO);
            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);

            let mut interaction_data: Vec<AB::Expr> = Vec::new();
            interaction_data.push(cols.and_xy[i].clone().into());
            interaction_data.push(cols.andn_xz[i].clone().into());
            interaction_data.push(AB::Expr::from_canonical_u8(ByteLookupOp::Xor as u8));
            interaction_data.push(cols.value[i].clone().into());
            interaction_data.push(AB::Expr::ZERO);
            builder.push_interaction(lookup_bus, interaction_data, AB::Expr::ONE, 1);
        }
    }
}