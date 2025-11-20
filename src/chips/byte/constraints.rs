use std::borrow::{Borrow, BorrowMut};

use openvm_stark_backend::{
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::chips::byte::{
    ByteLookupOp,
    bus::ByteLookupBus,
    columns::{
        ByteLookupCols, ByteLookupPreprocessedCols, NUM_BYTE_LOOKUP_COLS,
        NUM_BYTE_LOOKUP_PREPROCESSED_COLS,
    },
    utils::shr_carry,
};
use itertools::Itertools;

pub const NUM_ROWS: usize = 1 << 16;

#[derive(Clone, Copy, Debug, derive_new::new)]
pub struct ByteLookupAir {
    pub bus: ByteLookupBus,
}

impl<F: Field> BaseAirWithPublicValues<F> for ByteLookupAir {}
impl<F: Field> PartitionedBaseAir<F> for ByteLookupAir {}
impl<F: Field> BaseAir<F> for ByteLookupAir {
    fn width(&self) -> usize {
        NUM_BYTE_LOOKUP_COLS
    }

    /// Generates a preprocessed table with a row for each possible triple (x, y, x^y)
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_ROWS * NUM_BYTE_LOOKUP_PREPROCESSED_COLS],
            NUM_BYTE_LOOKUP_PREPROCESSED_COLS,
        );

        let opcodes = ByteLookupOp::all();

        for (row_index, (x, y)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let col: &mut ByteLookupPreprocessedCols<F> =
                initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.x = F::from_canonical_u8(x);
            col.y = F::from_canonical_u8(y);

            // Iterate over all operations for results and updating the table map.
            for opcode in opcodes.iter() {
                match opcode {
                    // default => {}
                    ByteLookupOp::Xor => {
                        let xor = x ^ y;
                        col.xor = F::from_canonical_u8(xor);
                    }
                    ByteLookupOp::ShrCarry => {
                        let (res, carry) = shr_carry(x, y);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                    }
                    ByteLookupOp::And => {
                        let and = x & y;
                        col.and = F::from_canonical_u8(and);
                    }
                };
            }
        }

        Some(initial_trace)
    }
}

impl<AB> Air<AB> for ByteLookupAir
where
    AB: InteractionBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ByteLookupPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let local = main.row_slice(0);
        let local: &ByteLookupCols<AB::Var> = (*local).borrow();

        // Enforce that (x, y, x^y) exists in the lookup table
        self.bus
            .receive(
                prep_local.x,
                prep_local.y,
                super::ByteLookupOp::Xor,
                vec![prep_local.xor.into(), AB::Expr::ZERO],
            )
            .eval(builder, local.muls[ByteLookupOp::Xor as usize]);

        // Enforce that (x, y, x >> y, <carry>) exists in the lookup table
        self.bus
            .receive(
                prep_local.x,
                prep_local.y,
                super::ByteLookupOp::ShrCarry,
                vec![prep_local.shr, prep_local.shr_carry],
            )
            .eval(builder, local.muls[ByteLookupOp::ShrCarry as usize]);

        // Enforce that (x, y, x & y) exists in the lookup table
        self.bus
            .receive(
                prep_local.x,
                prep_local.y,
                super::ByteLookupOp::And,
                vec![prep_local.and.into(), AB::Expr::ZERO],
            )
            .eval(builder, local.muls[ByteLookupOp::And as usize]);
    }
}
