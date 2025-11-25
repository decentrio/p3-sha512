use openvm_stark_backend::air_builders::debug::DebugConstraintBuilder;
use openvm_stark_backend::air_builders::symbolic::SymbolicRapBuilder;
use openvm_stark_backend::config::StarkGenericConfig;
use openvm_stark_backend::interaction::BusIndex;
use openvm_stark_backend::interaction::InteractionBuilder;
use p3_field::Field;
use p3_field::FieldAlgebra;

use crate::chips::byte::ByteLookupOp;

pub trait ChipBuilder: InteractionBuilder {
    fn slice_range_check_u8(
        &mut self,
        lookup_bus: BusIndex,
        input: &[impl Into<Self::Expr> + Clone],
        // mult: impl Into<Self::Expr> + Clone,
    );
}

impl<F: Field> ChipBuilder for SymbolicRapBuilder<F> {
    fn slice_range_check_u8(
        &mut self,
        lookup_bus: BusIndex,
        input: &[impl Into<Self::Expr> + Clone],
        // mult: impl Into<Self::Expr> + Clone,
    ) {
        for pair in input.chunks(2) {
            let b = pair
                .get(0)
                .cloned()
                .map(Into::into)
                .unwrap_or(Self::Expr::ZERO);
            let c = pair
                .get(1)
                .cloned()
                .map(Into::into)
                .unwrap_or(Self::Expr::ZERO);

            let mut interaction_data: Vec<Self::Expr> = Vec::new();

            interaction_data.push(b);
            interaction_data.push(c);
            interaction_data.push(Self::Expr::from_canonical_u8(
                ByteLookupOp::U8RangeCheck as u8,
            ));
            interaction_data.push(Self::Expr::ZERO);
            interaction_data.push(Self::Expr::ZERO);

            self.push_interaction(lookup_bus, interaction_data, Self::Expr::ONE, 1);
        }
    }
}

impl<SC> ChipBuilder for DebugConstraintBuilder<'_, SC>
where
    SC: StarkGenericConfig,
{
    fn slice_range_check_u8(
        &mut self,
        _lookup_bus: BusIndex,
        _input: &[impl Into<Self::Expr> + Clone],
        // mult: impl Into<Self::Expr> + Clone,
    ) {
        // Skip for debug builder?
    }
}
