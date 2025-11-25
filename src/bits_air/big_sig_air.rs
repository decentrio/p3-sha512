use crate::{chips::byte::ByteLookupChip, gadgets::{rotr::RightRotateGadget, xor::Xor3Gadget}};
use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::PrimeField32;

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct BigSigma0Cols<T> {
    pub rrots: [RightRotateGadget<T>; 3],
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_BIG_SIGMA_0_COLS: usize = size_of::<BigSigma0Cols<u8>>();

impl<F: PrimeField32> BigSigma0Cols<F> {
    pub fn populate(&mut self, byte_lookup: &ByteLookupChip, input: u32) -> u32 {
        let x = self.rrots[0].populate(byte_lookup, input, 2);
        let y = self.rrots[1].populate(byte_lookup, input, 13);
        let z = self.rrots[2].populate(byte_lookup, input, 22);

        self.xor3.populate(byte_lookup, x, y, z)
    }

    pub fn eval<AB: InteractionBuilder<F: PrimeField32>>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        input: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &BigSigma0Cols<AB::Var>,
    ) {
        let mut input_iter = input.into_iter();
        let input = [
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
        ];

        RightRotateGadget::<AB::F>::eval::<AB>(builder, lookup_bus, input.clone(), 2, &cols.rrots[0]);
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            lookup_bus,
            input.clone(),
            13,
            &cols.rrots[1],
        );
        RightRotateGadget::<AB::F>::eval(builder, lookup_bus, input.clone(), 22, &cols.rrots[2]);
        Xor3Gadget::<AB::F>::eval(
            builder,
            lookup_bus,
            cols.rrots[0].value,
            cols.rrots[1].value,
            cols.rrots[2].value,
            &cols.xor3,
        );
    }
}

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct BigSigma1Cols<T> {
    pub rrots: [RightRotateGadget<T>; 3],
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_BIG_SIGMA_1_COLS: usize = size_of::<BigSigma1Cols<u8>>();

impl<F: PrimeField32> BigSigma1Cols<F> {
    pub fn populate(&mut self, byte_lookup: &ByteLookupChip, input: u32) -> u32 {
        let x = self.rrots[0].populate(byte_lookup, input, 6);
        let y = self.rrots[1].populate(byte_lookup, input, 11);
        let z = self.rrots[2].populate(byte_lookup, input, 25);

        self.xor3.populate(byte_lookup, x, y, z)
    }

    pub fn eval<AB: InteractionBuilder<F: PrimeField32>>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        input: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &BigSigma1Cols<AB::Var>,
    ) {
        let mut input_iter = input.into_iter();
        let input = [
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
        ];

        RightRotateGadget::<AB::F>::eval::<AB>(builder, lookup_bus, input.clone(), 6, &cols.rrots[0]);
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            lookup_bus,
            input.clone(),
            11,
            &cols.rrots[1],
        );
        RightRotateGadget::<AB::F>::eval(builder, lookup_bus, input.clone(), 25, &cols.rrots[2]);
        Xor3Gadget::<AB::F>::eval(
            builder,
            lookup_bus,
            cols.rrots[0].value,
            cols.rrots[1].value,
            cols.rrots[2].value,
            &cols.xor3,
        );
    }
}
