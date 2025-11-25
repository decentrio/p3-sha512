use crate::{chips::byte::ByteLookupChip, gadgets::{rotr::RightRotateGadget, sr::ShiftRightGadget, xor::Xor3Gadget}};
use derive::AlignedBorrow;
use openvm_stark_backend::interaction::{BusIndex, InteractionBuilder};
use p3_field::PrimeField32;


#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct SmallSigma0Cols<T> {
    pub rrots: [RightRotateGadget<T>; 2],
    pub sr: ShiftRightGadget<T>,
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_SMALL_SIGMA_0_COLS: usize = size_of::<SmallSigma0Cols<u8>>();

impl<F: PrimeField32> SmallSigma0Cols<F> {
    pub fn populate(&mut self, byte_lookup: &ByteLookupChip, input: u32) -> u32 {
        let x = self.rrots[0].populate(byte_lookup, input, 7);
        let y = self.rrots[1].populate(byte_lookup, input, 18);
        let z = self.sr.populate(byte_lookup, input, 3);

        self.xor3.populate(byte_lookup, x, y, z)
    }

    pub fn eval<AB: InteractionBuilder<F: PrimeField32>>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        input: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &SmallSigma0Cols<AB::Var>,
    ) {
        let mut input_iter = input.into_iter();
        let input = [
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(builder, lookup_bus, input.clone(), 7, &cols.rrots[0]);
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            lookup_bus,
            input.clone(),
            18,
            &cols.rrots[1],
        );
        ShiftRightGadget::<AB::F>::eval(builder, lookup_bus, input.clone(), 3, &cols.sr);
        Xor3Gadget::<AB::F>::eval(
            builder,
            lookup_bus,
            cols.rrots[0].value,
            cols.rrots[1].value,
            cols.sr.value,
            &cols.xor3,
        );
    }
}

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct SmallSigma1Cols<T> {
    pub rrots: [RightRotateGadget<T>; 2],
    pub sr: ShiftRightGadget<T>,
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_SMALL_SIGMA_1_COLS: usize = size_of::<SmallSigma1Cols<u8>>();

impl<F: PrimeField32> SmallSigma1Cols<F> {
    pub fn populate(&mut self, byte_lookup: &ByteLookupChip, input: u32) -> u32 {
        let x = self.rrots[0].populate(byte_lookup, input, 17);
        let y = self.rrots[1].populate(byte_lookup, input, 19);
        let z = self.sr.populate(byte_lookup, input, 10);

        self.xor3.populate(byte_lookup, x, y, z)
    }

    pub fn eval<AB: InteractionBuilder<F: PrimeField32>>(
        builder: &mut AB,
        lookup_bus: BusIndex,
        input: impl IntoIterator<Item = impl Into<AB::Expr>>,
        cols: &SmallSigma1Cols<AB::Var>,
    ) {
        let mut input_iter = input.into_iter();
        let input = [
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
            input_iter.next().unwrap().into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            lookup_bus,
            input.clone(),
            17,
            &cols.rrots[0],
        );
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            lookup_bus,
            input.clone(),
            19,
            &cols.rrots[1],
        );
        ShiftRightGadget::<AB::F>::eval(builder, lookup_bus, input.clone(), 10, &cols.sr);
        Xor3Gadget::<AB::F>::eval(
            builder,
            lookup_bus,
            cols.rrots[0].value,
            cols.rrots[1].value,
            cols.sr.value,
            &cols.xor3,
        );
    }
}

pub mod tests {
    use std::{borrow::Borrow, sync::Arc};

    use crate::{bits_air::small_sig_air::NUM_SMALL_SIGMA_0_COLS, chips::byte::ByteLookupChip};
    use openvm_stark_backend::{
        AirRef,
        interaction::InteractionBuilder,
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

    use crate::bits_air::small_sig_air::SmallSigma0Cols;
    const LOG_BLOWUP: usize = 1;

    const BUS_INDEX: u16 = 10;

    #[derive(Debug)]
    pub struct ExampleAir {
        input: u32,
    }

    impl ExampleAir {
        pub fn generate_trace_rows<F: PrimeField32>(
            &self,
            byte_lookup: &ByteLookupChip,
            input: u32,
            extra_capacity_bits: usize,
        ) -> RowMajorMatrix<F> {
            let trace_length = NUM_SMALL_SIGMA_0_COLS;
            let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
            long_trace.truncate(trace_length);

            let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA_0_COLS);
            let (prefix, rows, suffix) =
                unsafe { trace.values.align_to_mut::<SmallSigma0Cols<F>>() };
            assert!(prefix.is_empty(), "Alignment should match");
            assert!(suffix.is_empty(), "Alignment should match");
            assert_eq!(rows.len(), 1);

            rows[0].populate(byte_lookup, input);
            trace
        }
    }

    impl<F> BaseAir<F> for ExampleAir {
        fn width(&self) -> usize {
            NUM_SMALL_SIGMA_0_COLS
        }
    }

    impl<F> BaseAirWithPublicValues<F> for ExampleAir {}

    impl<F> PartitionedBaseAir<F> for ExampleAir {}

    impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for ExampleAir {
        #[inline]
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &SmallSigma0Cols<AB::Var> = (*local).borrow();

            let input: Vec<AB::Expr> = self
                .input
                .to_le_bytes()
                .iter()
                .map(|x| AB::Expr::from_canonical_u8(*x))
                .collect();
            SmallSigma0Cols::<AB::F>::eval::<AB>(builder, BUS_INDEX, input, local);
        }
    }
    #[test]
    fn test_small_sig() {
        setup_tracing();

        let mut rng = create_seeded_rng();

        let byte_chip = ByteLookupChip::new(BUS_INDEX);

        let input: u32 = rng.r#gen();

        let air = ExampleAir { input };
        let trace = air.generate_trace_rows(&byte_chip, input, LOG_BLOWUP);

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
