use std::{array, borrow::Borrow};

use derive::AlignedBorrow;
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use crate::chips::byte::ByteLookupChip;

use crate::{
    gadgets::{rotr::RightRotateGadget, sr::ShiftRightGadget, xor::Xor3Gadget},
    constants::U32_LIMBS,
};

const BUS_INDEX: u16 = 10;

#[derive(Default, Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct SmallSigmaCols<T> {
    pub input: [T; U32_LIMBS],
    pub rrots: [RightRotateGadget<T>; 2],
    pub sr: ShiftRightGadget<T>,
    pub xor3: Xor3Gadget<T>,
}

pub const NUM_SMALL_SIGMA_COLS: usize = size_of::<SmallSigmaCols<u8>>();

#[derive(Debug)]
pub struct SmallSigma0Air {}

impl SmallSigma0Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig0_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}

impl<F> BaseAir<F> for SmallSigma0Air {
    fn width(&self) -> usize {
        NUM_SMALL_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for SmallSigma0Air {}

impl<F> PartitionedBaseAir<F> for SmallSigma0Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for SmallSigma0Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SmallSigmaCols<AB::Var> = (*local).borrow();

        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            BUS_INDEX,
            input.clone(),
            7,
            &local.rrots[0],
        );
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            BUS_INDEX,
            input.clone(),
            18,
            &local.rrots[1],
        );
        ShiftRightGadget::<AB::F>::eval(builder, BUS_INDEX, input.clone(), 3, &local.sr);
        Xor3Gadget::<AB::F>::eval(
            builder,
            BUS_INDEX,
            local.rrots[0].value,
            local.rrots[1].value,
            local.sr.value,
            &local.xor3,
        );
    }
}

fn generate_sig0_trace_rows<F: PrimeField32>(
    row: &mut SmallSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(|i| F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 7);
    let y = row.rrots[1].populate(byte_lookup, input, 18);
    let z = row.sr.populate(byte_lookup, input, 3);

    row.xor3.populate(byte_lookup, x, y, z);
}

#[derive(Debug)]
pub struct SmallSigma1Air {}

impl SmallSigma1Air {
    pub fn generate_trace_rows<F: PrimeField32>(
        &self,
        byte_lookup: &ByteLookupChip,
        input: u32,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let trace_length = NUM_SMALL_SIGMA_COLS;
        let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
        long_trace.truncate(trace_length);

        let mut trace = RowMajorMatrix::new(long_trace, NUM_SMALL_SIGMA_COLS);
        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<SmallSigmaCols<F>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), 1);

        generate_sig1_trace_rows(&mut rows[0], byte_lookup, input);
        trace
    }
}

impl<F> BaseAir<F> for SmallSigma1Air {
    fn width(&self) -> usize {
        NUM_SMALL_SIGMA_COLS
    }
}

impl<F> BaseAirWithPublicValues<F> for SmallSigma1Air {}

impl<F> PartitionedBaseAir<F> for SmallSigma1Air {}

impl<AB: InteractionBuilder<F: PrimeField32>> Air<AB> for SmallSigma1Air {
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SmallSigmaCols<AB::Var> = (*local).borrow();

        let input = [
            local.input[0].into(),
            local.input[1].into(),
            local.input[2].into(),
            local.input[3].into(),
        ];
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            BUS_INDEX,
            input.clone(),
            7,
            &local.rrots[0],
        );
        RightRotateGadget::<AB::F>::eval::<AB>(
            builder,
            BUS_INDEX,
            input.clone(),
            18,
            &local.rrots[1],
        );
        ShiftRightGadget::<AB::F>::eval(builder, BUS_INDEX, input.clone(), 3, &local.sr);
        Xor3Gadget::<AB::F>::eval(
            builder,
            BUS_INDEX,
            local.rrots[0].value,
            local.rrots[1].value,
            local.sr.value,
            &local.xor3,
        );
    }
}

fn generate_sig1_trace_rows<F: PrimeField32>(
    row: &mut SmallSigmaCols<F>,
    byte_lookup: &ByteLookupChip,
    input: u32,
) {
    let input_bytes = input.to_le_bytes();
    row.input = array::from_fn(|i| F::from_canonical_u8(input_bytes[i]));

    let x = row.rrots[0].populate(byte_lookup, input, 17);
    let y = row.rrots[1].populate(byte_lookup, input, 19);
    let z = row.sr.populate(byte_lookup, input, 10);

    row.xor3.populate(byte_lookup, x, y, z);
}

pub mod tests {
    use std::sync::Arc;

    use openvm_stark_backend::{
        AirRef,
        prover::types::{AirProvingContext, ProvingContext},
    };
    use openvm_stark_sdk::{
        config::{FriParameters, baby_bear_keccak::BabyBearKeccakEngine, setup_tracing},
        engine::{StarkEngine, StarkFriEngine},
        utils::create_seeded_rng,
    };
    use crate::chips::byte::ByteLookupChip;
    use rand::Rng;

    use crate::bits_air::small_sig_air::{BUS_INDEX, SmallSigma0Air};
    const LOG_BLOWUP: usize = 1;

    #[test]
    fn test_small_sig() {
        setup_tracing();

        let mut rng = create_seeded_rng();

        let byte_chip = ByteLookupChip::new(BUS_INDEX);

        let input: u32 = rng.r#gen();

        let air = SmallSigma0Air {};
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
