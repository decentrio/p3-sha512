use std::{borrow::Borrow, iter, sync::Arc};

use derive::AlignedBorrow;
use openvm_stark_backend::engine::StarkEngine;
use openvm_stark_backend::{
    AirRef,
    air_builders::PartitionedAirBuilder,
    interaction::{BusIndex, InteractionBuilder},
    prover::types::{AirProvingContext, ProvingContext},
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use openvm_stark_sdk::{
    config::{FriParameters, baby_bear_keccak::BabyBearKeccakEngine, setup_tracing},
    engine::StarkFriEngine,
    utils::create_seeded_rng,
};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use rand::Rng;
use sha2::digest::typenum::{Xor, int};

use crate::chips::byte::{ByteLookupChip, ByteLookupOp};

const LOG_BLOWUP: usize = 1;

const BYTE_XOR_BUS: BusIndex = 10;

// type Val = BabyBear;

#[repr(C)]
#[derive(Clone, Debug, AlignedBorrow)]
pub struct ByteInteractionCols<T> {
    pub x: T,
    pub y: T,
    pub res: [T; 2],
}

pub const NUM_BYTE_INTERACTION_COLS: usize = size_of::<ByteInteractionCols<u8>>();

#[derive(Clone, Copy, Debug)]
pub struct ByteInteractionAir {
    bus_index: BusIndex,
    op: ByteLookupOp,
}

impl<F> BaseAir<F> for ByteInteractionAir {
    fn width(&self) -> usize {
        NUM_BYTE_INTERACTION_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F> BaseAirWithPublicValues<F> for ByteInteractionAir {}

impl<F> PartitionedBaseAir<F> for ByteInteractionAir {}

impl<AB: InteractionBuilder + PartitionedAirBuilder> Air<AB> for ByteInteractionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &ByteInteractionCols<AB::Var> = (*local).borrow();

        let mut interaction_data: Vec<AB::Expr> = Vec::new();

        interaction_data.push(local.x.into());
        interaction_data.push(local.y.into());
        interaction_data.push(AB::Expr::from_canonical_u8(self.op as u8));

        interaction_data.push(local.res[0].into());
        interaction_data.push(local.res[1].into());

        builder.push_interaction(self.bus_index, interaction_data, AB::Expr::ONE, 1)
    }
}

#[test]
fn test_xor() {
    setup_tracing();

    let mut rng = create_seeded_rng();

    const LOG_XOR_REQUESTS: usize = 2;
    const LOG_NUM_REQUESTERS: usize = 2;

    const XOR_REQUESTS: usize = 1 << LOG_XOR_REQUESTS;
    const NUM_REQUESTERS: usize = 1 << LOG_NUM_REQUESTERS;

    const BYTE_XOR_BUS: u16 = 10;

    let xor_chip = ByteLookupChip::new(BYTE_XOR_BUS);

    let requesters_lists = (0..NUM_REQUESTERS)
        .map(|_| {
            (0..XOR_REQUESTS)
                .map(|_| {
                    let x = rng.r#gen::<u8>();
                    let y = rng.r#gen::<u8>();

                    (1, vec![x, y])
                })
                .collect::<Vec<(u8, Vec<u8>)>>()
        })
        .collect::<Vec<Vec<(u8, Vec<u8>)>>>();

    let requesters = (0..NUM_REQUESTERS)
        .map(|_| ByteInteractionAir {
            bus_index: BYTE_XOR_BUS,
            op: ByteLookupOp::Xor
        })
        .collect::<Vec<ByteInteractionAir>>();

    let requesters_traces = requesters_lists
        .par_iter()
        .map(|list| {
            RowMajorMatrix::new(
                list.clone()
                    .into_iter()
                    .flat_map(|(count, fields)| {
                        let x = fields[0];
                        let y = fields[1];
                        let res = xor_chip.request(x, y, ByteLookupOp::Xor);
                        // iter::once(count).chain(fields).chain(iter::once(z))
                        fields.into_iter().chain(res.into_iter())
                    })
                    .map(FieldAlgebra::from_canonical_u8)
                    .collect(),
                NUM_BYTE_INTERACTION_COLS,
            )
        })
        .collect::<Vec<RowMajorMatrix<BabyBear>>>();

    println!("Generated requester traces {:?}", requesters_traces[0]);

    let xor_trace = xor_chip.generate_trace();

    let mut all_chips: Vec<AirRef<_>> = vec![];
    for requester in requesters {
        all_chips.push(Arc::new(requester));
    }
    all_chips.push(Arc::new(xor_chip.air));

    let all_traces = requesters_traces
        .into_iter()
        .chain(iter::once(xor_trace))
        .collect::<Vec<RowMajorMatrix<BabyBear>>>();

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

#[test]
fn test_shr_carry() {
    setup_tracing();

    let mut rng = create_seeded_rng();

    const LOG_XOR_REQUESTS: usize = 1;
    const LOG_NUM_REQUESTERS: usize = 1;

    const XOR_REQUESTS: usize = 1 << LOG_XOR_REQUESTS;
    const NUM_REQUESTERS: usize = 1 << LOG_NUM_REQUESTERS;

    const BYTE_XOR_BUS: u16 = 10;

    let xor_chip = ByteLookupChip::new(BYTE_XOR_BUS);

    let requesters_lists = (0..NUM_REQUESTERS)
        .map(|_| {
            (0..XOR_REQUESTS)
                .map(|_| {
                    let x = rng.r#gen::<u8>();
                    let y = rng.r#gen::<u8>();

                    (1, vec![x, y])
                })
                .collect::<Vec<(u8, Vec<u8>)>>()
        })
        .collect::<Vec<Vec<(u8, Vec<u8>)>>>();

    let requesters = (0..NUM_REQUESTERS)
        .map(|_| ByteInteractionAir {
            bus_index: BYTE_XOR_BUS,
            op: ByteLookupOp::ShrCarry
        })
        .collect::<Vec<ByteInteractionAir>>();

    let requesters_traces = requesters_lists
        .par_iter()
        .map(|list| {
            RowMajorMatrix::new(
                list.clone()
                    .into_iter()
                    .flat_map(|(count, fields)| {
                        let x = fields[0];
                        let y = fields[1];
                        let res = xor_chip.request(x, y, ByteLookupOp::ShrCarry);
                        // iter::once(count).chain(fields).chain(iter::once(z))
                        fields.into_iter().chain(res.into_iter())
                    })
                    .map(FieldAlgebra::from_canonical_u8)
                    .collect(),
                NUM_BYTE_INTERACTION_COLS,
            )
        })
        .collect::<Vec<RowMajorMatrix<BabyBear>>>();

    println!("Generated requester traces {:?}", requesters_traces[0]);

    let xor_trace = xor_chip.generate_trace();

    let mut all_chips: Vec<AirRef<_>> = vec![];
    for requester in requesters {
        all_chips.push(Arc::new(requester));
    }
    all_chips.push(Arc::new(xor_chip.air));

    let all_traces = requesters_traces
        .into_iter()
        .chain(iter::once(xor_trace))
        .collect::<Vec<RowMajorMatrix<BabyBear>>>();

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
