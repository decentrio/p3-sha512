pub mod tests {
    use std::sync::Arc;

    use openvm_stark_backend::{AirRef, prover::types::{AirProvingContext, ProvingContext}};
    use openvm_stark_sdk::{config::{FriParameters, baby_bear_keccak::BabyBearKeccakEngine, setup_tracing}, engine::{StarkEngine, StarkFriEngine}, utils::create_seeded_rng};

    use crate::{air::{BUS_INDEX, ShaAir}, chips::byte::ByteLookupChip};
    const LOG_BLOWUP: usize = 2;

    #[test]
    fn test_sha256() {
        setup_tracing();

        let byte_chip = ByteLookupChip::new(BUS_INDEX);

        let air = ShaAir::new();
        let trace = air.generate_trace_rows(&byte_chip, 1, LOG_BLOWUP);


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