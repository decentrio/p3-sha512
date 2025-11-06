use core::borrow::Borrow;

use p3_air::AirBuilder;
use p3_field::{FieldAlgebra, PrimeField32};

use crate::constants::U32_LIMBS;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RightRotateAir<T> {
    /// The output value.
    pub value: [T; U32_LIMBS],

    /// The c_mod == 0 condition of `shrcarry` on each byte of a word.
    pub c_mod_is_zero: [T; U32_LIMBS],

    /// b << (8 - c_mod) of `shrcarry` on each byte of a word.
    pub left_aligned_carry: [T; U32_LIMBS],

    /// b - (b >> c_mod) << c_mod of `shrcarry` on each byte of a word.
    pub shift_remainder: [T; U32_LIMBS],
    pub shift_overflow: [T; U32_LIMBS],

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: [T; U32_LIMBS],

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: [T; U32_LIMBS],
}

pub const NUM_RIGHT_ROTATE_COLS: usize = size_of::<RightRotateAir<u8>>();

impl<F: PrimeField32> RightRotateAir<F> {
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

    pub fn populate(&mut self, input: u32, rotation: usize) -> u32 {
        let input_bytes = input.to_le_bytes().map(F::from_canonical_u8);
        let expected = input.rotate_right(rotation as u32);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated: [F; 4] = [
            input_bytes[nb_bytes_to_shift % U32_LIMBS],
            input_bytes[(1 + nb_bytes_to_shift) % U32_LIMBS],
            input_bytes[(2 + nb_bytes_to_shift) % U32_LIMBS],
            input_bytes[(3 + nb_bytes_to_shift) % U32_LIMBS],
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::ZERO;
        let mut last_carry = F::ZERO;
        for i in (0..U32_LIMBS).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;
            self.shift_overflow[i] = F::ZERO;

            let (shift, carry) = {
                let c_mod = c & 0x7;
                if c_mod != 0 {
                    let res = b >> c_mod;
                    let remainder = b - (res << c_mod);
                    let carry = (b << (8 - c_mod)) >> (8 - c_mod);
                    self.c_mod_is_zero[i] = F::ZERO;
                    self.left_aligned_carry[i] = F::from_canonical_u8(b << (8 - c_mod));
                    if ((b as u32) << (8 - c_mod)) > 255 {
                        self.shift_overflow[i] =
                            F::from_canonical_u8(((b as u32) << (8 - c_mod) >> 8) as u8);
                    }
                    self.shift_remainder[i] = F::from_canonical_u8(remainder);
                    (res, carry)
                } else {
                    self.c_mod_is_zero[i] = F::ONE;
                    self.left_aligned_carry[i] = F::ZERO;
                    (b, 0u8)
                }
            };
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
        self.value[U32_LIMBS - 1] = first_shift + last_carry * carry_multiplier;

        // Check that the value is correct.
        assert_eq!(
            u32::from_le_bytes(self.value.map(|x| x.to_string().parse::<u8>().unwrap())),
            expected
        );

        expected
    }

    pub fn eval<AB: AirBuilder>(
        builder: &mut AB,
        input: [AB::Expr; U32_LIMBS],
        rotation: usize,
        cols: &RightRotateAir<AB::Var>,
    ) {
        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_canonical_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated = [
            input[nb_bytes_to_shift % U32_LIMBS].clone(),
            input[(1 + nb_bytes_to_shift) % U32_LIMBS].clone(),
            input[(2 + nb_bytes_to_shift) % U32_LIMBS].clone(),
            input[(3 + nb_bytes_to_shift) % U32_LIMBS].clone(),
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = AB::Expr::ZERO;
        let mut last_carry = AB::Expr::ZERO;
        for i in (0..U32_LIMBS).rev() {
            let c_mod = (nb_bits_to_shift & 0x07) as u8;

            let c_mod_not_zero = AB::Expr::ONE - cols.c_mod_is_zero[i].clone();
            // assert when c_mod is zero
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(AB::F::from_canonical_u8(c_mod));
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_eq(input_bytes_rotated[i].clone(), cols.shift[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.carry[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.left_aligned_carry[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.shift_overflow[i].clone());

            // assert when c_mod is not zero
            let left_shift_amount = 8 - c_mod;
            builder.when(c_mod_not_zero.clone()).assert_eq(
                input_bytes_rotated[i].clone(),
                cols.shift[i].clone().into().mul_2exp_u64(c_mod as u64)
                    + cols.shift_remainder[i].clone(),
            );
            builder.when(c_mod_not_zero.clone()).assert_eq(
                cols.left_aligned_carry[i].clone()
                    + cols.shift_overflow[i].clone().into().mul_2exp_u64(8),
                input_bytes_rotated[i]
                    .clone()
                    .mul_2exp_u64(left_shift_amount as u64),
            );
            builder.when(c_mod_not_zero).assert_eq(
                cols.carry[i]
                    .clone()
                    .into()
                    .mul_2exp_u64(left_shift_amount as u64),
                cols.left_aligned_carry[i].clone(),
            );

            // assert when c_mod is zero
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_eq(cols.shift[i].clone(), input_bytes_rotated[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.carry[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.left_aligned_carry[i].clone());
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
            first_shift + last_carry * carry_multiplier,
        );
    }
}

impl<F> Borrow<RightRotateAir<F>> for [F] {
    fn borrow(&self) -> &RightRotateAir<F> {
        debug_assert_eq!(self.len(), NUM_RIGHT_ROTATE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<RightRotateAir<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

pub mod tests {
    use crate::bits_air::rotr_air::{NUM_RIGHT_ROTATE_COLS, RightRotateAir};
    use core::borrow::Borrow;
    use p3_air::{Air, AirBuilder, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32, SerializingChallenger64};
    use p3_circle::CirclePcs;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{Field, FieldAlgebra, PrimeField32, extension::BinomialExtensionField};
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_goldilocks::Goldilocks;
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_matrix::{Matrix, dense::RowMajorMatrix};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_mersenne_31::{Mersenne31, Poseidon2Mersenne31};
    use p3_monty_31::dft::RecursiveDft;
    use p3_sha256::Sha256;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
    };
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::{
        Rng, SeedableRng,
        rngs::{SmallRng, StdRng},
    };
    use std::{fmt::Debug, io::Error, marker::PhantomData};
    use tracing_forest::{ForestLayer, util::LevelFilter};
    use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

    #[derive(Debug)]
    pub struct ExampleAir {
        input: u32,
        rotation: usize,
    }

    impl ExampleAir {
        pub fn generate_trace_rows<F: PrimeField32>(
            &self,
            input: u32,
            rotation: usize,
            extra_capacity_bits: usize,
        ) -> RowMajorMatrix<F> {
            let trace_length = NUM_RIGHT_ROTATE_COLS;
            let mut long_trace = F::zero_vec(trace_length << extra_capacity_bits);
            long_trace.truncate(trace_length);

            let mut trace = RowMajorMatrix::new(long_trace, NUM_RIGHT_ROTATE_COLS);
            let (prefix, rows, suffix) =
                unsafe { trace.values.align_to_mut::<RightRotateAir<F>>() };
            assert!(prefix.is_empty(), "Alignment should match");
            assert!(suffix.is_empty(), "Alignment should match");
            assert_eq!(rows.len(), 1);

            let result = rows[0].populate(input, rotation);
            println!("result: {}", result);
            trace
        }
    }

    impl<F> BaseAir<F> for ExampleAir {
        fn width(&self) -> usize {
            NUM_RIGHT_ROTATE_COLS
        }
    }

    impl<AB: AirBuilder<F: PrimeField32>> Air<AB> for ExampleAir {
        #[inline]
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &RightRotateAir<AB::Var> = (*local).borrow();
            let input = self.input.to_le_bytes().map(AB::Expr::from_canonical_u8);
            RightRotateAir::<AB::F>::eval::<AB>(builder, input, self.rotation, local);
        }
    }

    #[test]
    fn test_right_rotate() {
        // WARNING: Use a real cryptographic PRNG in applications!!
        let mut rng = SmallRng::seed_from_u64(1);
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();

        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type ByteHash = Keccak256Hash;
        type FieldHash = SerializingHasher32<ByteHash>;
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(Keccak256Hash);

        type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
        let compress = MyCompress::new(byte_hash);

        type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
        let val_mmcs = ValMmcs::new(field_hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

        let fri_config = FriConfig {
            log_blowup: 2,
            log_final_poly_len: 0,
            num_queries: 100,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };

        let input: u32 = rng.random();
        let rotation: usize = rng.random_range(1..31);

        let air = ExampleAir { input, rotation };
        let trace = air.generate_trace_rows(input, rotation, fri_config.log_blowup);

        type Dft = RecursiveDft<Val>;
        let dft = Dft::new(trace.height() << fri_config.log_blowup);

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_config);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs);

        let mut challenger = Challenger::from_hasher(vec![], byte_hash);
        let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

        let mut challenger = Challenger::from_hasher(vec![], byte_hash);
        verify(&config, &air, &mut challenger, &proof, &vec![]).expect("verification failed");
    }
}
