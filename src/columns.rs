use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of};

use crate::bits_air::big_sig_air::{BigSigma0Cols, BigSigma1Cols};
use crate::bits_air::ch_air::ChooseCols;
use crate::bits_air::maj_air::MajorCols;
use crate::bits_air::small_sig_air::{SmallSigma0Cols, SmallSigma1Cols};
use crate::constants::{NUM_ROUNDS, NUM_ROUNDS_PER_ROW, SHA256_ROUND_VAR_CNT, U32_LIMBS};
use crate::gadgets::add::AddGadget;

#[derive(Debug)]
#[repr(C)]
pub struct ShaCols<T> {
    pub step_flags: [T; NUM_ROUNDS],
    pub first_16_steps: T,
    pub export: T,
    // pub is_round: T,
    // pub is_digest: T,
    // pub is_last_block:T,
    pub round_idx: [T; SHA256_ROUND_VAR_CNT],

    pub input_block: [T; 64],
    pub prev_block_seed: [[T; U32_LIMBS]; 8],
    
    pub small_sig0: [SmallSigma0Cols<T>; NUM_ROUNDS_PER_ROW],
    pub small_sig1: [SmallSigma1Cols<T>; NUM_ROUNDS_PER_ROW],
    pub sum_small_sig: [AddGadget<T, 4>; NUM_ROUNDS_PER_ROW],
    pub w_3: [[T; U32_LIMBS]; NUM_ROUNDS_PER_ROW],
    pub intermed_4: [[T; U32_LIMBS]; NUM_ROUNDS_PER_ROW],
    pub intermed_8: [[T; U32_LIMBS]; NUM_ROUNDS_PER_ROW],
    pub intermed_12: [[T; U32_LIMBS]; NUM_ROUNDS_PER_ROW],

    pub big_sig0: [BigSigma0Cols<T>; NUM_ROUNDS_PER_ROW -1],
    pub big_sig1: [BigSigma1Cols<T>; NUM_ROUNDS_PER_ROW -1],
    pub ch: [ChooseCols<T>;  NUM_ROUNDS_PER_ROW -1],
    pub maj: [MajorCols<T>;  NUM_ROUNDS_PER_ROW -1],
    pub sum_t1: [AddGadget<T, 5>;  NUM_ROUNDS_PER_ROW -1],
    pub sum_t2: [AddGadget<T, 2>;  NUM_ROUNDS_PER_ROW -1],
    pub sum_e: [AddGadget<T, 2>;  NUM_ROUNDS_PER_ROW -1],
    pub sum_a: [AddGadget<T, 2>; NUM_ROUNDS_PER_ROW -1],

    pub prev_seed: [[T; U32_LIMBS]; 8],
    pub a: [[T; U32_LIMBS]; 4],
    pub e: [[T; U32_LIMBS]; 4],
    pub seed: [[T; U32_LIMBS]; 8],
    pub final_hash: [[T; U32_LIMBS]; 8],
    pub buf: [[T; U32_LIMBS]; 64],

    pub sum_final: [AddGadget<T, 2>; 8],
}

pub const NUM_SHA_COLS: usize = size_of::<ShaCols<u8>>();


impl<T> Borrow<ShaCols<T>> for [T] {
    fn borrow(&self) -> &ShaCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ShaCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ShaCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ShaCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ShaCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
