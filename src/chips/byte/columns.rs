use derive::AlignedBorrow;

use crate::chips::byte::NUM_BYTE_LOOKUP_OPS;

#[repr(C)]
#[derive(Clone, Copy, Debug, AlignedBorrow)]
pub struct ByteLookupCols<T> {
    pub muls: [T; NUM_BYTE_LOOKUP_OPS],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, AlignedBorrow)]
pub struct ByteLookupPreprocessedCols<T> {
    pub x: T,
    pub y: T,

    /// XOR result (x ⊕ y)
    pub xor: T,

    pub shr: T,
    pub shr_carry: T,
}

pub const NUM_BYTE_LOOKUP_COLS: usize = size_of::<ByteLookupCols<u8>>();
pub const NUM_BYTE_LOOKUP_PREPROCESSED_COLS: usize = size_of::<ByteLookupPreprocessedCols<u8>>();
