use p3_field::FieldAlgebra;

use crate::{constants::{SHA256_H, SHA256_K}, encoder::encoder::Encoder};


/// Convert a list of limbs in little endian into a u32
pub fn limbs_into_u32<const NUM_LIMBS: usize>(limbs: [u32; NUM_LIMBS]) -> u32 {
    let limb_bits = 32 / NUM_LIMBS;
    limbs
        .iter()
        .rev()
        .fold(0, |acc, &limb| (acc << limb_bits) | limb)
}

/// Big sigma_0 function from SHA256
pub fn big_sig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Big sigma_1 function from SHA256
pub fn big_sig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Majority function from SHA256
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Choose function from SHA256
#[inline]
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

/// Wrapper of `get_flag_pt` to get the flag pointer as an array
pub fn get_flag_pt_array<const N: usize>(encoder: &Encoder, flag_idx: usize) -> [u32; N] {
    encoder.get_flag_pt(flag_idx).try_into().unwrap()
}

pub fn compose(bytes: [u32;4]) -> u32 {
    (bytes.as_ref()[3] as u32) << 24
            | (bytes.as_ref()[2] as u32) << 16
            | (bytes.as_ref()[1] as u32) << 8
            | (bytes.as_ref()[0] as u32)
}

#[inline]
pub fn compose_le<F: FieldAlgebra>(bytes: &[impl Into<F> + Clone]) -> F {
    F::from_canonical_usize(1<< 24) * bytes[3].clone().into()
        + F::from_canonical_usize(1<< 16) * bytes[2].clone().into()
        + F::from_canonical_usize(1<< 8) * bytes[1].clone().into()
        + bytes[0].clone().into()
}

#[inline]
pub fn compose_be<F: FieldAlgebra>(bytes: &[impl Into<F> + Clone]) -> F {
    F::from_canonical_usize(1<< 24) * bytes[0].clone().into()
        + F::from_canonical_usize(1<< 16) * bytes[1].clone().into()
        + F::from_canonical_usize(1<< 8) * bytes[2].clone().into()
        + bytes[3].clone().into()
}