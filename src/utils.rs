use crate::encoder::encoder::Encoder;


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
