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

// #[inline]
// pub fn compose<F: FieldAlgebra>(a: &[impl Into<F> + Clone], limb_size: usize) -> F {
//     a.iter().enumerate().fold(F::ZERO, |acc, (i, x)| {
//         acc + x.clone().into() * F::from_canonical_usize(1 << (i * limb_size))
//     })
// }

pub fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    let len: usize = bytes.as_ref().len();
    let mut buf = [0u8; 64];
    let mut seed = SHA256_H;
    // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
    let pad_len = if len % 64 < 56 {
        56 - len % 64
    } else {
        64 + 56 - len % 64
    };
    let mut tmp = [0u8; 72];
    tmp[0] = 0x80;

    let padding = &mut tmp[0..pad_len + 8];
    padding[pad_len..pad_len + 8].copy_from_slice(&(len << 3).to_be_bytes());

    let mut bytes_with_padding = bytes.as_ref().to_vec();
    bytes_with_padding.extend_from_slice(&padding);

    println!("bytes_with_padding: {:?}", bytes_with_padding);
    println!("bytes_with_padding len: {:?}", bytes_with_padding.len());
    println!("after padding: {}", bytes_with_padding.len() / 64);
    for i in 0..bytes_with_padding.len() / 64 {
        buf.copy_from_slice(&bytes_with_padding[i * 64..(i + 1) * 64]);
        permute(&mut seed, buf)
    }
    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&seed[i].to_be_bytes());
    }
    return digest.to_vec();
}

fn permute(mut seed: impl AsMut<[u32]>, bytes: impl AsRef<[u8]>) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let j = i * 4;
        w[i] = (bytes.as_ref()[j] as u32) << 24
            | (bytes.as_ref()[j + 1] as u32) << 16
            | (bytes.as_ref()[j + 2] as u32) << 8
            | (bytes.as_ref()[j + 3] as u32);
    }

    for i in 16..64 {
        let v1 = w[i - 2];
        let t1 = v1.rotate_right(17) ^ v1.rotate_right(19) ^ (v1 >> 10);
        let v2 = w[i - 15];
        let t2 = v2.rotate_right(7) ^ v2.rotate_right(18) ^ (v2 >> 3);
        w[i] = t1
            .wrapping_add(w[i - 7])
            .wrapping_add(t2)
            .wrapping_add(w[i - 16])
    }

    let seed_copy: &mut [u32] = &mut seed.as_mut().to_vec();
    for i in 0..64 {
        let t1 = seed_copy.as_mut()[7]
            .wrapping_add(
                seed_copy.as_mut()[4].rotate_right(6)
                    ^ seed_copy.as_mut()[4].rotate_right(11)
                    ^ seed_copy.as_mut()[4].rotate_right(25),
            )
            .wrapping_add(
                (seed_copy.as_mut()[4] & seed_copy.as_mut()[5])
                    ^ (!seed_copy.as_mut()[4] & seed_copy.as_mut()[6]),
            )
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);

        let t2 = (seed_copy.as_mut()[0].rotate_right(2)
            ^ seed_copy.as_mut()[0].rotate_right(13)
            ^ seed_copy.as_mut()[0].rotate_right(22))
        .wrapping_add(
            (seed_copy.as_mut()[0] & seed_copy.as_mut()[1])
                ^ (seed_copy.as_mut()[0] & seed_copy.as_mut()[2])
                ^ (seed_copy.as_mut()[1] & seed_copy.as_mut()[2]),
        );
        (
            seed_copy.as_mut()[7],
            seed_copy.as_mut()[6],
            seed_copy.as_mut()[5],
            seed_copy.as_mut()[4],
            seed_copy.as_mut()[3],
            seed_copy.as_mut()[2],
            seed_copy.as_mut()[1],
            seed_copy.as_mut()[0],
        ) = (
            seed_copy.as_mut()[6],
            seed_copy.as_mut()[5],
            seed_copy.as_mut()[4],
            seed_copy.as_mut()[3].wrapping_add(t1),
            seed_copy.as_mut()[2],
            seed_copy.as_mut()[1],
            seed_copy.as_mut()[0],
            t1.wrapping_add(t2),
        );
    }
    for (x, y) in seed.as_mut().iter_mut().zip(seed_copy.iter()) {
        *x = x.wrapping_add(*y);
    }
    println!("seed: {:?}", seed.as_mut().iter().map(|x| x.to_le_bytes()).collect::<Vec<_>>())
}

pub fn compose(bytes: [u32;4]) -> u32 {
    (bytes.as_ref()[3] as u32) << 24
            | (bytes.as_ref()[2] as u32) << 16
            | (bytes.as_ref()[1] as u32) << 8
            | (bytes.as_ref()[0] as u32)
}