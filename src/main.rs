use std::io::Bytes;

use p3_sha512::constants::{SHA256_H, SHA256_K};
use sha2::Digest;

fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
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
}
fn main() {
    let rand_bytes: [u8; 32] = [
        16, 71, 94, 251, 180, 27, 214, 66, 25, 64, 54, 0, 202, 116, 10, 106, 153, 150, 20, 138,
        173, 67, 225, 187, 28, 143, 224, 140, 200, 218, 171, 166,
    ];
    println!("sha2: {:?}", sha2::Sha256::digest(&rand_bytes));

    println!("sha custom: {:?}", sha256(&rand_bytes));
}
