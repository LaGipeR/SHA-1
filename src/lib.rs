use long_int::LongInt;

pub struct SHA1 {
    last_block: Vec<bool>,
    result_a: u32,
    result_b: u32,
    result_c: u32,
    result_d: u32,
    result_e: u32,
    len: u64,
}

impl SHA1 {
    const START_A: u32 = 0x67452301;
    const START_B: u32 = 0xEFCDAB89;
    const START_C: u32 = 0x98BADCFE;
    const START_D: u32 = 0x10325476;
    const START_E: u32 = 0xC3D2E1F0;
    pub fn new() -> SHA1 {
        SHA1 {
            last_block: vec![],
            result_a: Self::START_A,
            result_b: Self::START_B,
            result_c: Self::START_C,
            result_d: Self::START_D,
            result_e: Self::START_E,
            len: 0,
        }
    }

    fn circular_shift(num: u32, shift: usize) -> u32 {
        let shift = shift % 32;
        (num << shift) | (num >> (32 - shift))
    }

    fn calc_block(&mut self, message: &[u32; 16]) {
        let mut a = self.result_a;
        let mut b = self.result_b;
        let mut c = self.result_c;
        let mut d = self.result_d;
        let mut e = self.result_e;

        let m = *message;

        let mut w: Vec<u32> = Vec::from(m);
        for i in 16..80 {
            let new_w_block = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w.push(Self::circular_shift(new_w_block, 1));
        }

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };

            let tmp = u32::wrapping_add(
                u32::wrapping_add(
                    u32::wrapping_add(u32::wrapping_add(e, f), Self::circular_shift(a, 5)),
                    w[i],
                ),
                k,
            );

            e = d;
            d = c;
            c = Self::circular_shift(b, 30);
            b = a;
            a = tmp;
        }

        self.result_a = self.result_a.wrapping_add(a);
        self.result_b = self.result_b.wrapping_add(b);
        self.result_c = self.result_c.wrapping_add(c);
        self.result_d = self.result_d.wrapping_add(d);
        self.result_e = self.result_e.wrapping_add(e);
    }

    fn bits2num(bits: &[bool]) -> u32 {
        let mut result = 0;

        for &bit in bits {
            result = (result << 1) | (bit as u32);
        }

        result
    }

    fn group_bits(bits: &[bool]) -> [u32; 16] {
        assert_eq!(bits.len(), 512);

        let mut result = [0u32; 16];

        for i in 0..16 {
            result[i] = Self::bits2num(&bits[(i << 5)..((i + 1) << 5)])
        }

        result
    }

    pub fn add(&mut self, message: &[bool]) {
        self.len += message.len() as u64;

        if message.len() + self.last_block.len() < 512 {
            self.last_block.extend_from_slice(message);
            return;
        }

        let mut l = 512 - self.last_block.len();

        self.last_block.extend_from_slice(&message[..l]);

        self.calc_block(&Self::group_bits(self.last_block.as_slice()));

        while l + 512 <= message.len() {
            self.calc_block(&Self::group_bits(&message[l..(l + 512)]));
            l += 512;
        }

        self.last_block = Vec::new();
        self.last_block.extend_from_slice(&message[l..]);
    }

    fn num2bits(num: u64) -> [bool; 64] {
        let mut result = [false; 64];
        for i in 0..64 {
            result[63 - i] = (num & (1 << i)) != 0;
        }

        result
    }

    fn addition(&mut self) {
        self.last_block.push(true);
        while self.last_block.len() % 512 != 448 {
            self.last_block.push(false);
        }

        self.last_block
            .extend_from_slice(Self::num2bits(self.len).as_slice());
    }

    pub fn finalize(&mut self) -> LongInt {
        self.addition();

        self.calc_block(&Self::group_bits(&self.last_block[..512]));
        if self.last_block.len() > 512 {
            self.calc_block(&Self::group_bits(&self.last_block[512..]));
        }

        let result = LongInt::from_blocks_big_endian(
            [
                self.result_a,
                self.result_b,
                self.result_c,
                self.result_d,
                self.result_e,
            ]
            .to_vec(),
        );

        self.clear();

        result
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

fn u8_to_bits(num: u8) -> [bool; 8] {
    let mut result = [false; 8];
    for i in 0..8 {
        result[7 - i] = (num & (1 << i)) != 0;
    }

    result
}

pub fn u8_slice_to_bool(u8slice: &[u8]) -> Vec<bool> {
    let mut result = Vec::new();
    for el in u8slice {
        result.extend_from_slice(&u8_to_bits(*el));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests() {
        let mut sha = SHA1::new();

        let a = sha.finalize();
        assert_eq!(a.getHex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        sha.add(&*u8_slice_to_bool(b"sha".as_slice()));
        let a = sha.finalize();
        assert_eq!(a.getHex(), "d8f4590320e1343a915b6394170650a8f35d6926");

        sha.add(&*u8_slice_to_bool(b"Sha".as_slice()));
        let a = sha.finalize();
        assert_eq!(a.getHex(), "ba79baeb9f10896a46ae74715271b7f586e74640");

        sha.add(&*u8_slice_to_bool(
            b"da39a3ee5e6b4b0d3255bfef95601890afd80709".as_slice(),
        ));
        let a = sha.finalize();
        assert_eq!(a.getHex(), "10a34637ad661d98ba3344717656fcc76209c2f8");

        sha.add(&*u8_slice_to_bool(
            b"da39a3ee5e6b4b0d3255bfef95601890afd80709".as_slice(),
        ));
        sha.add(&*u8_slice_to_bool(
            b"10a34637ad661d98ba3344717656fcc76209c2f8".as_slice(),
        ));
        sha.add(&*u8_slice_to_bool(
            b"7c2229e9d8448e3fbd61f080c99afcccc165c5ac".as_slice(),
        ));
        sha.add(&*u8_slice_to_bool(
            b"316a45578b56e1488bfdc0d694b59d649b2dab83".as_slice(),
        ));
        sha.add(&*u8_slice_to_bool(
            b"59253cd4beeb1b2d3f2fd8d28aefc39ef7979fdd".as_slice(),
        ));
        sha.add(&*u8_slice_to_bool(
            b"5eaeb22e983ab50b5a3eef6b2deeffac98c21a72".as_slice(),
        ));
        let a = sha.finalize();
        assert_eq!(a.getHex(), "a3bd4137b0e29adb6e38e2befc9b1d933b5341d1");
    }
}
