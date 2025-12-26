use rand::Rng;

/// Samples an integer from {0, ..., 18} according to the distribution χ, which is close to
/// the half-Gaussian distribution on the natural numbers with mean 0 and standard deviation
/// equal to sigma_max.
fn base_sampler(bytes: [u8; 9]) -> i16 {
    const RCDT: [u128; 18] = [
        3024686241123004913666,
        1564742784480091954050,
        636254429462080897535,
        199560484645026482916,
        47667343854657281903,
        8595902006365044063,
        1163297957344668388,
        117656387352093658,
        8867391802663976,
        496969357462633,
        20680885154299,
        638331848991,
        14602316184,
        247426747,
        3104126,
        28824,
        198,
        1,
    ];

    let mut bytes = bytes.to_vec();
    bytes.extend_from_slice(&[0u8; 7]);
    bytes.reverse();
    let u = u128::from_be_bytes(bytes.try_into().expect("should have length 16"));
    RCDT.into_iter().filter(|r| u < *r).count() as i16
}

/// Computes an integer approximation of 2^63 * ccs * exp(-x).
fn approx_exp(x: f64, ccs: f64) -> u64 {
    // The constants C are used to approximate exp(-x); these
    // constants are taken from FACCT (up to a scaling factor
    // of 2^63):
    //   https://eprint.iacr.org/2018/1234
    //   https://github.com/raykzhao/gaussian
    const C: [u64; 13] = [
        0x00000004741183a3u64,
        0x00000036548cfc06u64,
        0x0000024fdcbf140au64,
        0x0000171d939de045u64,
        0x0000d00cf58f6f84u64,
        0x000680681cf796e3u64,
        0x002d82d8305b0feau64,
        0x011111110e066fd0u64,
        0x0555555555070f00u64,
        0x155555555581ff00u64,
        0x400000000002b400u64,
        0x7fffffffffff4800u64,
        0x8000000000000000u64,
    ];

    let mut z: u64;
    let mut y: u64;
    let twoe63 = 1u64 << 63;

    y = C[0];
    z = f64::floor(x * (twoe63 as f64)) as u64;
    for cu in C.iter().skip(1) {
        let zy = (z as u128) * (y as u128);
        y = cu - ((zy >> 63) as u64);
    }

    z = f64::floor((twoe63 as f64) * ccs) as u64;

    (((z as u128) * (y as u128)) >> 63) as u64
}

/// A random bool that is true with probability ≈ ccs · exp(-x).
fn ber_exp<R: Rng>(x: f64, ccs: f64, rng: &mut R) -> bool {
    const LN2: f64 = core::f64::consts::LN_2;
    const ILN2: f64 = 1.0 / LN2;
    let s = f64::floor(x * ILN2);
    let r = x - s * LN2;
    let s = (s as u64).min(63);
    let z = ((approx_exp(r, ccs) << 1) - 1) >> s;

    let mut w = 0_i32;
    for i in (0..=56).rev().step_by(8) {
        let mut dest = [0_u8; 1];
        rng.fill_bytes(&mut dest);
        let p = u8::from_be_bytes(dest);
        w = (p as i32) - (z >> i & 0xff) as i32;
        if w != 0 {
            break;
        }
    }
    w < 0
}

/// Samples an integer from the Gaussian distribution with given mean (mu) and standard deviation
/// (sigma).
pub(crate) fn sampler_z<R: Rng>(mu: f64, sigma: f64, sigma_min: f64, rng: &mut R) -> i16 {
    const SIGMA_MAX: f64 = 1.8205;
    const INV_2SIGMA_MAX_SQ: f64 = 1f64 / (2f64 * SIGMA_MAX * SIGMA_MAX);
    let isigma = 1f64 / sigma;
    let dss = 0.5f64 * isigma * isigma;
    let s = f64::floor(mu);
    let r = mu - s;
    let ccs = sigma_min * isigma;
    loop {
        let mut dest = [0_u8; 9];
        rng.fill_bytes(&mut dest);
        let z0 = base_sampler(dest);

        let mut dest = [0_u8; 1];
        rng.fill_bytes(&mut dest);
        let random_byte: u8 = dest[0];

        // x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
        let b = (random_byte & 1) as i16;
        let z = b + (2 * b - 1) * z0;
        let zf_min_r = (z as f64) - r;
        let x = zf_min_r * zf_min_r * dss - (z0 * z0) as f64 * INV_2SIGMA_MAX_SQ;

        if ber_exp(x, ccs, rng) {
            return z + (s as i16);
        }
    }
}

#[cfg(test)]
mod test {
    use super::approx_exp;

    #[test]
    fn test_approx_exp() {
        let precision = 1u64 << 14;
        // known answers were generated with the following sage script:
        //```sage
        // num_samples = 10
        // precision = 200
        // R = Reals(precision)
        //
        // print(f"let kats : [(f64, f64, u64);{num_samples}] = [")
        // for i in range(num_samples):
        //     x = RDF.random_element(0.0, 0.693147180559945)
        //     ccs = RDF.random_element(0.0, 1.0)
        //     res = round(2^63 * R(ccs) * exp(R(-x)))
        //     print(f"({x}, {ccs}, {res}),")
        // print("];")
        // ```
        let kats: [(f64, f64, u64); 10] = [
            (0.2314993926072656, 0.8148006314615972, 5962140072160879737),
            (0.2648875572812225, 0.12769669655309035, 903712282351034505),
            (0.11251957513682391, 0.9264611470305881, 7635725498677341553),
            (0.04353439307256617, 0.5306497137523327, 4685877322232397936),
            (0.41834495299784347, 0.879438856118578, 5338392138535350986),
            (0.32579398973228557, 0.16513412873289002, 1099603299296456803),
            (0.5939508073919817, 0.029776019144967303, 151637565622779016),
            (0.2932367999399056, 0.37123847662857923, 2553827649386670452),
            (0.5005699297417507, 0.31447208863888976, 1758235618083658825),
            (0.4876437338498085, 0.6159515298936868, 3488632981903743976),
        ];
        for (x, ccs, answer) in kats {
            let difference = (answer as i128) - (approx_exp(x, ccs) as i128);
            assert!(
                (difference * difference) as u64 <= precision * precision,
                "answer: {answer} versus approximation: {}\ndifference: {} whereas precision: {}",
                approx_exp(x, ccs),
                difference,
                precision
            );
        }
    }

    /// Test that legacy sampler_z matches official Falcon KAT vectors
    #[test]
    fn test_legacy_sampler_kat_falcon512() {
        use super::super::flr::FLR;
        use super::sampler_z;
        use alloc::vec::Vec;
        use rand::RngCore;
        use rand_core::impls;
        use std::println;
        // Same KAT as FLR sampler test - first 10 from official Falcon512 vectors
        const KAT_RND_HEX: &str = concat!(
            "C5442FF043D66E910FD1EAC64EA5450A22941ECADC6CDA0F8D8444D1A772F465",
            "C26F98BBBB4BEE7DB8EFD9B347F6D7FB9B19F25CDB36D6334D477A8BC0BE68B9",
            "145D41B4F5209665C74DAE00DCA8168A7BB516B319C10CB41DED26CD52AED770",
            "2CECA7334E0547BCC3C163DDCE0B054166C1012780C63103AE833CEC73F2F41C",
            "A59B807C9C92158834632F9BC815557E9D68A50A06DBBC7364778DDD14BF0BF2",
            "2061A9D632BF6818A68F7AB9993C15148633F5BFA5D268486F668E5DDD46958E",
            "9763043D10587C2BC6C25F5C5EE53F2783C4361FBC7CC91DC7833AE20A443C59",
            "574C2C3B0745E2E1071E6D133DBE3275D94B0AC116ED60C258E2CB6AAEAB8C48",
            "23E6DA36E18D7208DA0CC104E21CC7FD1F5D5CA8DBB675266C928448D9059E16",
            "3BC1E2CBF3E18E687426A1B51D76222A705AD60259523BFAA8A394BF4EF0A5C1",
            "842366FDE286D6A30F0803BD87E63374CEE6218727FC31104AAB64F136A06948",
            "5B2EADBC08EA77ED1CE7282332C29BEF5FF255BB36BA7DE8FBAD926A8748EF11",
            "BD3D5D7EEC0DEC4AB54775669AD5113B6D846510284427BBFAD1B91B1F32C7D6",
            "685CF27A2DE77F5B02549FB27829B2BD367EE80FCCF30135AEFDF86C0EF4AD07",
            "6D8F7854042F67F18F2A49BA99EEA6BA65EF008BE154FDCD9DFD32C97F885D20",
            "EEFEEE41005C53D4AD1BCF824AF04ABB1814BD9CB8B37171705ACECFDC88A5AF",
        );

        // First 10 (mu, isigma) pairs - using FLR to compute f64 values
        let kat_params: [(f64, f64); 10] = [
            (
                FLR::scaled(-0x16f9e6cb3119a4, -52 + 6).to_f64(),
                1.0 / FLR::scaled(0x12c8142a489b3c, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x10a52739d97620, -52 + 3).to_f64(),
                1.0 / FLR::scaled(0x12c8142a489b3c, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x1318b5479c9f93, -52 + 4).to_f64(),
                1.0 / FLR::scaled(0x12c8b0c2363cd8, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x16abcc6bbdc16d, -52 + 3).to_f64(),
                1.0 / FLR::scaled(0x12c8b0c2363cd8, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(0x1fc1339ad7c928, -52 + 2).to_f64(),
                1.0 / FLR::scaled(0x12d72de0aa39e9, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x1cfda859ee5568, -52 + 4).to_f64(),
                1.0 / FLR::scaled(0x12d72de0aa39e9, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x12247bead535ad, -52 + 3).to_f64(),
                1.0 / FLR::scaled(0x12d846f69991f7, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x15f19b18dcaebe, -52 + 5).to_f64(),
                1.0 / FLR::scaled(0x12d846f69991f7, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x1d165147c514e3, -52 + 5).to_f64(),
                1.0 / FLR::scaled(0x12cfb65140b836, -52 - 1).to_f64(),
            ),
            (
                FLR::scaled(-0x15cb17510e2b49, -52 + 5).to_f64(),
                1.0 / FLR::scaled(0x12cfb65140b836, -52 - 1).to_f64(),
            ),
        ];

        // Expected outputs for first 10 samples
        const KAT_EXPECTED: [i16; 10] = [-92, -8, -20, -12, 8, -30, -10, -41, -61, -46];
        const SIGMA_MIN: f64 = 1.2778336969128337;

        // Decode RND hex string to bytes
        let rnd_bytes = hex::decode(KAT_RND_HEX).expect("Failed to decode KAT RND hex");

        // Create RNG that replays the KAT byte stream
        struct KatRng {
            bytes: Vec<u8>,
            pos: usize,
        }

        impl KatRng {
            fn new(bytes: Vec<u8>) -> Self {
                Self { bytes, pos: 0 }
            }
        }

        impl RngCore for KatRng {
            fn next_u32(&mut self) -> u32 {
                impls::next_u32_via_fill(self)
            }

            fn next_u64(&mut self) -> u64 {
                impls::next_u64_via_u32(self)
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for byte in dest.iter_mut() {
                    *byte = self.bytes[self.pos];
                    self.pos += 1;
                }
            }
        }

        let mut rng = KatRng::new(rnd_bytes);

        // Test each of the 10 KAT vectors
        for (i, ((mu, sigma), &expected)) in kat_params.iter().zip(KAT_EXPECTED.iter()).enumerate()
        {
            let actual = sampler_z(*mu, *sigma, SIGMA_MIN, &mut rng);
            assert_eq!(
                actual, expected,
                "Legacy KAT mismatch at index {}: expected {}, got {} (mu={}, sigma={})",
                i, expected, actual, mu, sigma
            );
        }

        println!("✅ Legacy sampler passed all 10 Falcon512 KAT vectors!");
    }
}
