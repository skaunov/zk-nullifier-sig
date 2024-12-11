// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

//! A library for generating and verifying PLUME signatures.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
// Find `arkworks-rs` crate as `plume_arkworks`.
//
//! # Examples
//! If you want more control or to be more generic on traits `use` [`PlumeSigner`] from [`randomizedsigner`]
//! ```rust
//! use plume_rustcrypto::{PlumeSignature, SecretKey};
//! use rand_core::OsRng;
//! # fn main() {
//! #   let sk = SecretKey::random(&mut OsRng);
//! #       
//!     let sig_v1 = PlumeSignature::sign_v1(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//!     assert!(sig_v1.verify());
//!
//!     let sig_v2 = PlumeSignature::sign_v2(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//!     assert!(sig_v2.verify());
//! # }
//! ```

use k256::elliptic_curve::bigint::ArrayEncoding;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::sha2::{digest::Output, Digest, Sha256}; // requires 'getrandom' feature
use k256::{ProjectivePoint, Secp256k1};
use k256::Scalar;
use k256::U256;
use signature::RandomizedSigner;

/// Exports types from the `k256` crate:
///
/// - `NonZeroScalar`: A secret 256-bit scalar value.
/// - `SecretKey`: A secret 256-bit scalar wrapped in a struct.  
/// - `AffinePoint`: A public elliptic curve point.
pub use k256::{AffinePoint, NonZeroScalar, SecretKey};
/// Re-exports the [`CryptoRngCore`] trait from the [`rand_core`] crate.
/// This allows it to be used from the current module.
pub use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
/// Provides the ability to serialize and deserialize data using the Serde library.
/// The `Serialize` and `Deserialize` traits from the Serde library are re-exported for convenience.
pub use serde::{Deserialize, Serialize};

mod utils;
// not published due to use of `Projective...`; these utils can be found in other crates
use utils::*;

/// The domain separation tag used for hashing to the `secp256k1` curve
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

/// Struct holding signature data for a PLUME signature.
///
/// `v1specific` field differintiate whether V1 or V2 protocol will be used.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignature {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The public key used to verify the signature.
    pub pk: AffinePoint,
    /// The nullifier.
    pub nullifier: AffinePoint,
    /// Part of the signature data. SHA-256 interpreted as a scalar.
    pub c: NonZeroScalar,
    /// Part of the signature data, a scalar value.
    pub s: NonZeroScalar,
}
/// Nested struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: AffinePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: AffinePoint,
}
fn sign_with_rng(
    sk: NonZeroScalar,
    rng: &mut impl CryptoRngCore,
    msg: &[u8],
) -> PlumeSignature {
    // Pick a random r from Fp
    let r_scalar = SecretKey::random(rng);

    let r_point = r_scalar.public_key();

    let sk = SecretKey::from(sk);
    let pk = sk.public_key();

    let pk_bytes = pk.to_encoded_point(true).to_bytes();

    let hashed_to_curve = 
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<pse_poseidon::Poseidon<
            halo2curves_axiom::bn256::Fr, 3, 2
        >>>(
            &[[msg, &pk_bytes].concat().as_slice()],
            &[b"QUUX-V01-CS02-with-secp256k1_XMD:POSEIDON_SSWU_RO_"]
        )
        .unwrap()
        .to_affine();
    // let hashed_to_curve = hashed_to_curve.to_encoded_point(false).to_bytes().into_vec();
    // assert_eq!(hashed_to_curve.len(), 65);

    // let mut x = hashed_to_curve[1..33].to_vec();
    // x.reverse();
    // let mut y = hashed_to_curve[33..].to_vec();
    // y.reverse();

    // let hashed_to_curve = Secp256k1Affine::from_xy(
    //     Fp::from_bytes_le(x.as_slice()),
    //     Fp::from_bytes_le(y.as_slice())
    // ).unwrap();

    let hashed_to_curve_sk = (hashed_to_curve * *sk.to_nonzero_scalar()).to_affine();

    // it feels not that scary to store `r_scalar` as `NonZeroScalar` (compared to `self.secret_key`)
    let r_scalar = r_scalar.to_nonzero_scalar();

    // Compute z = h^r
    let hashed_to_curve_r = 
        (hashed_to_curve * *r_scalar).to_affine();

    let mut poseidon_hasher = 
        pse_poseidon::Poseidon::<halo2curves_axiom::bn256::Fr, 3, 2>::new(
            8, 57
        );
    poseidon_hasher.update(
        &[
            k256::AffinePoint::GENERATOR.to_encoded_point(true).to_bytes(),
            pk_bytes,
            hashed_to_curve.to_encoded_point(true).to_bytes(),
            hashed_to_curve_sk.to_encoded_point(true).to_bytes(),
            r_point.to_encoded_point(true).to_bytes(),
            hashed_to_curve_r.to_encoded_point(true).to_bytes(),
        ]
        .concat()
        .iter()
        .map(|v| halo2curves_axiom::bn256::Fr::from(*v as u64))
        .collect::<Vec<halo2curves_axiom::bn256::Fr>>()
    );
    // let c = poseidon_hasher.squeeze_and_reset();
    let mut c_bytes = poseidon_hasher.squeeze_and_reset().to_bytes();
    c_bytes.reverse();
    let c_scalar = 
        NonZeroScalar::from_repr(c_bytes.into())
        .expect("it should be impossible to get the hash equal to zero");

    // Compute $s = r + sk ⋅ c$. #lastoponsecret
    let s_scalar = 
        NonZeroScalar::new(
            *r_scalar + *(c_scalar * sk.to_nonzero_scalar())
        ).expect("something is terribly wrong if the nonce is equal to negated product of the secret and the hash");

    PlumeSignature {
        message: msg.to_owned(),
        pk: pk.into(),
        nullifier: hashed_to_curve_sk,
        c: c_scalar,
        s: s_scalar,
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::gates::RangeInstructions;
    use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
    use halo2_base::poseidon::hasher::PoseidonHasher;
    use halo2_base::utils::testing::base_test;
    use halo2_ecc::ecc::EccChip;
    use halo2_ecc::fields::FieldChip;
    use halo2_ecc::secp256k1::{FpChip, FqChip};
    use halo2_plume::{verify_plume, PlumeInput};
    use halo2curves::CurveAffine;
    use halo2curves_axiom::bn256::Fr;
    use rand_core::OsRng;
    use k256::elliptic_curve::point::AffineCoordinates;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use halo2_base::utils::ScalarField;

    #[test]
    fn test_plume_verify() {
        let msg_str =
          b"vulputate ut pharetra tis amet aliquam id diam maecenas ultricies mi eget mauris pharetra et adasdds";
    
        let mut rng = OsRng;
        // the only change is `test_data` to switch to the synced part
        let test_data = 
            super::sign_with_rng(
                k256::NonZeroScalar::random(& mut rng), &mut rng, msg_str
            );
        let test_data = halo2_plume::PlumeCircuitInput{ 
            nullifier: 
            {
                let result = test_data.nullifier.to_encoded_point(false).to_bytes().into_vec();
                assert_eq!(result.len(), 65);

                let mut x = result[1..33].to_vec();
                x.reverse();
                let mut y = result[33..].to_vec();
                y.reverse();
                let result = halo2curves_axiom::secp256k1::Secp256k1Affine::from_xy(
                    halo2curves_axiom::secp256k1::Fp::from_bytes_le(x.as_slice()),
                    halo2curves_axiom::secp256k1::Fp::from_bytes_le(y.as_slice())
                ).unwrap();
                (result.x, result.y)
            }, 
            s: {
                let mut result = test_data.s.to_bytes().to_vec();
                assert!(result.len() == 32);
                result.reverse();
                let result: [u8; 32] = result.try_into().unwrap();
                halo2curves_axiom::secp256k1::Fq::from_bytes(&result).unwrap()
            }, 
            c: {
                let mut result = test_data.c.to_bytes().to_vec();
                assert!(result.len() == 32);
                result.reverse();
                let result: [u8; 32] = result.try_into().unwrap();
                halo2curves_axiom::secp256k1::Fq::from_bytes(&result).unwrap()
            }, 
            pk: {
                let mut result = 
                    (test_data.pk.x().to_vec(), test_data.pk.to_encoded_point(false).y().unwrap().to_vec());
                assert!(result.0.len() == 32 && result.1.len() == 32);
                result.0.reverse();
                result.1.reverse();
                let result: ([u8; 32], [u8; 32]) = (result.0.try_into().unwrap(), result.1.try_into().unwrap());
                (
                    halo2curves_axiom::secp256k1::Fp::from_bytes(&result.0).unwrap(),
                    halo2curves_axiom::secp256k1::Fp::from_bytes(&result.1).unwrap(),
                )
            }, 
            m: test_data.message.iter()
                .map(|b| halo2curves_axiom::bn256::Fr::from(*b as u64))
                .collect::<Vec<_>>()
        };
    
        base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let fp_chip = FpChip::<Fr>::new(range, 88, 3);
            let fq_chip = FqChip::<Fr>::new(range, 88, 3);
            let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

            let mut poseidon_hasher = PoseidonHasher::<Fr, 3, 2>::new(
                OptimizedPoseidonSpec::new::<8, 57, 0>()
            );
            poseidon_hasher.initialize_consts(ctx, range.gate());

            let nullifier = ecc_chip.load_private_unchecked(ctx, (
                test_data.nullifier.0,
                test_data.nullifier.1,
            ));
            let s = fq_chip.load_private(ctx, test_data.s);
            let c = fq_chip.load_private(ctx, test_data.c);
            let pk = ecc_chip.load_private_unchecked(ctx, (test_data.pk.0, test_data.pk.1));
            let m = test_data.m
                .iter()
                .map(|m| ctx.load_witness(*m))
                .collect::<Vec<_>>();

            let plume_input = PlumeInput {
                nullifier,
                s,
                c,
                pk,
                m,
            };

            verify_plume::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4, plume_input)
        });
      }
}
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use hex_literal::hex;

//     pub fn verify_nullifier(
//         message: &[u8],
//         nullifier: &Secp256k1Affine,
//         pk: &Secp256k1Affine,
//         s: &Fq,
//         c: &Fq
//       ) {
//         let compressed_pk = compress_point(&pk);
//         let hashed_to_curve = hash_to_curve(message, &compressed_pk);
//         let hashed_to_curve_s_nullifier_c = (hashed_to_curve * s - nullifier * c).to_affine();
//         let gs_pkc = (Secp256k1::generator() * s - pk * c).to_affine();
      
//         let mut poseidon_hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
//         poseidon_hasher.update(
//           &[
//             compress_point(&Secp256k1::generator().to_affine()),
//             compressed_pk,
//             compress_point(&hashed_to_curve),
//             compress_point(&nullifier),
//             compress_point(&gs_pkc),
//             compress_point(&hashed_to_curve_s_nullifier_c),
//           ]
//             .concat()
//             .iter()
//             .map(|v| Fr::from(*v as u64))
//             .collect::<Vec<Fr>>()
//         );
      
//         let mut _c = poseidon_hasher.squeeze_and_reset();
      
//         let _c = Fq::from_bytes_le(&_c.to_bytes_le());
      
//         assert_eq!(*c, _c);
//       }
      
//       pub fn gen_test_nullifier(sk: &Fq, message: &[u8]) -> (Secp256k1Affine, Fq, Fq) {
//         let pk = (Secp256k1::generator() * sk).to_affine();
//         let compressed_pk = compress_point(&pk);
      
//         let hashed_to_curve = hash_to_curve(message, &compressed_pk);
      
//         let hashed_to_curve_sk = (hashed_to_curve * sk).to_affine();
      
//         let r = Fq::random(OsRng);
//         let g_r = (Secp256k1::generator() * r).to_affine();
//         let hashed_to_curve_r = (hashed_to_curve * r).to_affine();
      
//         let mut poseidon_hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
//         poseidon_hasher.update(
//           &[
//             compress_point(&Secp256k1::generator().to_affine()),
//             compressed_pk,
//             compress_point(&hashed_to_curve),
//             compress_point(&hashed_to_curve_sk),
//             compress_point(&g_r),
//             compress_point(&hashed_to_curve_r),
//           ]
//             .concat()
//             .iter()
//             .map(|v| Fr::from(*v as u64))
//             .collect::<Vec<Fr>>()
//         );
      
//         let c = poseidon_hasher.squeeze_and_reset();
      
//         let c = Fq::from_bytes_le(&c.to_bytes_le());
//         let s = r + sk * c;
      
//         (hashed_to_curve_sk, s, c)
//       }
      
//       pub fn generate_test_data(msg: &[u8]) -> PlumeCircuitInput {
//         let m = msg
//           .iter()
//           .map(|b| Fr::from(*b as u64))
//           .collect::<Vec<_>>();
      
//         let sk = Fq::random(OsRng);
//         let pk = Secp256k1Affine::from(Secp256k1::generator() * sk);
//         let (nullifier, s, c) = gen_test_nullifier(&sk, msg);
//         verify_nullifier(msg, &nullifier, &pk, &s, &c);
      
//         PlumeCircuitInput {
//           nullifier: (nullifier.x, nullifier.y),
//           s,
//           c,
//           pk: (pk.x, pk.y),
//           m,
//         }
//       }

//       #[test]
//       fn test_plume_verify() {
//         // Inputs
//         let msg_str =
//           b"vulputate ut pharetra tis amet aliquam id diam maecenas ultricies mi eget mauris pharetra et adasdds";
    
//         let test_data = generate_test_data(msg_str);
    
//         base_test()
//           .k(16)
//           .lookup_bits(15)
//           .expect_satisfied(true)
//           .run(|ctx, range| {
//             let fp_chip = FpChip::<Fr>::new(range, 88, 3);
//             let fq_chip = FqChip::<Fr>::new(range, 88, 3);
//             let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);
    
//             let mut poseidon_hasher = PoseidonHasher::<Fr, 3, 2>::new(
//               OptimizedPoseidonSpec::new::<8, 57, 0>()
//             );
//             poseidon_hasher.initialize_consts(ctx, range.gate());
    
//             let nullifier = ecc_chip.load_private_unchecked(ctx, (
//               test_data.nullifier.0,
//               test_data.nullifier.1,
//             ));
//             let s = fq_chip.load_private(ctx, test_data.s);
//             let c = fq_chip.load_private(ctx, test_data.c);
//             let pk = ecc_chip.load_private_unchecked(ctx, (test_data.pk.0, test_data.pk.1));
//             let m = test_data.m
//               .iter()
//               .map(|m| ctx.load_witness(*m))
//               .collect::<Vec<_>>();
    
//             let plume_input = PlumeInput {
//               nullifier,
//               s,
//               c,
//               pk,
//               m,
//             };
    
            
//           });
          
//           plume_input.verify::<Fr>(ctx, &ecc_chip, &poseidon_hasher, 4, 4)
//       }
    
//     // Test encode_pt()
//     #[test]
//     fn test_encode_pt() {
//         let g_as_bytes = encode_pt(&ProjectivePoint::GENERATOR);
//         assert_eq!(
//             hex::encode(g_as_bytes),
//             "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
//         );
//     }

// /// Convert a 32-byte array to a scalar
// fn byte_array_to_scalar(bytes: &[u8]) -> Scalar {
//     // From https://docs.rs/ark-ff/0.3.0/src/ark_ff/fields/mod.rs.html#371-393
//     assert!(bytes.len() == 32);
//     let mut res = Scalar::from(0u64);
//     let window_size = Scalar::from(256u64);
//     for byte in bytes.iter() {
//         res *= window_size;
//         res += Scalar::from(*byte as u64);
//     }
//     res
// }

//     // Test byte_array_to_scalar()
//     #[test]
//     fn plume_v1_test() {
//         let g = ProjectivePoint::GENERATOR;

//         let m = b"An example app message string";

//         // Fixed key nullifier, secret key, and random value for testing
//         // Normally a secure enclave would generate these values, and output to a wallet implementation
//         let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) =
//             test_gen_signals(m, PlumeVersion::V1);

//         // The signer's secret key. It is only accessed within the secure enclave.
//         let sk = gen_test_scalar_sk();

//         // The user's public key: g^sk.
//         let pk = &g * &sk;

//         // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
//         // The wallet should probably run this prior to snarkify-ing as a sanity check
//         // m and nullifier should be public, so we can verify that they are correct
//         let verified = PlumeSignature {
//             message: m,
//             pk: &pk,
//             nullifier: &nullifier,
//             c: &c,
//             s: &r_sk_c,
//             v1: Some(PlumeSignatureV1Fields {
//                 r_point: &g_r.unwrap(),
//                 hashed_to_curve_r: &hash_m_pk_pow_r.unwrap(),
//             }),
//         }
//         .verify_signals();
//         println!("Verified: {}", verified);

//         // Print nullifier
//         println!(
//             "nullifier.x: {:?}",
//             hex::encode(nullifier.to_affine().to_encoded_point(false).x().unwrap())
//         );
//         println!(
//             "nullifier.y: {:?}",
//             hex::encode(nullifier.to_affine().to_encoded_point(false).y().unwrap())
//         );

//         // Print c
//         println!("c: {:?}", hex::encode(&c));

//         // Print r_sk_c
//         println!("r_sk_c: {:?}", hex::encode(r_sk_c.to_bytes()));

//         // Print g_r
//         println!(
//             "g_r.x: {:?}",
//             hex::encode(
//                 g_r.unwrap()
//                     .to_affine()
//                     .to_encoded_point(false)
//                     .x()
//                     .unwrap()
//             )
//         );
//         println!(
//             "g_r.y: {:?}",
//             hex::encode(
//                 g_r.unwrap()
//                     .to_affine()
//                     .to_encoded_point(false)
//                     .y()
//                     .unwrap()
//             )
//         );

//         // Print hash_m_pk_pow_r
//         println!(
//             "hash_m_pk_pow_r.x: {:?}",
//             hex::encode(
//                 hash_m_pk_pow_r
//                     .unwrap()
//                     .to_affine()
//                     .to_encoded_point(false)
//                     .x()
//                     .unwrap()
//             )
//         );
//         println!(
//             "hash_m_pk_pow_r.y: {:?}",
//             hex::encode(
//                 hash_m_pk_pow_r
//                     .unwrap()
//                     .to_affine()
//                     .to_encoded_point(false)
//                     .y()
//                     .unwrap()
//             )
//         );

//         // Test encode_pt()
//         let g_as_bytes = encode_pt(&g);
//         assert_eq!(
//             hex::encode(g_as_bytes),
//             "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
//         );

//         // Test byte_array_to_scalar()
//         let scalar = byte_array_to_scalar(&c); // TODO this `fn` looks suspicious as in reproducing const time ops
//         assert_eq!(
//             hex::encode(scalar.to_bytes()),
//             "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
//         );

//         // Test the hash-to-curve algorithm
//         let h = hash_to_secp(b"abc");
//         assert_eq!(
//             hex::encode(h.to_affine().to_encoded_point(false).x().unwrap()),
//             "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"
//         );
//         assert_eq!(
//             hex::encode(h.to_affine().to_encoded_point(false).y().unwrap()),
//             "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
//         );
//         assert!(verified);
//     }

//     #[test]
//     fn plume_v2_test() {
//         let g = ProjectivePoint::GENERATOR;

//         let m = b"An example app message string";

//         // Fixed key nullifier, secret key, and random value for testing
//         // Normally a secure enclave would generate these values, and output to a wallet implementation
//         let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) =
//             test_gen_signals(m, PlumeVersion::V2);

//         // The signer's secret key. It is only accessed within the secu`re enclave.
//         let sk = gen_test_scalar_sk();

//         // The user's public key: g^sk.
//         let pk = &g * &sk;

//         // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
//         // The wallet should probably run this prior to snarkify-ing as a sanity check
//         // m and nullifier should be public, so we can verify that they are correct
//         let verified = PlumeSignature {
//             message: m,
//             pk: &pk,
//             nullifier: &nullifier,
//             c: &c,
//             s: &r_sk_c,
//             v1: None,
//         }
//         .verify_signals();
//         assert!(verified)
//     }
// }
