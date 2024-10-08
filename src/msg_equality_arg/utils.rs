use ark_ed_on_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};

pub fn b2s_hash_to_field<C: CanonicalSerialize>(input: &C) -> Fr {

    // hash input to bytes
    let bytes = input.hash::<blake2::Blake2s>();
    
    // convert bytes in little-endian to Fr field elements, with reduction
    Fr::from_le_bytes_mod_order(&bytes)
}
