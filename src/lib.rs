//! The zkEVM keccak circuit implementation, with some modifications.
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit
//!
//! This is a lookup table based implementation, where bytes are packed into big field elements as efficiently as possible.
//! The circuits can be configured to use different numbers of columns, by specifying the number of rows per internal
//! round of the keccak_f permutation.

use crate::circuit::{generate_halo2_proof, verify_halo2_proof};
use crate::serialisation::{deserialize_circuit_inputs, InputsSerialisationWrapper};
pub use circuit::KeccakCircuit;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::path::Path;
use thiserror::Error;
pub use vanilla::KeccakConfigParams;

mod util;
/// Module for Keccak circuits in vanilla halo2.
mod vanilla;

mod circuit;
pub mod io;

mod serialisation;
#[cfg(test)]
mod tests;

pub const DEFAULT_CONFIG: KeccakConfigParams = KeccakConfigParams {
    k: 14,
    rows_per_round: 28,
};

#[derive(Debug, Error)]
pub struct Keccak256Error(String);

impl Display for Keccak256Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn prove(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let srs = io::read_srs_path(Path::new(&srs_key_path));
    let proving_key =
        io::read_pk::<KeccakCircuit<Fr>>(Path::new(&proving_key_path), DEFAULT_CONFIG);

    prove_with_params(srs, proving_key, input)
}

#[cfg(target_arch = "wasm32")]
pub fn prove(
    srs_key: &[u8],
    proving_key: &[u8],
    input: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let srs = io::read_srs_bytes(srs_key);
    let proving_key = io::read_pk_bytes::<KeccakCircuit<Fr>>(proving_key, DEFAULT_CONFIG);

    prove_with_params(srs, proving_key, input)
}

fn prove_with_params(
    srs: ParamsKZG<Bn256>,
    proving_key: ProvingKey<G1Affine>,
    input: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let circuit_inputs = deserialize_circuit_inputs(input)
        .map_err(|e| Keccak256Error(format!("Failed to deserialize circuit inputs: {}", e)))?;

    let (inputs, proof) =
        generate_halo2_proof(circuit_inputs, &srs, &proving_key, Some(DEFAULT_CONFIG))
            .map_err(|e| Keccak256Error(format!("Failed to generate the proof: {}", e)))?;

    let serialized_inputs = bincode::serialize(&InputsSerialisationWrapper(inputs))
        .map_err(|e| Keccak256Error(format!("Serialisation of Inputs failed: {}", e)))?;

    Ok((proof, serialized_inputs))
}

fn verify_with_params(
    srs: ParamsKZG<Bn256>,
    verifying_key: VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let deserialized_inputs = bincode::deserialize::<InputsSerialisationWrapper>(&public_inputs)
        .map_err(|e| Keccak256Error(e.to_string()))?
        .0;

    let is_valid = verify_halo2_proof(proof, &deserialized_inputs, &srs, &verifying_key)
        .map_err(|_| Keccak256Error("Verification failed".to_string()))?;

    Ok(is_valid)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let srs = io::read_srs_path(Path::new(&srs_key_path));
    let verifying_key =
        io::read_vk::<KeccakCircuit<Fr>>(Path::new(&verifying_key_path), DEFAULT_CONFIG);

    verify_with_params(srs, verifying_key, proof, public_inputs)
}

#[cfg(target_arch = "wasm32")]
pub fn verify(
    srs_key: &[u8],
    verifying_key: &[u8],
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let srs = io::read_srs_bytes(srs_key);
    let verifying_key = io::read_vk_bytes::<KeccakCircuit<Fr>>(verifying_key, DEFAULT_CONFIG);

    verify_with_params(srs, verifying_key, proof, public_inputs)
}
