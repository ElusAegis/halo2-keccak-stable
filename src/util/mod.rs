//! Utility traits, functions used in the crate.

use halo2_proofs::circuit::{Value};
use halo2_proofs::circuit::AssignedCell;
use halo2_proofs::plonk::Assigned;
use eth_types::{Field, ToScalar, Word};

pub mod constraint_builder;
pub mod eth_types;
pub mod expression;
pub mod prime_field;
pub mod assign_value;
pub(crate) mod word;

pub type Halo2AssignedCell<'v, F> = AssignedCell<Assigned<F>, F>;


pub const SKIP_FIRST_PASS: bool = true;

pub const NUM_BITS_PER_BYTE: usize = 8;
pub const NUM_BYTES_PER_WORD: usize = 8;
pub const NUM_BITS_PER_WORD: usize = NUM_BYTES_PER_WORD * NUM_BITS_PER_BYTE;
// The number of bits used in the sparse word representation per bit
pub const BIT_COUNT: usize = 3;
// The base of the bit in the sparse word representation
pub const BIT_SIZE: usize = 2usize.pow(BIT_COUNT as u32);

// `a ^ ((~b) & c) ^ d` is calculated by doing `lookup[5 - 2*a - b + c - 2*d]`
// pub(crate) const CHI_EXT_LOOKUP_TABLE: [u8; 7] = [0, 0, 1, 1, 0, 0, 1];

/// Description of which bits (positions) a part contains
#[derive(Clone, Debug)]
pub struct PartInfo {
    /// The bit positions of the part
    pub bits: Vec<usize>,
}

/// Description of how a word is split into parts
#[derive(Clone, Debug)]
pub struct WordParts {
    /// The parts of the word
    pub parts: Vec<PartInfo>,
}


/// Wraps the internal value of `value` in an [Option].
/// If the value is [None], then the function returns [None].
/// * `value`: Value to convert.
pub fn value_to_option<V>(value: Value<V>) -> Option<V> {
    let mut v = None;
    value.map(|val| {
        v = Some(val);
    });
    v
}

/// Rotates a word that was split into parts to the right
pub fn rotate<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_right(get_rotate_count(count, part_size));
    rotated_parts
}

/// Rotates a word that was split into parts to the left
pub fn rotate_rev<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_left(get_rotate_count(count, part_size));
    rotated_parts
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word
pub fn pack<F: Field>(bits: &[u8]) -> F {
    pack_with_base(bits, BIT_SIZE)
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word with the
/// specified bit base
pub fn pack_with_base<F: Field>(bits: &[u8], base: usize) -> F {
    let base = F::from(base as u64);
    bits.iter().rev().fold(F::ZERO, |acc, &bit| acc * base + F::from(bit as u64))
}

/// Decodes the bits using the position data found in the part info
pub fn pack_part(bits: &[u8], info: &PartInfo) -> u64 {
    info.bits
        .iter()
        .rev()
        .fold(0u64, |acc, &bit_pos| acc * (BIT_SIZE as u64) + (bits[bit_pos] as u64))
}

/// Unpack a sparse keccak word into bits in the range [0,BIT_SIZE[
pub fn unpack<F: Field>(packed: F) -> [u8; NUM_BITS_PER_WORD] {
    let mut bits = [0; NUM_BITS_PER_WORD];
    let packed = Word::from_little_endian(packed.to_repr().as_ref());
    let mask = Word::from(BIT_SIZE - 1);
    for (idx, bit) in bits.iter_mut().enumerate() {
        *bit = ((packed >> (idx * BIT_COUNT)) & mask).as_u32() as u8;
    }
    debug_assert_eq!(pack::<F>(&bits), packed.to_scalar().unwrap());
    bits
}

/// Returns the size (in bits) of each part size when splitting up a keccak word
/// in parts of `part_size`
pub fn target_part_sizes(part_size: usize) -> Vec<usize> {
    let num_full_chunks = NUM_BITS_PER_WORD / part_size;
    let partial_chunk_size = NUM_BITS_PER_WORD % part_size;
    let mut part_sizes = vec![part_size; num_full_chunks];
    if partial_chunk_size > 0 {
        part_sizes.push(partial_chunk_size);
    }
    part_sizes
}

/// Gets the rotation count in parts
pub fn get_rotate_count(count: usize, part_size: usize) -> usize {
    (count + part_size - 1) / part_size
}

impl WordParts {
    /// Returns a description of how a word will be split into parts
    pub fn new(part_size: usize, rot: usize, normalize: bool) -> Self {
        let mut bits = (0usize..64).collect::<Vec<_>>();
        bits.rotate_right(rot);

        let mut parts = Vec::new();
        let mut rot_idx = 0;

        let mut idx = 0;
        let target_sizes = if normalize {
            // After the rotation we want the parts of all the words to be at the same
            // positions
            target_part_sizes(part_size)
        } else {
            // Here we only care about minimizing the number of parts
            let num_parts_a = rot / part_size;
            let partial_part_a = rot % part_size;

            let num_parts_b = (64 - rot) / part_size;
            let partial_part_b = (64 - rot) % part_size;

            let mut part_sizes = vec![part_size; num_parts_a];
            if partial_part_a > 0 {
                part_sizes.push(partial_part_a);
            }

            part_sizes.extend(vec![part_size; num_parts_b]);
            if partial_part_b > 0 {
                part_sizes.push(partial_part_b);
            }

            part_sizes
        };
        // Split into parts bit by bit
        for part_size in target_sizes {
            let mut num_consumed = 0;
            while num_consumed < part_size {
                let mut part_bits: Vec<usize> = Vec::new();
                while num_consumed < part_size {
                    if !part_bits.is_empty() && bits[idx] == 0 {
                        break;
                    }
                    if bits[idx] == 0 {
                        rot_idx = parts.len();
                    }
                    part_bits.push(bits[idx]);
                    idx += 1;
                    num_consumed += 1;
                }
                parts.push(PartInfo { bits: part_bits });
            }
        }

        debug_assert_eq!(get_rotate_count(rot, part_size), rot_idx);

        parts.rotate_left(rot_idx);
        debug_assert_eq!(parts[0].bits[0], 0);

        Self { parts }
    }
}