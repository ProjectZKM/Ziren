use hashbrown::HashMap;
use std::str::FromStr;

use crate::{MipsAirId, Opcode};
use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize a `HashMap<u32, V>` as a `Vec<(u32, V)>`.
pub fn serialize_hashmap_as_vec<V: Serialize, S: Serializer>(
    map: &HashMap<u32, V, BuildNoHashHasher<u32>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Serialize::serialize(&map.iter().collect::<Vec<_>>(), serializer)
}

/// Deserialize a `Vec<(u32, V)>` as a `HashMap<u32, V>`.
pub fn deserialize_hashmap_as_vec<'de, V: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<u32, V, BuildNoHashHasher<u32>>, D::Error> {
    let seq: Vec<(u32, V)> = Deserialize::deserialize(deserializer)?;
    Ok(seq.into_iter().collect())
}

/// Returns `true` if the given opcode is a signed operation.
#[must_use]
pub fn is_signed_operation(opcode: Opcode) -> bool {
    // todo: add more signed operations
    opcode == Opcode::DIV || opcode == Opcode::MOD
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per MIPS spec.
#[must_use]
pub fn get_quotient_and_remainder(b: u32, c: u32, opcode: Opcode) -> (u32, u32) {
    if c == 0 {
        // When c is 0, the quotient is 2^32 - 1 and the remainder is b regardless of whether we
        // perform signed or unsigned division.
        (u32::MAX, b)
    } else if is_signed_operation(opcode) {
        ((b as i32).wrapping_div(c as i32) as u32, (b as i32).wrapping_rem(c as i32) as u32)
    } else {
        (b.wrapping_div(c), b.wrapping_rem(c))
    }
}

/// Calculate the most significant bit of the given 32-bit integer `a`, and returns it as a u8.
#[must_use]
pub const fn get_msb(a: u32) -> u8 {
    ((a >> 31) & 1) as u8
}

/// Load the cost of each air from the predefined JSON.
#[must_use]
pub fn mips_costs() -> HashMap<MipsAirId, usize> {
    let costs: HashMap<String, usize> =
        serde_json::from_str(include_str!("./artifacts/mips_costs.json")).unwrap();
    costs.into_iter().map(|(k, v)| (MipsAirId::from_str(&k).unwrap(), v)).collect()
}

pub fn sign_extend<const N: usize>(value: u32) -> u32 {
    let is_signed = (value >> (N - 1)) != 0;
    let signed = ((1 << (32 - N)) - 1) << N;
    let mask = (1 << N) - 1;
    if is_signed {
        value & mask | signed
    } else {
        value & mask
    }
}
