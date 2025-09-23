/// Multiply a byte by 2 in GF(2^8) with AES polynomial 0x9B
fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {
        (x << 1) ^ 0x1b
    } else {
        x << 1
    }
}

/// Multiply a byte by 1, 2, or 3 in GF(2^8)
pub fn mul_md5(x: u8, by: u8) -> u8 {
    match by {
        1 => x,
        2 => xtime(x),
        3 => xtime(x) ^ x, // 3*x = (2*x) ⊕ x
        _ => panic!("Only supports multipliers 1, 2, or 3"),
    }
}
