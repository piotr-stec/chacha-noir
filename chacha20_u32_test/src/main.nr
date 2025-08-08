fn main(key: [u32; 8], nonce: pub [u32; 3], counter: pub u32, input: [u32; 16]) -> pub [u32; 16] {
    chacha20::chacha20_u32::chacha20(key, nonce, counter, input)
}
