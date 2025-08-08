fn main(
    key: [[bool; 32]; 8],
    nonce: pub [[bool; 32]; 3],
    counter: pub [bool; 32],
    input: [[bool; 32]; 16],
) -> pub [[bool; 32]; 16] {
    chacha20::chacha20_bitwise::chacha20(key, nonce, counter, input)
}
