fn main(
    key: [[Field; 32]; 8],
    nonce: pub [[Field; 32]; 3],
    counter: pub [Field; 32],
    input: [[Field; 32]; 16],
) -> pub [[Field; 32]; 16] {
    chacha20::chacha20_bitwise_field::chacha20(key, nonce, counter, input)
}
