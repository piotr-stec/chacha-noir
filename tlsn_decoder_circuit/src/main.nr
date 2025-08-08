use dep::chacha20::{chacha12_block};

global BIT_ENCODING_SIZE: u32 = 16;
global BYTE_ENCODING_SIZE: u32 = 128;

// Error types for decoding
global DECODE_SUCCESS: u8 = 0;
global DECODE_INVALID_LENGTH: u8 = 1;
global DECODE_INVALID_ENCODING: u8 = 2;
global DECODE_INSUFFICIENT_DATA: u8 = 3;

struct DecoderSecret {
    seed: [u8; 32],
    delta: [u8; 16],
}

fn seed_to_key(seed: [u8; 32]) -> [u32; 8] {
    [
        (seed[0] as u32) | ((seed[1] as u32) << 8) | ((seed[2] as u32) << 16) | ((seed[3] as u32) << 24),
        (seed[4] as u32) | ((seed[5] as u32) << 8) | ((seed[6] as u32) << 16) | ((seed[7] as u32) << 24),
        (seed[8] as u32) | ((seed[9] as u32) << 8) | ((seed[10] as u32) << 16) | ((seed[11] as u32) << 24),
        (seed[12] as u32) | ((seed[13] as u32) << 8) | ((seed[14] as u32) << 16) | ((seed[15] as u32) << 24),
        (seed[16] as u32) | ((seed[17] as u32) << 8) | ((seed[18] as u32) << 16) | ((seed[19] as u32) << 24),
        (seed[20] as u32) | ((seed[21] as u32) << 8) | ((seed[22] as u32) << 16) | ((seed[23] as u32) << 24),
        (seed[24] as u32) | ((seed[25] as u32) << 8) | ((seed[26] as u32) << 16) | ((seed[27] as u32) << 24),
        (seed[28] as u32) | ((seed[29] as u32) << 8) | ((seed[30] as u32) << 16) | ((seed[31] as u32) << 24)
    ]
}

fn generate_chacha_state(seed: [u8; 32], stream_id: u64, word_pos: u64) -> [u32; 16] {
    let key = seed_to_key(seed);
    let block_pos = word_pos / 16;
    
    [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        block_pos as u32, (block_pos >> 32) as u32,
        stream_id as u32, (stream_id >> 32) as u32
    ]
}

fn words_to_bytes_128(words: [u32; 16]) -> [u8; 128] {
    let mut result = [0; 128];
    for i in 0..16 {
        let word = words[i];
        result[i * 4] = (word & 0xff) as u8;
        result[i * 4 + 1] = ((word >> 8) & 0xff) as u8;
        result[i * 4 + 2] = ((word >> 16) & 0xff) as u8;
        result[i * 4 + 3] = ((word >> 24) & 0xff) as u8;
    }
    result
}

// Generate zero-encoding (PRG output) for given range
fn generate_zero_encoding(secret: DecoderSecret, direction: u64, range_start: u32, range_len: u32) -> [u8; 128] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;
    
    let state = generate_chacha_state(secret.seed, stream_id, word_pos);
    let output = chacha12_block(state);
    
    words_to_bytes_128(output)
}

// Decode a single bit from its 16-byte encoding
fn decode_bit(zero_chunk: [u8; 16], encoded_chunk: [u8; 16], delta: [u8; 16]) -> (bool, u8) {
    // XOR encoded chunk with corresponding zero encoding
    let mut decoded_chunk = [0; 16];
    for i in 0..16 {
        decoded_chunk[i] = encoded_chunk[i] ^ zero_chunk[i];
    }
    
    // Check if result is all zeros (bit = 0) or equals delta (bit = 1)
    let mut is_zero = true;
    let mut is_delta = true;
    
    for i in 0..16 {
        if decoded_chunk[i] != 0 {
            is_zero = false;
        }
        if decoded_chunk[i] != delta[i] {
            is_delta = false;
        }
    }
    
    if is_zero {
        (false, DECODE_SUCCESS)
    } else if is_delta {
        (true, DECODE_SUCCESS)
    } else {
        (false, DECODE_INVALID_ENCODING)
    }
}

// Decode bits from encoded data (LSB-first ordering)
fn decode_bits(
    secret: DecoderSecret, 
    direction: u64, 
    range_start: u32, 
    encoded_data: [u8; 128], 
    bit_count: u32
) -> [bool; 8] {
    // Generate zero encoding for comparison
    let zero_encoding = generate_zero_encoding(secret, direction, range_start, 1);
    
    let mut decoded_bits = [false; 8];
    
    // Decode each bit (max 8 bits)
    let max_bits = if bit_count > 8 { 8 } else { bit_count };
    for bit_idx in 0..max_bits {
        
        let start_pos = bit_idx * BIT_ENCODING_SIZE;
        
        // Extract 16-byte chunks
        let mut zero_chunk = [0; 16];
        let mut encoded_chunk = [0; 16];
        
        for i in 0..16 {
            zero_chunk[i] = zero_encoding[(start_pos + i) as u32];
            encoded_chunk[i] = encoded_data[(start_pos + i) as u32];
        }
        
        let (bit_value, error_code) = decode_bit(zero_chunk, encoded_chunk, secret.delta);
        
        // In Noir, we can't early return, so we'll check error at the end
        assert(error_code == DECODE_SUCCESS);
        
        decoded_bits[bit_idx] = bit_value;
    }
    
    decoded_bits
}

// Convert decoded bits to byte value (LSB-first)
fn bits_to_byte(bits: [bool; 8]) -> u8 {
    let mut byte_value = 0;
    for i in 0..8 {
        if bits[i] {
            byte_value |= 1 << i;
        }
    }
    byte_value
}

// Decode a single byte from its 128-byte encoding
fn decode_data_1_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    encoded_data: [u8; 128]
) -> u8 {
    let decoded_bits = decode_bits(secret, direction, range_start, encoded_data, 8);
    bits_to_byte(decoded_bits)
}

// TLSn Decoder Verification Circuit
// Proves that encoded data corresponds to specific plaintext without revealing the secret
fn main(
    // Public: claimed plaintext and its location
    plaintext_byte: u8,
    transcript_position: u32,
    direction: u64,
    
    // Private: decoder secret (only known to prover)
    decoder_seed: [u8; 32],
    decoder_delta: [u8; 16],
    
    // Public: encoded data to verify
    encoded_data: [u8; 128]
) {
    let secret = DecoderSecret {
        seed: decoder_seed,
        delta: decoder_delta
    };
    
    // Decode the encoded data
    let decoded_byte = decode_data_1_byte(
        secret,
        direction,
        transcript_position,
        encoded_data
    );
    
    // Assert decoded byte matches claimed plaintext
    assert(decoded_byte == plaintext_byte);
}

#[test]
fn test_encode_decode_roundtrip() {
    // Test data
    let seed = [1; 32];
    let delta = [0xff; 16];
    let secret = DecoderSecret { seed, delta };
    
    let direction = 0;
    let position = 50;
    let original_byte = 0x42; // 'B'
    
    // First encode the byte (using our previous encoder logic)
    let word_pos = (position * 32) as u64;
    let state = generate_chacha_state(secret.seed, direction, word_pos);
    let output = chacha12_block(state);
    let mut encoded_data = words_to_bytes_128(output);
    
    // Apply delta for each bit that is 1 (LSB-first)
    for bit_idx in 0..8 {
        let bit = (original_byte >> bit_idx) & 1;
        if bit == 1 {
            let encoding_start = (bit_idx as u32) * BIT_ENCODING_SIZE;
            for i in 0..BIT_ENCODING_SIZE {
                encoded_data[(encoding_start + i) as u32] ^= secret.delta[i as u32];
            }
        }
    }
    
    // Now decode it back
    let decoded_byte = decode_data_1_byte(secret, direction, position, encoded_data);
    
    assert(decoded_byte == original_byte);
}

#[test]
fn test_decode_different_bytes() {
    let secret = DecoderSecret { seed: [2; 32], delta: [0x0f; 16] };
    let direction = 1; // Received
    let position = 100;
    
    // Test different byte values
    for test_byte in [0x00, 0x01, 0x42, 0xff] {
        // Generate encoding for this byte
        let word_pos = (position * 32) as u64;
        let state = generate_chacha_state(secret.seed, direction, word_pos);
        let output = chacha12_block(state);
        let mut encoded_data = words_to_bytes_128(output);
        
        // Apply delta for each set bit
        for bit_idx in 0..8 {
            let bit = (test_byte >> bit_idx) & 1;
            if bit == 1 {
                let encoding_start = (bit_idx as u32) * BIT_ENCODING_SIZE;
                for i in 0..BIT_ENCODING_SIZE {
                    encoded_data[(encoding_start + i) as u32] ^= secret.delta[i as u32];
                }
            }
        }
        
        // Decode and verify
        let decoded_byte = decode_data_1_byte(secret, direction, position, encoded_data);
        assert(decoded_byte == test_byte);
    }
}

#[test]
fn test_position_sensitivity() {
    let secret = DecoderSecret { seed: [42; 32], delta: [13; 16] };
    let direction = 0;
    let test_byte = 0x48; // 'H'
    
    // Test two different positions
    let pos1 = 10;
    let pos2 = 100;
    
    // Generate encodings for both positions
    let mut encoding1 = [0; 128];
    let mut encoding2 = [0; 128];
    
    // Position 1
    let word_pos1 = (pos1 * 32) as u64;
    let state1 = generate_chacha_state(secret.seed, direction, word_pos1);
    let output1 = chacha12_block(state1);
    encoding1 = words_to_bytes_128(output1);
    
    for bit_idx in 0..8 {
        let bit = (test_byte >> bit_idx) & 1;
        if bit == 1 {
            let encoding_start = (bit_idx as u32) * BIT_ENCODING_SIZE;
            for j in 0..BIT_ENCODING_SIZE {
                encoding1[(encoding_start + j) as u32] ^= secret.delta[j as u32];
            }
        }
    }
    
    // Position 2  
    let word_pos2 = (pos2 * 32) as u64;
    let state2 = generate_chacha_state(secret.seed, direction, word_pos2);
    let output2 = chacha12_block(state2);
    encoding2 = words_to_bytes_128(output2);
    
    for bit_idx in 0..8 {
        let bit = (test_byte >> bit_idx) & 1;
        if bit == 1 {
            let encoding_start = (bit_idx as u32) * BIT_ENCODING_SIZE;
            for j in 0..BIT_ENCODING_SIZE {
                encoding2[(encoding_start + j) as u32] ^= secret.delta[j as u32];
            }
        }
    }
    
    // Verify both decode correctly
    let decoded1 = decode_data_1_byte(secret, direction, pos1, encoding1);
    let decoded2 = decode_data_1_byte(secret, direction, pos2, encoding2);
    
    assert(decoded1 == test_byte);
    assert(decoded2 == test_byte);
    
    // Verify encodings are different
    assert(encoding1 != encoding2);
}

#[test]
fn test_rust_noir_decoder_compatibility() {
    // Test parameters from Rust compatibility test
    let seed = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let delta = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let direction = 0; // Sent
    let position = 100;
    let test_byte = 0x48; // 'H'
    
    // Encoded data from Rust (first 128 bytes)
    let rust_encoded_data = [
        88, 74, 122, 75, 236, 64, 93, 240, 187, 157, 148, 32, 51, 198, 65, 113, 
        183, 164, 173, 114, 5, 96, 118, 24, 70, 86, 151, 22, 6, 169, 6, 133,
        // Continue with remaining bytes - for test we'll generate them
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    
    // Generate the full encoded data like Rust would
    let secret = DecoderSecret { seed, delta };
    let word_pos = (position * 32) as u64;
    let state = generate_chacha_state(secret.seed, direction, word_pos);
    let output = chacha12_block(state);
    let mut full_encoded_data = words_to_bytes_128(output);
    
    // Apply delta for set bits in test_byte
    for bit_idx in 0..8 {
        let bit = (test_byte >> bit_idx) & 1;
        if bit == 1 {
            let encoding_start = (bit_idx as u32) * BIT_ENCODING_SIZE;
            for j in 0..BIT_ENCODING_SIZE {
                full_encoded_data[(encoding_start + j) as u32] ^= secret.delta[j as u32];
            }
        }
    }
    
    // Verify first 32 bytes match Rust output
    for i in 0..32 {
        assert(full_encoded_data[i] == rust_encoded_data[i]);
    }
    
    // Test decoding
    let decoded_byte = decode_data_1_byte(secret, direction, position, full_encoded_data);
    assert(decoded_byte == test_byte);
}