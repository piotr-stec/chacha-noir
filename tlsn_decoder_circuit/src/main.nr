use dep::chacha20::chacha12_block;

global BIT_ENCODING_SIZE: u32 = 16;
global BYTE_ENCODING_SIZE: u32 = 128;
global TWO_BYTE_ENCODING_SIZE: u32 = 256;

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
        (seed[0] as u32)
            | ((seed[1] as u32) << 8)
            | ((seed[2] as u32) << 16)
            | ((seed[3] as u32) << 24),
        (seed[4] as u32)
            | ((seed[5] as u32) << 8)
            | ((seed[6] as u32) << 16)
            | ((seed[7] as u32) << 24),
        (seed[8] as u32)
            | ((seed[9] as u32) << 8)
            | ((seed[10] as u32) << 16)
            | ((seed[11] as u32) << 24),
        (seed[12] as u32)
            | ((seed[13] as u32) << 8)
            | ((seed[14] as u32) << 16)
            | ((seed[15] as u32) << 24),
        (seed[16] as u32)
            | ((seed[17] as u32) << 8)
            | ((seed[18] as u32) << 16)
            | ((seed[19] as u32) << 24),
        (seed[20] as u32)
            | ((seed[21] as u32) << 8)
            | ((seed[22] as u32) << 16)
            | ((seed[23] as u32) << 24),
        (seed[24] as u32)
            | ((seed[25] as u32) << 8)
            | ((seed[26] as u32) << 16)
            | ((seed[27] as u32) << 24),
        (seed[28] as u32)
            | ((seed[29] as u32) << 8)
            | ((seed[30] as u32) << 16)
            | ((seed[31] as u32) << 24),
    ]
}

fn generate_chacha_state(seed: [u8; 32], stream_id: u64, word_pos: u64) -> [u32; 16] {
    let key = seed_to_key(seed);
    let block_pos = word_pos / 16;

    [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        block_pos as u32,
        (block_pos >> 32) as u32,
        stream_id as u32,
        (stream_id >> 32) as u32,
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
fn generate_zero_encoding(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    range_len: u32,
) -> [u8; 128] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;

    // Generate first 64 bytes (first ChaCha block)
    let state1 = generate_chacha_state(secret.seed, stream_id, word_pos);
    let output1 = chacha12_block(state1);

    // Generate second 64 bytes (second ChaCha block)
    let state2 = generate_chacha_state(secret.seed, stream_id, word_pos + 16);
    let output2 = chacha12_block(state2);

    // Combine both outputs into 128 bytes
    let mut result = [0; 128];

    // First 64 bytes from first block
    for i in 0..16 {
        let word = output1[i];
        result[i * 4] = (word & 0xff) as u8;
        result[i * 4 + 1] = ((word >> 8) & 0xff) as u8;
        result[i * 4 + 2] = ((word >> 16) & 0xff) as u8;
        result[i * 4 + 3] = ((word >> 24) & 0xff) as u8;
    }

    // Second 64 bytes from second block
    for i in 0..16 {
        let word = output2[i];
        result[64 + i * 4] = (word & 0xff) as u8;
        result[64 + i * 4 + 1] = ((word >> 8) & 0xff) as u8;
        result[64 + i * 4 + 2] = ((word >> 16) & 0xff) as u8;
        result[64 + i * 4 + 3] = ((word >> 24) & 0xff) as u8;
    }

    result
}

// Generate zero-encoding for multiple bytes (up to 256 bytes output)
fn generate_zero_encoding_multi_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    byte_count: u32,
) -> [u8; 256] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;

    let mut result = [0; 256];

    // Generate as many ChaCha blocks as needed
    // Each byte needs 128 bytes of encoding, so 2 bytes need 256 bytes
    let blocks_needed = (byte_count * 128 + 63) / 64; // Round up to nearest block

    for block_idx in 0..4 {
        // Max 4 blocks for 256 bytes
        if block_idx < blocks_needed {
            let state =
                generate_chacha_state(secret.seed, stream_id, word_pos + (block_idx as u64 * 16));
            let output = chacha12_block(state);

            // Convert to bytes and store in result
            for i in 0..16 {
                let word = output[i];
                let base_idx = block_idx * 64 + i * 4;
                if base_idx < 256 {
                    result[base_idx] = (word & 0xff) as u8;
                    if base_idx + 1 < 256 {
                        result[base_idx + 1] = ((word >> 8) & 0xff) as u8;
                    }
                    if base_idx + 2 < 256 {
                        result[base_idx + 2] = ((word >> 16) & 0xff) as u8;
                    }
                    if base_idx + 3 < 256 {
                        result[base_idx + 3] = ((word >> 24) & 0xff) as u8;
                    }
                }
            }
        }
    }

    result
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
    bit_count: u32,
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
            byte_value |= 1 << (i as u8);
        }
    }
    byte_value
}

// Decode a single byte from its 128-byte encoding
fn decode_data_1_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    encoded_data: [u8; 128],
) -> u8 {
    let decoded_bits = decode_bits(secret, direction, range_start, encoded_data, 8);
    bits_to_byte(decoded_bits)
}

// Decode multiple bytes from encoded data
fn decode_data_multi_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    encoded_data: [u8; 256],
    byte_count: u32,
) -> [u8; 2] {
    // Max 2 bytes for now
    let zero_encoding =
        generate_zero_encoding_multi_byte(secret, direction, range_start, byte_count);

    let mut result = [0; 2];

    for byte_idx in 0..byte_count {
        if byte_idx < 2 {
            // Safety check
            let mut decoded_bits = [false; 8];

            // Decode each bit of this byte
            for bit_idx in 0..8 {
                let encoding_offset = byte_idx * 128; // Each byte uses 128 bytes
                let start_pos = encoding_offset + bit_idx * BIT_ENCODING_SIZE;

                // Extract 16-byte chunks
                let mut zero_chunk = [0; 16];
                let mut encoded_chunk = [0; 16];

                for i in 0..16 {
                    zero_chunk[i] = zero_encoding[(start_pos + i) as u32];
                    encoded_chunk[i] = encoded_data[(start_pos + i) as u32];
                }

                let (bit_value, error_code) = decode_bit(zero_chunk, encoded_chunk, secret.delta);
                assert(error_code == DECODE_SUCCESS);

                decoded_bits[bit_idx] = bit_value;
            }

            // Convert bits to byte
            let mut byte_value = 0;
            for i in 0..8 {
                if decoded_bits[i] {
                    byte_value |= 1 << (i as u8);
                }
            }

            result[byte_idx] = byte_value;
        }
    }

    result
}

// Encode multiple bytes
fn encode_data_multi_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    data: [u8; 2],
    byte_count: u32,
) -> [u8; 256] {
    let mut encoded_data =
        generate_zero_encoding_multi_byte(secret, direction, range_start, byte_count);

    // Apply delta for each bit that is 1 in each byte
    for byte_idx in 0..byte_count {
        if byte_idx < 2 {
            // Safety check
            let byte_value = data[byte_idx];
            let encoding_offset = byte_idx * 128; // Each byte uses 128 bytes

            for bit_idx in 0..8 {
                let bit = (byte_value >> bit_idx) & 1;
                if bit == 1 {
                    let encoding_start = encoding_offset + (bit_idx as u32) * BIT_ENCODING_SIZE;
                    for i in 0..BIT_ENCODING_SIZE {
                        encoded_data[(encoding_start + i) as u32] ^= secret.delta[i as u32];
                    }
                }
            }
        }
    }

    encoded_data
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
    encoded_data: [u8; 128],
) {
    let secret = DecoderSecret { seed: decoder_seed, delta: decoder_delta };

    // Decode the encoded data
    let decoded_byte = decode_data_1_byte(secret, direction, transcript_position, encoded_data);

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
    let mut encoded_data = generate_zero_encoding(secret, direction, position, 1);

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
    let secret = DecoderSecret { seed: [42; 32], delta: [13; 16] };
    let direction = 0; // Received
    let position = 0;

    // Test different byte values
    for test_byte in [170] {
        // Generate encoding for this byte
        let word_pos = (position * 32) as u64;
        let state = generate_chacha_state(secret.seed, direction, word_pos);

        let mut encoded_data = generate_zero_encoding(secret, direction, position, 1);
        println(f"encoded_data: {encoded_data}");
        println(f"test byte : {test_byte}");

        let test_to_decode = [
            27, 140, 32, 205, 226, 219, 180, 60, 211, 199, 9, 178, 144, 172, 80, 220, 223, 179, 39,
            138, 174, 175, 72, 73, 184, 168, 29, 150, 202, 99, 170, 246, 7, 166, 101, 241, 82, 145,
            64, 12, 189, 34, 235, 74, 211, 244, 219, 114, 240, 84, 48, 236, 54, 187, 70, 11, 124,
            243, 31, 90, 92, 119, 238, 176, 240, 200, 57, 15, 100, 108, 176, 16, 205, 59, 99, 198,
            124, 16, 23, 190, 173, 184, 172, 126, 94, 186, 38, 58, 47, 216, 45, 34, 205, 185, 102,
            111, 16, 120, 212, 254, 210, 138, 180, 38, 239, 244, 74, 125, 118, 167, 76, 234, 114,
            93, 226, 200, 127, 66, 34, 252, 206, 129, 124, 107, 49, 253, 16, 67,
        ];

        let expected_encoded = [
            27, 140, 32, 205, 226, 219, 180, 60, 211, 199, 9, 178, 144, 172, 80, 220, 223, 179, 39,
            138, 174, 175, 72, 73, 184, 168, 29, 150, 202, 99, 170, 246, 7, 166, 101, 241, 82, 145,
            64, 12, 189, 34, 235, 74, 211, 244, 219, 114, 240, 84, 48, 236, 54, 187, 70, 11, 124,
            243, 31, 90, 92, 119, 238, 176, 240, 200, 57, 15, 100, 108, 176, 16, 205, 59, 99, 198,
            124, 16, 23, 190, 173, 184, 172, 126, 94, 186, 38, 58, 47, 216, 45, 34, 205, 185, 102,
            111, 16, 120, 212, 254, 210, 138, 180, 38, 239, 244, 74, 125, 118, 167, 76, 234, 127,
            80, 239, 197, 114, 79, 47, 241, 195, 140, 113, 102, 60, 240, 29, 78,
        ];

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

        assert(expected_encoded == encoded_data);

        // Decode and verify
        let decoded_byte = decode_data_1_byte(secret, direction, position, test_to_decode);
        println(f"decoded byte: {decoded_byte}");
        // assert(decoded_byte == test_byte);
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
}

#[test]
fn test_encode_decode_two_bytes() {
    let secret = DecoderSecret { seed: [42; 32], delta: [13; 16] };
    let direction = 0;
    let position = 0;
    let test_data = [170, 138]; // Dane do zakodowania

    // Enkoduj dane
    let encoded_data = encode_data_multi_byte(secret, direction, position, test_data, 2);
    println(f"Encoded data: {encoded_data}");

    let expected_encoded = [
        27, 140, 32, 205, 226, 219, 180, 60, 211, 199, 9, 178, 144, 172, 80, 220, 223, 179, 39, 138,
        174, 175, 72, 73, 184, 168, 29, 150, 202, 99, 170, 246, 7, 166, 101, 241, 82, 145, 64, 12,
        189, 34, 235, 74, 211, 244, 219, 114, 240, 84, 48, 236, 54, 187, 70, 11, 124, 243, 31, 90,
        92, 119, 238, 176, 240, 200, 57, 15, 100, 108, 176, 16, 205, 59, 99, 198, 124, 16, 23, 190,
        173, 184, 172, 126, 94, 186, 38, 58, 47, 216, 45, 34, 205, 185, 102, 111, 16, 120, 212, 254,
        210, 138, 180, 38, 239, 244, 74, 125, 118, 167, 76, 234, 127, 80, 239, 197, 114, 79, 47,
        241, 195, 140, 113, 102, 60, 240, 29, 78, 7, 77, 245, 67, 158, 62, 104, 215, 157, 16, 236,
        4, 232, 50, 1, 98, 206, 28, 130, 76, 124, 208, 225, 73, 154, 248, 102, 4, 107, 172, 111,
        123, 255, 5, 185, 223, 41, 188, 11, 130, 40, 74, 166, 116, 186, 83, 130, 227, 194, 155, 134,
        28, 22, 39, 91, 175, 218, 211, 205, 61, 137, 255, 90, 53, 94, 52, 213, 177, 12, 200, 174,
        217, 65, 83, 242, 117, 42, 161, 201, 167, 154, 154, 113, 53, 143, 192, 255, 14, 34, 249,
        140, 175, 161, 9, 43, 239, 174, 20, 144, 122, 131, 233, 175, 236, 194, 121, 91, 203, 88,
        129, 30, 12, 254, 22, 144, 23, 10, 199, 251, 251, 179, 69, 233, 223, 229, 98, 195, 133,
    ];

    assert(expected_encoded == encoded_data);
    // Dekoduj z powrotem
    let decoded_data = decode_data_multi_byte(secret, direction, position, encoded_data, 2);

    println(f"decoded data: {decoded_data}");

    // assert(decoded_data[0] == test_data[0]);
    // assert(decoded_data[1] == test_data[1]);

}
