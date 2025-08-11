use dep::chacha20::chacha12_block;
use std::hash::blake3;

global BIT_ENCODING_SIZE: u32 = 16;
global BYTE_ENCODING_SIZE: u32 = 128;
global TWO_BYTE_ENCODING_SIZE: u32 = 256;
global FOUR_BYTE_ENCODING_SIZE: u32 = 512;
global ELEVEN_BYTE_ENCODING_SIZE: u32 = 1408; // 11 * 128

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

// Generate zero-encoding for up to 4 bytes (512 bytes output)
fn generate_zero_encoding_four_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    byte_count: u32,
) -> [u8; 512] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;

    let mut result = [0; 512];

    // Each byte needs 128 bytes of encoding, so 4 bytes need 512 bytes
    // We need 8 ChaCha blocks (8 * 64 = 512 bytes)
    let blocks_needed = (byte_count * 128 + 63) / 64; // Round up to nearest block

    for block_idx in 0..8 {
        // Max 8 blocks for 512 bytes
        if block_idx < blocks_needed {
            let state =
                generate_chacha_state(secret.seed, stream_id, word_pos + (block_idx as u64 * 16));
            let output = chacha12_block(state);

            // Convert to bytes and store in result
            for i in 0..16 {
                let word = output[i];
                let base_idx = block_idx * 64 + i * 4;
                if base_idx < 512 {
                    result[base_idx] = (word & 0xff) as u8;
                    if base_idx + 1 < 512 {
                        result[base_idx + 1] = ((word >> 8) & 0xff) as u8;
                    }
                    if base_idx + 2 < 512 {
                        result[base_idx + 2] = ((word >> 16) & 0xff) as u8;
                    }
                    if base_idx + 3 < 512 {
                        result[base_idx + 3] = ((word >> 24) & 0xff) as u8;
                    }
                }
            }
        }
    }

    result
}

// Generate zero-encoding for up to 11 bytes (1408 bytes output)
fn generate_zero_encoding_eleven_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    byte_count: u32,
) -> [u8; 1408] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;

    let mut result = [0; 1408];

    let result_len = result.len() as u32;

    // Each byte needs 128 bytes of encoding, so 11 bytes need 1408 bytes
    // We need 22 ChaCha blocks (22 * 64 = 1408 bytes)
    let blocks_needed = (byte_count * 128 + 63) / 64; // Round up to nearest block

    for block_idx in 0..byte_count * 2 {
        // Max 22 blocks for 1408 bytes
        if block_idx < blocks_needed {
            let state =
                generate_chacha_state(secret.seed, stream_id, word_pos + (block_idx as u64 * 16));
            let output = chacha12_block(state);

            // Convert to bytes and store in result
            for i in 0..16 {
                let word = output[i];
                let base_idx = block_idx * 64 + i * 4;
                if base_idx < result_len {
                    result[base_idx] = (word & 0xff) as u8;
                    if base_idx + 1 < result_len {
                        result[base_idx + 1] = ((word >> 8) & 0xff) as u8;
                    }
                    if base_idx + 2 < result_len {
                        result[base_idx + 2] = ((word >> 16) & 0xff) as u8;
                    }
                    if base_idx + 3 < result_len {
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

// Decode up to 4 bytes from encoded data
fn decode_data_four_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    encoded_data: [u8; 512],
    byte_count: u32,
) -> [u8; 4] {
    let zero_encoding =
        generate_zero_encoding_four_byte(secret, direction, range_start, byte_count);

    let mut result = [0; 4];

    for byte_idx in 0..byte_count {
        if byte_idx < 4 {
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

// Decode up to 11 bytes from encoded data
fn decode_data_eleven_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    encoded_data: [u8; 1408],
    byte_count: u32,
) -> [u8; 11] {
    let zero_encoding =
        generate_zero_encoding_eleven_byte(secret, direction, range_start, byte_count);

    let mut result = [0; 11];

    for byte_idx in 0..byte_count {
        if byte_idx < 11 {
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

    // Apply delta for each bit that is 1 (LSB-first)
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

// Encode up to 4 bytes
fn encode_data_four_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    data: [u8; 4],
    byte_count: u32,
) -> [u8; 512] {
    let mut encoded_data =
        generate_zero_encoding_four_byte(secret, direction, range_start, byte_count);

    // Apply delta for each bit that is 1 in each byte
    for byte_idx in 0..byte_count {
        if byte_idx < 4 {
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

// Encode up to 11 bytes
fn encode_data_eleven_byte(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    data: [u8; 11],
    byte_count: u32,
) -> [u8; 1408] {
    let mut encoded_data =
        generate_zero_encoding_generic_byte::<11>(secret, direction, range_start);

    // Apply delta for each bit that is 1 in each byte
    for byte_idx in 0..byte_count {
        if byte_idx < 11 {
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

// Encode up to 11 bytes
fn encode_data_generic_byte<let INPUT_SIZE: u32>(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
    data: [u8; INPUT_SIZE],
) -> [u8; INPUT_SIZE * 128] {
    let mut encoded_data =
        generate_zero_encoding_generic_byte::<INPUT_SIZE>(secret, direction, range_start);

    // Apply delta for each bit that is 1 in each byte
    for byte_idx in 0..INPUT_SIZE {
        if byte_idx < 11 {
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

// Main function for 11-byte verification
fn main_eleven_byte(
    // Public: claimed plaintext and its location
    plaintext_data: [u8; 11],
    transcript_position: u32,
    direction: u64,
    byte_count: u32,
    // Private: decoder secret
    decoder_seed: [u8; 32],
    decoder_delta: [u8; 16],
    // Public: encoded data to verify
    encoded_data: [u8; 1408],
) {
    let secret = DecoderSecret { seed: decoder_seed, delta: decoder_delta };

    // Decode the encoded data
    let decoded_data = decode_data_eleven_byte(
        secret,
        direction,
        transcript_position,
        encoded_data,
        byte_count,
    );

    // Assert decoded data matches claimed plaintext
    for i in 0..byte_count {
        if i < 11 {
            assert(decoded_data[i] == plaintext_data[i]);
        }
    }
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

#[test]
fn test_encode_decode_four_bytes() {
    let secret = DecoderSecret { seed: [42; 32], delta: [13; 16] };
    let direction = 0;
    let position = 0;
    let test_data = [170, 69, 46, 56]; // 4 bajty do zakodowania

    // Enkoduj dane
    let encoded_data = encode_data_generic_byte(secret, direction, position, test_data);

    // Dekoduj z powrotem
    // let decoded_data = decode_data_four_byte(secret, direction, position, encoded_data, 4);

    let expected_encoded = [
        27, 140, 32, 205, 226, 219, 180, 60, 211, 199, 9, 178, 144, 172, 80, 220, 223, 179, 39, 138,
        174, 175, 72, 73, 184, 168, 29, 150, 202, 99, 170, 246, 7, 166, 101, 241, 82, 145, 64, 12,
        189, 34, 235, 74, 211, 244, 219, 114, 240, 84, 48, 236, 54, 187, 70, 11, 124, 243, 31, 90,
        92, 119, 238, 176, 240, 200, 57, 15, 100, 108, 176, 16, 205, 59, 99, 198, 124, 16, 23, 190,
        173, 184, 172, 126, 94, 186, 38, 58, 47, 216, 45, 34, 205, 185, 102, 111, 16, 120, 212, 254,
        210, 138, 180, 38, 239, 244, 74, 125, 118, 167, 76, 234, 127, 80, 239, 197, 114, 79, 47,
        241, 195, 140, 113, 102, 60, 240, 29, 78, 10, 64, 248, 78, 147, 51, 101, 218, 144, 29, 225,
        9, 229, 63, 12, 111, 195, 17, 143, 65, 113, 221, 236, 68, 151, 245, 107, 9, 102, 161, 98,
        118, 242, 8, 180, 210, 36, 177, 6, 143, 37, 71, 171, 121, 183, 94, 143, 238, 207, 150, 139,
        17, 27, 42, 86, 162, 215, 222, 192, 48, 132, 242, 87, 56, 94, 52, 213, 177, 12, 200, 174,
        217, 65, 83, 242, 117, 42, 161, 201, 167, 154, 154, 113, 53, 143, 192, 255, 14, 34, 249,
        140, 175, 161, 9, 43, 239, 163, 25, 157, 119, 142, 228, 162, 225, 207, 116, 86, 198, 85,
        140, 19, 1, 243, 27, 157, 26, 7, 202, 246, 246, 190, 72, 228, 210, 232, 111, 206, 136, 178,
        228, 133, 125, 65, 107, 38, 113, 162, 22, 50, 203, 40, 130, 32, 103, 161, 11, 94, 56, 13,
        176, 215, 89, 185, 34, 18, 166, 189, 30, 253, 69, 145, 167, 209, 193, 32, 155, 90, 234, 179,
        32, 74, 80, 50, 176, 8, 19, 99, 83, 208, 202, 54, 4, 83, 132, 136, 97, 197, 42, 145, 165,
        33, 226, 151, 69, 121, 161, 81, 145, 103, 95, 28, 214, 35, 14, 234, 176, 56, 16, 135, 218,
        179, 86, 128, 37, 110, 96, 31, 159, 134, 244, 175, 125, 164, 238, 102, 29, 62, 154, 200, 30,
        49, 253, 112, 180, 8, 0, 134, 137, 120, 201, 121, 116, 167, 247, 58, 218, 237, 116, 130,
        232, 101, 134, 85, 200, 35, 69, 45, 182, 224, 61, 200, 133, 201, 223, 126, 145, 215, 175,
        135, 246, 57, 224, 168, 128, 18, 213, 119, 140, 251, 146, 167, 18, 244, 81, 253, 161, 148,
        183, 120, 202, 120, 1, 72, 57, 147, 154, 42, 46, 74, 4, 219, 153, 167, 146, 195, 25, 117,
        125, 51, 181, 236, 204, 235, 121, 130, 155, 142, 4, 51, 65, 188, 162, 71, 26, 117, 203, 83,
        215, 249, 118, 108, 137, 184, 156, 22, 212, 218, 206, 98, 68, 20, 29, 100, 136, 47, 87, 91,
        120, 158, 199, 97, 109, 252, 194, 144, 220, 212, 168, 234, 82, 233, 49, 199, 128, 244, 27,
        93, 77, 198, 104, 185, 225, 140, 214, 83, 83, 249, 191, 190, 234, 205, 221, 42, 254,
    ];

    assert(expected_encoded == encoded_data);
    // assert(decoded_data == test_data);
}

#[test]
fn test_encode_decode_eleven_bytes() {
    let secret = DecoderSecret {
        seed: [
            224, 23, 153, 74, 234, 98, 141, 150, 41, 48, 254, 129, 253, 246, 80, 97, 13, 206, 19,
            254, 252, 165, 221, 174, 203, 150, 63, 131, 76, 8, 18, 105,
        ],
        delta: [165, 18, 235, 99, 233, 112, 133, 193, 141, 147, 108, 17, 202, 200, 217, 197],
    };
    let direction = 1;
    let position = 229;
    let test_data = [34, 97, 109, 111, 117, 110, 116, 34, 58, 45, 50];
    let blinder = [232, 39, 246, 246, 229, 151, 200, 167, 108, 141, 180, 43, 108, 226, 219, 47];

    // Enkoduj dane
    let encoded_data = encode_data_generic_byte(secret, direction, position, test_data);

    // // Dekoduj z powrotem
    let decoded_data = decode_data_eleven_byte(secret, direction, position, encoded_data, 11);

    let expected = [
        77, 67, 168, 21, 208, 246, 155, 22, 28, 98, 39, 108, 85, 253, 27, 211, 64, 101, 78, 179,
        147, 140, 222, 63, 213, 30, 104, 6, 32, 78, 6, 37, 201, 89, 176, 57, 208, 30, 109, 197, 93,
        76, 232, 195, 118, 111, 160, 237, 82, 181, 208, 218, 246, 71, 19, 81, 8, 67, 142, 133, 255,
        53, 247, 214, 201, 77, 111, 77, 20, 81, 135, 134, 184, 217, 213, 35, 153, 110, 145, 158,
        146, 194, 15, 15, 88, 92, 53, 121, 140, 176, 33, 180, 178, 48, 105, 173, 23, 121, 156, 238,
        80, 254, 84, 2, 208, 248, 5, 37, 140, 164, 194, 28, 186, 211, 15, 89, 150, 106, 228, 222,
        112, 163, 75, 197, 2, 45, 164, 50, 168, 98, 4, 181, 6, 60, 80, 220, 104, 249, 75, 248, 79,
        179, 231, 100, 250, 193, 200, 5, 19, 244, 70, 203, 173, 202, 67, 27, 174, 208, 247, 245, 60,
        212, 8, 164, 205, 195, 79, 171, 182, 115, 101, 75, 2, 224, 167, 50, 53, 36, 59, 98, 117, 18,
        104, 213, 250, 120, 247, 151, 61, 192, 45, 191, 156, 4, 7, 164, 129, 53, 111, 138, 170, 217,
        122, 207, 89, 23, 125, 3, 136, 13, 125, 8, 226, 27, 131, 236, 173, 84, 230, 49, 121, 253,
        217, 152, 40, 13, 119, 180, 157, 241, 125, 126, 36, 211, 45, 17, 237, 81, 252, 71, 53, 41,
        254, 240, 208, 240, 246, 215, 109, 50, 175, 144, 252, 29, 129, 3, 77, 225, 34, 111, 118, 28,
        63, 141, 108, 214, 187, 207, 229, 157, 66, 9, 94, 123, 217, 195, 21, 10, 155, 190, 75, 57,
        37, 49, 156, 48, 134, 62, 7, 190, 155, 96, 227, 4, 65, 83, 121, 29, 122, 82, 158, 248, 42,
        196, 192, 126, 235, 84, 249, 62, 109, 191, 234, 53, 78, 235, 111, 206, 237, 109, 183, 136,
        41, 191, 255, 108, 51, 175, 72, 172, 251, 22, 174, 178, 24, 49, 57, 219, 4, 62, 232, 31,
        200, 139, 148, 132, 13, 220, 22, 95, 9, 118, 72, 14, 41, 52, 237, 254, 178, 3, 217, 103, 73,
        27, 128, 160, 202, 41, 154, 108, 123, 194, 68, 210, 21, 198, 199, 217, 113, 155, 42, 0, 166,
        227, 103, 247, 160, 153, 138, 242, 4, 45, 1, 251, 225, 59, 210, 162, 56, 198, 113, 117, 79,
        149, 85, 188, 82, 156, 46, 197, 250, 225, 112, 80, 155, 49, 23, 97, 197, 81, 182, 16, 125,
        240, 198, 25, 54, 73, 57, 43, 189, 166, 9, 51, 107, 191, 236, 153, 107, 103, 143, 202, 87,
        17, 46, 169, 207, 141, 235, 17, 24, 157, 200, 55, 8, 197, 131, 132, 242, 91, 193, 198, 94,
        223, 167, 95, 1, 236, 177, 187, 248, 7, 134, 135, 38, 124, 206, 102, 104, 79, 241, 76, 22,
        60, 168, 243, 159, 104, 248, 157, 126, 201, 236, 94, 7, 100, 205, 94, 17, 130, 51, 102, 33,
        131, 41, 188, 189, 12, 107, 2, 168, 250, 200, 28, 13, 161, 236, 12, 179, 20, 84, 217, 119,
        107, 228, 210, 8, 36, 164, 33, 21, 78, 149, 16, 104, 20, 55, 186, 145, 127, 178, 30, 235,
        21, 153, 10, 230, 94, 190, 122, 107, 207, 15, 47, 58, 158, 133, 52, 177, 46, 244, 157, 177,
        116, 46, 154, 137, 165, 112, 190, 34, 79, 154, 119, 152, 31, 34, 200, 54, 159, 151, 193, 71,
        40, 112, 207, 28, 87, 226, 47, 233, 104, 187, 158, 65, 250, 103, 146, 192, 211, 156, 209,
        166, 146, 93, 250, 227, 114, 241, 16, 49, 59, 83, 94, 166, 135, 61, 65, 100, 1, 1, 244, 13,
        255, 34, 226, 255, 102, 55, 74, 157, 104, 255, 102, 42, 161, 200, 121, 222, 9, 201, 68, 213,
        181, 58, 114, 246, 152, 202, 58, 84, 43, 62, 70, 240, 222, 14, 47, 86, 145, 49, 195, 230,
        105, 24, 21, 132, 52, 112, 159, 134, 0, 136, 136, 114, 131, 26, 62, 26, 107, 134, 202, 192,
        212, 211, 97, 213, 138, 29, 254, 222, 197, 239, 229, 140, 227, 158, 125, 91, 177, 130, 171,
        28, 176, 201, 157, 152, 146, 155, 30, 127, 6, 177, 242, 176, 190, 36, 7, 43, 31, 14, 137,
        144, 170, 118, 70, 50, 218, 235, 175, 45, 63, 194, 80, 175, 241, 70, 25, 199, 235, 15, 233,
        170, 143, 158, 0, 2, 216, 111, 11, 246, 53, 230, 67, 39, 88, 217, 201, 4, 254, 199, 181,
        162, 88, 2, 171, 9, 57, 221, 158, 139, 246, 50, 177, 205, 192, 104, 6, 120, 27, 218, 103,
        192, 131, 158, 118, 101, 62, 206, 199, 83, 106, 24, 198, 151, 142, 10, 207, 15, 10, 54, 68,
        126, 19, 33, 252, 94, 172, 112, 57, 60, 46, 138, 95, 125, 140, 187, 130, 1, 133, 195, 193,
        106, 15, 75, 68, 184, 28, 239, 243, 47, 11, 155, 120, 73, 252, 106, 226, 37, 75, 114, 91,
        58, 70, 82, 92, 59, 201, 90, 42, 216, 253, 67, 224, 216, 54, 128, 187, 49, 172, 201, 36,
        199, 255, 164, 50, 50, 71, 8, 227, 149, 3, 98, 44, 68, 249, 0, 176, 64, 154, 13, 178, 44,
        228, 43, 128, 112, 62, 202, 179, 99, 163, 123, 78, 234, 130, 19, 164, 253, 38, 212, 211,
        112, 173, 104, 51, 174, 141, 134, 15, 58, 102, 251, 107, 162, 44, 247, 135, 209, 34, 213,
        158, 217, 94, 149, 248, 127, 128, 34, 97, 128, 188, 126, 189, 123, 234, 8, 126, 112, 244,
        111, 46, 30, 84, 91, 220, 84, 111, 161, 134, 72, 252, 253, 154, 212, 202, 49, 20, 53, 154,
        172, 155, 1, 209, 124, 43, 86, 80, 88, 228, 1, 180, 122, 128, 210, 73, 194, 223, 51, 73,
        203, 183, 202, 168, 237, 32, 220, 22, 72, 183, 14, 130, 13, 144, 149, 222, 170, 79, 155, 94,
        254, 226, 112, 121, 157, 57, 210, 225, 100, 31, 108, 237, 232, 41, 15, 188, 151, 146, 74,
        21, 207, 176, 221, 178, 137, 207, 198, 215, 127, 50, 172, 117, 28, 216, 39, 231, 232, 195,
        50, 131, 220, 135, 54, 100, 153, 83, 169, 24, 16, 205, 231, 70, 165, 111, 117, 246, 35, 157,
        231, 47, 231, 109, 83, 33, 19, 247, 9, 50, 93, 30, 207, 139, 46, 144, 251, 143, 53, 193,
        248, 18, 231, 24, 154, 222, 101, 188, 126, 45, 158, 18, 186, 37, 253, 10, 240, 47, 238, 139,
        16, 229, 76, 6, 40, 90, 23, 89, 244, 143, 113, 220, 249, 231, 5, 186, 213, 206, 199, 85, 3,
        251, 19, 186, 179, 92, 81, 99, 142, 249, 147, 254, 178, 47, 249, 142, 45, 126, 59, 211, 162,
        12, 218, 9, 97, 166, 11, 200, 227, 133, 31, 180, 60, 187, 72, 225, 154, 184, 102, 194, 253,
        62, 116, 174, 57, 120, 209, 198, 190, 65, 104, 140, 190, 14, 146, 6, 247, 249, 123, 130,
        207, 166, 70, 110, 45, 196, 232, 136, 214, 190, 94, 108, 21, 114, 130, 90, 218, 4, 2, 59,
        145, 39, 198, 254, 90, 190, 226, 208, 167, 176, 197, 9, 194, 141, 22, 41, 158, 101, 101,
        153, 78, 221, 30, 122, 8, 29, 71, 2, 148, 178, 241, 219, 222, 241, 24, 75, 87, 225, 190,
        240, 155, 64, 63, 62, 21, 245, 17, 38, 48, 107, 148, 62, 238, 37, 77, 2, 76, 138, 205, 26,
        5, 255, 29, 26, 93, 211, 19, 91, 160, 121, 14, 230, 13, 68, 192, 244, 41, 44, 231, 211, 155,
        128, 51, 0, 70, 242, 166, 166, 85, 84, 180, 109, 244, 35, 244, 167, 97, 73, 230, 34, 167,
        146, 192, 104, 212, 224, 90, 108, 150, 13, 200, 79, 28, 165, 170, 235, 212, 230, 139, 96,
        102, 139, 103, 110, 41, 123, 226, 136, 151, 190, 4, 171, 68, 112, 75, 142, 53, 130, 234,
        195, 172, 105, 230, 186, 147, 137, 218, 88, 32, 83, 213, 121, 170, 104, 188, 229, 204, 9,
        50, 18, 213, 203, 151, 61, 204, 175, 40, 11, 130, 223, 21, 197, 101, 207, 19, 168, 117, 11,
        233, 135, 28, 174, 148, 133, 252, 211, 13, 51, 252, 191, 21, 85, 233, 125, 25, 116, 12, 180,
        91, 140, 13, 58, 245, 71, 9, 15, 143, 200, 222, 122,
    ];

    let expected_hash = [
        158, 205, 185, 207, 162, 58, 151, 252, 154, 136, 25, 227, 93, 34, 139, 110, 129, 92, 87,
        251, 47, 44, 198, 38, 138, 160, 22, 126, 167, 201, 151, 12,
    ];

    let encoded_with_blinder = add_sixteen_elements(encoded_data, blinder);
    let hash = blake3(encoded_with_blinder);

    assert(hash == expected_hash);

    // println(f"Encoded with blinder data: {encoded_with_blinder}");
    println(f"Hash: {hash}");
    // for i in 0..64 {
    //     assert(encoded_data[i] == expected_start[i]);
    // }
    // assert(decoded_data == test_data);
    // println(f"Encoded data size: {encoded_data} bytes");

    assert(encoded_data.len() == 1408);
    assert(encoded_data == expected);
}

// Function to create a new array with 16 additional elements from provided array
fn add_sixteen_elements<let INPUT_SIZE: u32>(
    input: [u8; INPUT_SIZE],
    additional_elements: [u8; 16],
) -> [u8; INPUT_SIZE + 16] {
    // Verify that OUTPUT_SIZE = INPUT_SIZE + 16

    let mut result = [0; INPUT_SIZE + 16];

    // Copy original data
    for i in 0..INPUT_SIZE {
        result[i] = input[i];
    }

    // Add the 16 additional elements at the end
    for i in 0..16 {
        result[INPUT_SIZE + i] = additional_elements[i];
    }

    result
}

// Generate zero-encoding for up to 11 bytes (1408 bytes output)
fn generate_zero_encoding_generic_byte<let INPUT_SIZE: u32>(
    secret: DecoderSecret,
    direction: u64,
    range_start: u32,
) -> [u8; INPUT_SIZE * 128] {
    let stream_id = direction;
    let word_pos = (range_start * 32) as u64;

    let mut result = [0; INPUT_SIZE * 128];

    let result_len = result.len() as u32;

    // Each byte needs 128 bytes of encoding, so 11 bytes need 1408 bytes
    // We need 22 ChaCha blocks (22 * 64 = 1408 bytes)
    let blocks_needed = (INPUT_SIZE * 128 + 63) / 64; // Round up to nearest block

    for block_idx in 0..INPUT_SIZE * 2 {
        // Max 22 blocks for 1408 bytes
        if block_idx < blocks_needed {
            let state =
                generate_chacha_state(secret.seed, stream_id, word_pos + (block_idx as u64 * 16));
            let output = chacha12_block(state);

            // Convert to bytes and store in result
            for i in 0..16 {
                let word = output[i];
                let base_idx = block_idx * 64 + i * 4;
                if base_idx < result_len {
                    result[base_idx] = (word & 0xff) as u8;
                    if base_idx + 1 < result_len {
                        result[base_idx + 1] = ((word >> 8) & 0xff) as u8;
                    }
                    if base_idx + 2 < result_len {
                        result[base_idx + 2] = ((word >> 16) & 0xff) as u8;
                    }
                    if base_idx + 3 < result_len {
                        result[base_idx + 3] = ((word >> 24) & 0xff) as u8;
                    }
                }
            }
        }
    }

    result
}
