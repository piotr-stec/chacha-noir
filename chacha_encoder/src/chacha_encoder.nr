use dep::chacha20::chacha12_block;

global BIT_ENCODING_SIZE: u32 = 16;

pub struct EncoderSecret {
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


// Function to create a new array with 16 additional elements from provided array
pub fn add_sixteen_elements<let INPUT_SIZE: u32>(
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

fn generate_zero_encoding_generic_byte<let INPUT_SIZE: u32>(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
) -> [u8; INPUT_SIZE * 128] {
    let stream_id = direction as u64;
    let word_pos = (range_start * 32) as u64;

    let mut result = [0; INPUT_SIZE * 128];

    let result_len = result.len() as u32;

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

// Encode up to 11 bytes
pub fn encode_data_generic_byte<let INPUT_SIZE: u32>(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
    data: [u8; INPUT_SIZE],
) -> [u8; INPUT_SIZE * 128] {
    let mut encoded_data =
        generate_zero_encoding_generic_byte::<INPUT_SIZE>(secret, direction, range_start);

    // Apply delta for each bit that is 1 in each byte
    for byte_idx in 0..INPUT_SIZE {
        if byte_idx < INPUT_SIZE {
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

