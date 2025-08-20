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

pub fn add_sixteen_elements<let INPUT_SIZE: u32>(
    input: [u8; INPUT_SIZE],
    additional_elements: [u8; 16],
) -> [u8; INPUT_SIZE + 16] {
    let mut result = [0; INPUT_SIZE + 16];

    for i in 0..INPUT_SIZE {
        result[i] = input[i];
    }

    for i in 0..16 {
        result[INPUT_SIZE + i] = additional_elements[i];
    }

    result
}

fn generate_chacha_block_at_position(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
    block_idx: u32,
) -> [u8; 64] {
    let stream_id = direction as u64;
    let word_pos = (range_start * 32) as u64;
    
    let state = generate_chacha_state(secret.seed, stream_id, word_pos + (block_idx as u64 * 16));
    let output = chacha12_block(state);
    
    let mut result = [0u8; 64];
    for i in 0..16 {
        let word = output[i];
        let base_idx = i * 4;
        result[base_idx] = (word & 0xff) as u8;
        result[base_idx + 1] = ((word >> 8) & 0xff) as u8;
        result[base_idx + 2] = ((word >> 16) & 0xff) as u8;
        result[base_idx + 3] = ((word >> 24) & 0xff) as u8;
    }
    
    result
}

fn get_keystream_bytes_for_bit(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
    byte_idx: u32,
    bit_idx: u32,
) -> [u8; 16] {
    let global_bit_pos = byte_idx * 8 + bit_idx;
    let keystream_start = global_bit_pos * BIT_ENCODING_SIZE;
    
    let block_idx = keystream_start / 64;
    let block_offset = keystream_start % 64;
    
    let mut result = [0u8; 16];
    
    if block_offset + BIT_ENCODING_SIZE <= 64 {
        let block = generate_chacha_block_at_position(secret, direction, range_start, block_idx);
        for i in 0..BIT_ENCODING_SIZE {
            result[i] = block[block_offset + i];
        }
    } else {
        let first_block = generate_chacha_block_at_position(secret, direction, range_start, block_idx);
        let second_block = generate_chacha_block_at_position(secret, direction, range_start, block_idx + 1);
        
        let first_part_size = 64 - block_offset;
        for i in 0..first_part_size {
            result[i] = first_block[block_offset + i];
        }
        for i in 0..(BIT_ENCODING_SIZE - first_part_size) {
            result[first_part_size + i] = second_block[i];
        }
    }
    
    result
}

pub fn encode_data_generic_byte<let INPUT_SIZE: u32>(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
    data: [u8; INPUT_SIZE],
) -> [u8; INPUT_SIZE * 128] {
    let mut encoded_data = [0u8; INPUT_SIZE * 128];
    
    for byte_idx in 0..INPUT_SIZE {
        let byte_value = data[byte_idx];
        let encoding_offset = byte_idx * 128;
        
        for bit_idx in 0..8 {
            let bit = (byte_value >> bit_idx) & 1;
            let bit_start = encoding_offset + (bit_idx as u32) * BIT_ENCODING_SIZE;
            
            let keystream = get_keystream_bytes_for_bit(secret, direction, range_start, byte_idx, bit_idx as u32);
            
            for i in 0..BIT_ENCODING_SIZE {
                let keystream_byte = keystream[i];
                encoded_data[bit_start + i] = if bit == 1 {
                    keystream_byte ^ secret.delta[i]
                } else {
                    keystream_byte
                };
            }
        }
    }
    
    encoded_data
}

pub fn encode_data_memory_optimized<let INPUT_SIZE: u32>(
    secret: EncoderSecret,
    direction: u8,
    range_start: u32,
    data: [u8; INPUT_SIZE],
) -> [u8; INPUT_SIZE * 128] {
    let mut encoded_data = [0u8; INPUT_SIZE * 128];
    let mut current_block = [0u8; 64];
    let mut current_block_idx = 0xffffffff;
    
    for byte_idx in 0..INPUT_SIZE {
        let byte_value = data[byte_idx];
        let encoding_offset = byte_idx * 128;
        
        for bit_idx in 0..8 {
            let bit = (byte_value >> bit_idx) & 1;
            let bit_start = encoding_offset + (bit_idx as u32) * BIT_ENCODING_SIZE;
            
            let global_bit_pos = byte_idx * 8 + bit_idx as u32;
            let keystream_start = global_bit_pos * BIT_ENCODING_SIZE;
            let block_idx = keystream_start / 64;
            let block_offset = keystream_start % 64;
            
            if block_idx != current_block_idx {
                current_block = generate_chacha_block_at_position(secret, direction, range_start, block_idx);
                current_block_idx = block_idx;
            }
            
            for i in 0..BIT_ENCODING_SIZE {
                let keystream_byte = if block_offset + i < 64 {
                    current_block[block_offset + i]
                } else {
                    let next_block = generate_chacha_block_at_position(secret, direction, range_start, block_idx + 1);
                    next_block[(block_offset + i) - 64]
                };
                
                encoded_data[bit_start + i] = if bit == 1 {
                    keystream_byte ^ secret.delta[i]
                } else {
                    keystream_byte
                };
            }
        }
    }
    
    encoded_data
}