fn chacha20_rotl(x: u32, n: u8) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn chacha20_qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = std::wrapping_add(a, b);
    d ^= a;
    d = chacha20_rotl(d, 16);
    
    c = std::wrapping_add(c, d);
    b ^= c;
    b = chacha20_rotl(b, 12);
    
    a = std::wrapping_add(a, b);
    d ^= a;
    d = chacha20_rotl(d, 8);
    
    c = std::wrapping_add(c, d);
    b ^= c;
    b = chacha20_rotl(b, 7);
    
    (a, b, c, d)
}

pub fn chacha12_block(input: [u32; 16]) -> [u32; 16] {
    let initial_state = input;
    let mut state = input;

    for _ in 0..6 {
        // Column rounds
        let (a, b, c, d) = chacha20_qr(state[0], state[4], state[8], state[12]);
        state[0] = a; state[4] = b; state[8] = c; state[12] = d;
        
        let (a, b, c, d) = chacha20_qr(state[1], state[5], state[9], state[13]);
        state[1] = a; state[5] = b; state[9] = c; state[13] = d;
        
        let (a, b, c, d) = chacha20_qr(state[2], state[6], state[10], state[14]);
        state[2] = a; state[6] = b; state[10] = c; state[14] = d;
        
        let (a, b, c, d) = chacha20_qr(state[3], state[7], state[11], state[15]);
        state[3] = a; state[7] = b; state[11] = c; state[15] = d;
        
        // Diagonal rounds  
        let (a, b, c, d) = chacha20_qr(state[0], state[5], state[10], state[15]);
        state[0] = a; state[5] = b; state[10] = c; state[15] = d;
        
        let (a, b, c, d) = chacha20_qr(state[1], state[6], state[11], state[12]);
        state[1] = a; state[6] = b; state[11] = c; state[12] = d;
        
        let (a, b, c, d) = chacha20_qr(state[2], state[7], state[8], state[13]);
        state[2] = a; state[7] = b; state[8] = c; state[13] = d;
        
        let (a, b, c, d) = chacha20_qr(state[3], state[4], state[9], state[14]);
        state[3] = a; state[4] = b; state[9] = c; state[14] = d;
    }

    // Add initial state
    for i in 0..16 {
        state[i] = std::wrapping_add(state[i], initial_state[i]);
    }

    state
}

pub fn chacha12(key: [u32; 8], nonce: [u32; 3], counter: u32, input: [u32; 16]) -> [u32; 16] {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3], key[4],
        key[5], key[6], key[7], nonce[0], nonce[1], nonce[2], counter,
    ];

    let mut output = chacha12_block(state);

    for i in 0..16 {
        output[i] = std::wrapping_add(output[i], input[i]);
    }
    output
}
