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

#[test]
fn test_chacha20_rotl() {
    let inp: u32 = 0x12345678;
    let out = chacha20_rotl(inp, 16);
    assert_eq(out, 0x56781234);
    let inp: u32 = 0x12345678;
    let out = chacha20_rotl(inp, 7);
    assert_eq(out, 0x1a2b3c09);
}

#[test]
fn test_chacha20_qr() {
    let state: [u32; 4] = [0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689];

    let expected: [u32; 4] = [0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79];

    let (a, b, c, d) = chacha20_qr(state[0], state[1], state[2], state[3]);
    assert_eq(a, expected[0]);
    assert_eq(b, expected[1]);
    assert_eq(c, expected[2]);
    assert_eq(d, expected[3]);
}

#[test]
fn test_chacha12_block() {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];

    let output = chacha12_block(state);

    assert(output[0] != 0);
    assert(output[1] != 0);
}
