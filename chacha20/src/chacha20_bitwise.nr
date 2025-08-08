fn chacha20_rotl16(input: [bool; 32]) -> [bool; 32] {
    [
        input[16], input[17], input[18], input[19], input[20], input[21], input[22], input[23],
        input[24], input[25], input[26], input[27], input[28], input[29], input[30], input[31],
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
        input[9], input[10], input[11], input[12], input[13], input[14], input[15],
    ]
}
fn chacha20_rotl12(input: [bool; 32]) -> [bool; 32] {
    [
        input[20], input[21], input[22], input[23], input[24], input[25], input[26], input[27],
        input[28], input[29], input[30], input[31], input[0], input[1], input[2], input[3],
        input[4], input[5], input[6], input[7], input[8], input[9], input[10], input[11], input[12],
        input[13], input[14], input[15], input[16], input[17], input[18], input[19],
    ]
}
fn chacha20_rotl8(input: [bool; 32]) -> [bool; 32] {
    [
        input[24], input[25], input[26], input[27], input[28], input[29], input[30], input[31],
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
        input[9], input[10], input[11], input[12], input[13], input[14], input[15], input[16],
        input[17], input[18], input[19], input[20], input[21], input[22], input[23],
    ]
}
fn chacha20_rotl7(input: [bool; 32]) -> [bool; 32] {
    [
        input[25], input[26], input[27], input[28], input[29], input[30], input[31], input[0],
        input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8], input[9],
        input[10], input[11], input[12], input[13], input[14], input[15], input[16], input[17],
        input[18], input[19], input[20], input[21], input[22], input[23], input[24],
    ]
}

fn chacha20_xor(mut input1: [bool; 32], input2: [bool; 32]) -> [bool; 32] {
    for i in 0..32 {
        input1[i] ^= input2[i];
    }
    input1
}

fn chacha20_add(input1: [bool; 32], input2: [bool; 32]) -> [bool; 32] {
    let mut output = [false; 32];

    output[0] = input1[0] ^ input2[0];
    let mut c = input1[0] & input2[0];

    for i in 1..31 {
        let t = input1[i] ^ input2[i];
        let s = input1[i] & input2[i];
        output[i] = t ^ c;
        c = s | (t & c);
    }

    output[31] = input1[31] ^ input2[31] ^ c;

    output
}

fn chacha20_qr(a: [bool; 32], b: [bool; 32], c: [bool; 32], d: [bool; 32]) -> [[bool; 32]; 4] {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;

    a = chacha20_add(a, b);
    d = chacha20_rotl16(chacha20_xor(d, a));
    c = chacha20_add(c, d);
    b = chacha20_rotl12(chacha20_xor(b, c));
    a = chacha20_add(a, b);
    d = chacha20_rotl8(chacha20_xor(d, a));
    c = chacha20_add(c, d);
    b = chacha20_rotl7(chacha20_xor(b, c));

    [a, b, c, d]
}

pub fn chacha12_block(input: [[bool; 32]; 16]) -> [[bool; 32]; 16] {
    let mut state = input;

    // 6 "double rounds"
    for _ in 0..6 {
        let res = chacha20_qr(state[0], state[4], state[8], state[12]); // Column 0
        state[0] = res[0];
        state[4] = res[1];
        state[8] = res[2];
        state[12] = res[3];
        let res = chacha20_qr(state[1], state[5], state[9], state[13]); // Column 1
        state[1] = res[0];
        state[5] = res[1];
        state[9] = res[2];
        state[13] = res[3];
        let res = chacha20_qr(state[2], state[6], state[10], state[14]); // Column 2
        state[2] = res[0];
        state[6] = res[1];
        state[10] = res[2];
        state[14] = res[3];
        let res = chacha20_qr(state[3], state[7], state[11], state[15]); // Column 3
        state[3] = res[0];
        state[7] = res[1];
        state[11] = res[2];
        state[15] = res[3];
        let res = chacha20_qr(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
        state[0] = res[0];
        state[5] = res[1];
        state[10] = res[2];
        state[15] = res[3];
        let res = chacha20_qr(state[1], state[6], state[11], state[12]); // Diagonal 2
        state[1] = res[0];
        state[6] = res[1];
        state[11] = res[2];
        state[12] = res[3];
        let res = chacha20_qr(state[2], state[7], state[8], state[13]); // Diagonal 3
        state[2] = res[0];
        state[7] = res[1];
        state[8] = res[2];
        state[13] = res[3];
        let res = chacha20_qr(state[3], state[4], state[9], state[14]); // Diagonal 4
        state[3] = res[0];
        state[4] = res[1];
        state[9] = res[2];
        state[14] = res[3];
    }

    for i in 0..16 {
        state[i] = chacha20_add(input[i], state[i]);
    }

    state
}

pub fn chacha12(
    key: [[bool; 32]; 8],
    nonce: [[bool; 32]; 3],
    counter: [bool; 32],
    input: [[bool; 32]; 16],
) -> [[bool; 32]; 16] {
    let mut state = [
        [
            true, false, true, false, false, true, true, false, false, false, false, true, true,
            true, true, false, false, false, false, false, true, true, true, false, true, false,
            false, false, false, true, true, false,
        ],
        [
            false, true, true, true, false, true, true, false, false, false, true, false, false,
            true, true, false, false, false, false, false, false, true, false, false, true, true,
            false, false, true, true, false, false,
        ],
        [
            false, true, false, false, true, true, false, false, true, false, true, true, false,
            true, false, false, false, true, false, false, false, true, true, false, true, false,
            false, true, true, true, true, false,
        ],
        [
            false, false, true, false, true, true, true, false, true, false, true, false, false,
            true, true, false, false, false, false, false, false, true, false, false, true, true,
            false, true, false, true, true, false,
        ],
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        nonce[0],
        nonce[1],
        nonce[2],
        counter,
    ];

    let mut output = chacha12_block(state);
    for i in 0..16 {
        for j in 0..32 {
            output[i][j] ^= input[i][j];
        }
    }

    output
}

#[test]
fn test_chacha20_qr() {
    // let state: [u32; 4] = [0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689];

    let state_bin: [[bool; 32]; 4] = [
        [
            true, false, false, false, true, true, false, true, true, false, false, false, false,
            true, true, false, false, false, true, false, false, true, true, false, true, false,
            false, false, true, false, true, false,
        ],
        [
            false, false, true, true, false, false, true, false, true, false, false, false, true,
            true, true, false, true, true, true, true, true, false, true, false, false, true, false,
            true, false, true, false, false,
        ],
        [
            true, true, true, false, false, true, true, false, true, true, true, false, false, true,
            false, false, true, true, true, false, true, true, false, false, true, true, false,
            false, true, false, true, false,
        ],
        [
            true, false, false, true, false, false, false, true, false, true, true, false, true,
            false, false, false, true, true, false, false, false, true, true, false, true, false,
            true, true, true, true, false, false,
        ],
    ];

    // let expected: [u32; 4] = [0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79];
    let expected_bin: [[bool; 32]; 4] = [
        [
            false, false, true, true, true, false, true, true, false, true, true, false, false,
            false, false, true, false, false, false, true, true, true, false, true, true, false,
            true, true, true, true, false, true,
        ],
        [
            false, true, false, false, true, false, true, true, true, true, true, true, false, true,
            false, true, false, false, true, true, false, true, false, true, true, true, true, true,
            false, false, true, true,
        ],
        [
            false, false, false, false, false, false, false, true, false, true, false, true, false,
            true, true, true, true, true, false, true, false, true, true, false, false, false, true,
            false, false, true, true, true,
        ],
        [
            true, false, false, true, true, true, true, false, false, false, true, true, true, true,
            true, false, false, false, false, false, false, false, true, true, false, false, true,
            true, false, false, true, true,
        ],
    ];

    let res = chacha20_qr(state_bin[0], state_bin[1], state_bin[2], state_bin[3]);

    for i in 0..4 {
        assert_eq(res[i], expected_bin[i]);
    }
}

#[test]
fn test_chacha12_block() {
    let state = [
        [
            true, false, true, false, false, true, true, false, false, false, false, true, true,
            true, true, false, false, false, false, false, true, true, true, false, true, false,
            false, false, false, true, true, false,
        ],
        [
            false, true, true, true, false, true, true, false, false, false, true, false, false,
            true, true, false, false, false, false, false, false, true, false, false, true, true,
            false, false, true, true, false, false,
        ],
        [
            false, true, false, false, true, true, false, false, true, false, true, true, false,
            true, false, false, false, true, false, false, false, true, true, false, true, false,
            false, true, true, true, true, false,
        ],
        [
            false, false, true, false, true, true, true, false, true, false, true, false, false,
            true, true, false, false, false, false, false, false, true, false, false, true, true,
            false, true, false, true, true, false,
        ],
        [
            false, false, false, false, false, false, false, false, true, false, false, false,
            false, false, false, false, false, true, false, false, false, false, false, false, true,
            true, false, false, false, false, false, false,
        ],
        [
            false, false, true, false, false, false, false, false, true, false, true, false, false,
            false, false, false, false, true, true, false, false, false, false, false, true, true,
            true, false, false, false, false, false,
        ],
        [
            false, false, false, true, false, false, false, false, true, false, false, true, false,
            false, false, false, false, true, false, true, false, false, false, false, true, true,
            false, true, false, false, false, false,
        ],
        [
            false, false, true, true, false, false, false, false, true, false, true, true, false,
            false, false, false, false, true, true, true, false, false, false, false, true, true,
            true, true, false, false, false, false,
        ],
        [
            false, false, false, false, true, false, false, false, true, false, false, false, true,
            false, false, false, false, true, false, false, true, false, false, false, true, true,
            false, false, true, false, false, false,
        ],
        [
            false, false, true, false, true, false, false, false, true, false, true, false, true,
            false, false, false, false, true, true, false, true, false, false, false, true, true,
            true, false, true, false, false, false,
        ],
        [
            false, false, false, true, true, false, false, false, true, false, false, true, true,
            false, false, false, false, true, false, true, true, false, false, false, true, true,
            false, true, true, false, false, false,
        ],
        [
            false, false, true, true, true, false, false, false, true, false, true, true, true,
            false, false, false, false, true, true, true, true, false, false, false, true, true,
            true, true, true, false, false, false,
        ],
        [
            true, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
        ],
        [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            true, false, false, true, false, false, false, false,
        ],
        [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, true, false, true, false, false, true, false,
        ],
        [
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
        ],
    ];
    let out = chacha12_block(state);

    assert(out[0][0]);
}
