fn chacha20_rotl16(input: [Field; 32]) -> [Field; 32] {
    [
        input[16], input[17], input[18], input[19], input[20], input[21], input[22], input[23],
        input[24], input[25], input[26], input[27], input[28], input[29], input[30], input[31],
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
        input[9], input[10], input[11], input[12], input[13], input[14], input[15],
    ]
}
fn chacha20_rotl12(input: [Field; 32]) -> [Field; 32] {
    [
        input[20], input[21], input[22], input[23], input[24], input[25], input[26], input[27],
        input[28], input[29], input[30], input[31], input[0], input[1], input[2], input[3],
        input[4], input[5], input[6], input[7], input[8], input[9], input[10], input[11], input[12],
        input[13], input[14], input[15], input[16], input[17], input[18], input[19],
    ]
}
fn chacha20_rotl8(input: [Field; 32]) -> [Field; 32] {
    [
        input[24], input[25], input[26], input[27], input[28], input[29], input[30], input[31],
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
        input[9], input[10], input[11], input[12], input[13], input[14], input[15], input[16],
        input[17], input[18], input[19], input[20], input[21], input[22], input[23],
    ]
}
fn chacha20_rotl7(input: [Field; 32]) -> [Field; 32] {
    [
        input[25], input[26], input[27], input[28], input[29], input[30], input[31], input[0],
        input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8], input[9],
        input[10], input[11], input[12], input[13], input[14], input[15], input[16], input[17],
        input[18], input[19], input[20], input[21], input[22], input[23], input[24],
    ]
}

fn chacha20_xor(mut input1: [Field; 32], input2: [Field; 32]) -> [Field; 32] {
    for i in 0..32 {
        input1[i] = input1[i] + input2[i] - 2 * input1[i] * input2[i];
    }
    input1
}

fn chacha20_add(input1: [Field; 32], input2: [Field; 32]) -> [Field; 32] {
    let mut output = [0; 32];

    let mut c = 0;

    let mut c = input1[0] * input2[0];
    output[0] = input1[0] + input2[0] - 2 * c;

    for i in 1..31 {
        let mul = input1[i] * input2[i];
        let t = input1[i] + input2[i] - 2 * mul;
        let s = mul;
        let mul = t * c;
        output[i] = t + c - 2 * mul;
        c = 1 - ((1 - s) * (1 - mul));
    }

    let mul = input1[31] * input2[31];
    let t = input1[31] + input2[31] - 2 * mul;
    let mul = t * c;
    output[31] = t + c - 2 * mul;

    output
}

fn chacha20_qr(a: [Field; 32], b: [Field; 32], c: [Field; 32], d: [Field; 32]) -> [[Field; 32]; 4] {
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

pub fn chacha20_block(input: [[Field; 32]; 16]) -> [[Field; 32]; 16] {
    let mut state = input;

    // 10 "double rounds"
    for _ in 0..10 {
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

fn range_check_state(state: [[Field; 32]; 16]) {
    for i in 4..16 {
        for j in 0..32 {
            state[i][j].assert_max_bit_size::<1>();
        }
    }
}

pub fn chacha20(
    key: [[Field; 32]; 8],
    nonce: [[Field; 32]; 3],
    counter: [Field; 32],
    input: [[Field; 32]; 16],
) -> [[Field; 32]; 16] {
    let mut state = [
        [
            1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0,
            1, 1, 0,
        ],
        [
            0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1,
            1, 0, 0,
        ],
        [
            0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1,
            1, 1, 0,
        ],
        [
            0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0,
            1, 1, 0,
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
    range_check_state(state);

    let mut output = chacha20_block(state);
    for i in 0..16 {
        output[i] = chacha20_xor(output[i], input[i]);
    }

    output
}

#[test]
fn test_chacha20_qr() {
    // let state: [u32; 4] = [0x516461b1, 0x2a5f714c, 0x53372767, 0x3d631689];

    let state_bin: [[Field; 32]; 4] = [
        [
            1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            0, 1, 0,
        ],
        [
            0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0,
            1, 0, 0,
        ],
        [
            1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1,
            0, 1, 0,
        ],
        [
            1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1,
            1, 0, 0,
        ],
    ];

    // let expected: [u32; 4] = [0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79];
    let expected_bin: [[Field; 32]; 4] = [
        [
            0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
            1, 0, 1,
        ],
        [
            0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0,
            0, 1, 1,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0,
            1, 1, 1,
        ],
        [
            1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0,
            0, 1, 1,
        ],
    ];

    let res = chacha20_qr(state_bin[0], state_bin[1], state_bin[2], state_bin[3]);

    for i in 0..4 {
        assert_eq(res[i], expected_bin[i]);
    }
}

#[test]
fn test_chacha20_block() {
    let state = [
        [
            1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0,
            1, 1, 0,
        ],
        [
            0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1,
            1, 0, 0,
        ],
        [
            0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1,
            1, 1, 0,
        ],
        [
            0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0,
            1, 1, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 0,
        ],
        [
            0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1,
            0, 0, 0,
        ],
        [
            0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1,
            0, 0, 0,
        ],
        [
            0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1,
            0, 0, 0,
        ],
        [
            0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1,
            0, 0, 0,
        ],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,
            0, 1, 0,
        ],
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    ];
    let out = chacha20_block(state);

    let expected = [
        [
            0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0,
            1, 1, 1,
        ],
        [
            1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
            0, 0, 0,
        ],
        [
            0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
            0, 0, 0,
        ],
        [
            1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0,
            0, 1, 1,
        ],
        [
            1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0,
            0, 1, 1,
        ],
        [
            1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0,
            0, 0, 0,
        ],
        [
            0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1,
            0, 0, 1,
        ],
        [
            1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0,
            0, 1, 0,
        ],
        [
            0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0,
            0, 1, 0,
        ],
        [
            1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0,
            0, 0, 0,
        ],
        [
            0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0,
            0, 0, 0,
        ],
        [
            1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            1, 0, 1,
        ],
        [
            1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1,
            0, 1, 1,
        ],
        [
            0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1,
            1, 0, 1,
        ],
        [
            1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0,
            1, 1, 1,
        ],
        [
            0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0,
            0, 1, 0,
        ],
    ];

    for i in 0..16 {
        assert_eq(out[i], expected[i]);
    }
}
