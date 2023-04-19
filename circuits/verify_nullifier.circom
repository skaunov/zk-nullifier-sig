pragma circom 2.1.2;

include "./node_modules/circom-ecdsa/circuits/ecdsa.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1.circom";
include "./node_modules/circom-ecdsa/circuits/secp256k1_func.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/hash_to_curve.circom";
include "./node_modules/secp256k1_hash_to_curve_circom/circom/Sha256.circom";
include "./node_modules/circomlib/circuits/bitify.circom";

// Verifies that a nullifier belongs to a specific public key
// This blog explains the intuition behind the construction https://blog.aayushg.com/posts/nullifier
template verify_nullifier(n, k, msg_length) {
    signal input c[k];
    signal input s[k];
    signal input msg[msg_length];
    signal input public_key[2][k];
    signal input nullifier[2][k];

    signal output g_pow_r[2][k];
    signal output h_pow_r[2][k];

    // precomputed values for the hash_to_curve component
    signal input q0_gx1_sqrt[4];
    signal input q0_gx2_sqrt[4];
    signal input q0_y_pos[4];
    signal input q0_x_mapped[4];
    signal input q0_y_mapped[4];

    signal input q1_gx1_sqrt[4];
    signal input q1_gx2_sqrt[4];
    signal input q1_y_pos[4];
    signal input q1_x_mapped[4];
    signal input q1_y_mapped[4];

    // precomputed value for the sha256 component. TODO: calculate internally in circom to simplify API
    signal input sha256_preimage_bit_length;

    // calculate g^r
    // g^r = g^s / pk^c (where g is the generator)
    // Note this implicitly checks the first equation in the blog

    // Calculates g^s. Note, turning a private key to a public key is the same operation as
    // raising the generator g to some power, and we are *not* dealing with private keys in this circuit.
    component g_pow_s = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        g_pow_s.privkey[i] <== s[i];
    }

    component g_pow_r_comp = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        g_pow_r_comp.a[0][i] <== g_pow_s.pubkey[0][i];
        g_pow_r_comp.a[1][i] <== g_pow_s.pubkey[1][i];
        g_pow_r_comp.b[0][i] <== public_key[0][i];
        g_pow_r_comp.b[1][i] <== public_key[1][i];
        g_pow_r_comp.c[i] <== c[i];
    }

    // Calculate hash[m, pk]^r
    // hash[m, pk]^r = hash[m, pk]^s / (hash[m, pk]^sk)^c
    // Note this implicitly checks the second equation in the blog

    // Calculate hash[m, pk]^r
    component h = HashToCurve(msg_length + 33);
    for (var i = 0; i < msg_length; i++) {
        h.msg[i] <== msg[i];
    }

    component pk_compressor = compress_ec_point(n, k);
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            pk_compressor.uncompressed[i][j] <== public_key[i][j];
        }
    }

    for (var i = 0; i < 33; i++) {
        h.msg[msg_length + i] <== pk_compressor.compressed[i];
    }

    // Input precalculated values into HashToCurve
    for (var i = 0; i < k; i++) {
        h.q0_gx1_sqrt[i] <== q0_gx1_sqrt[i];
        h.q0_gx2_sqrt[i] <== q0_gx2_sqrt[i];
        h.q0_y_pos[i] <== q0_y_pos[i];
        h.q0_x_mapped[i] <== q0_x_mapped[i];
        h.q0_y_mapped[i] <== q0_y_mapped[i];
        h.q1_gx1_sqrt[i] <== q1_gx1_sqrt[i];
        h.q1_gx2_sqrt[i] <== q1_gx2_sqrt[i];
        h.q1_y_pos[i] <== q1_y_pos[i];
        h.q1_x_mapped[i] <== q1_x_mapped[i];
        h.q1_y_mapped[i] <== q1_y_mapped[i];
    }

    component h_pow_s = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        h_pow_s.scalar[i] <== s[i];
        h_pow_s.point[0][i] <== h.out[0][i];
        h_pow_s.point[1][i] <== h.out[1][i];
    }

    component h_pow_r_comp = a_div_b_pow_c(n, k);
    for (var i = 0; i < k; i++) {
        h_pow_r_comp.a[0][i] <== h_pow_s.out[0][i];
        h_pow_r_comp.a[1][i] <== h_pow_s.out[1][i];
        h_pow_r_comp.b[0][i] <== nullifier[0][i];
        h_pow_r_comp.b[1][i] <== nullifier[1][i];
        h_pow_r_comp.c[i] <== c[i];
    }

    for (var i = 0; i < k; i++) {
        h_pow_r[0][i] <== h_pow_r_comp.out[0][i];
        h_pow_r[1][i] <== h_pow_r_comp.out[1][i];
        g_pow_r[0][i] <== g_pow_r_comp.out[0][i];
        g_pow_r[1][i] <== g_pow_r_comp.out[1][i];
    }

    // calculate c as sha256(g, pk, h, nullifier, g^r, h^r)
    component c_sha256 = sha256_12_coordinates(n, k);
    var g[2][100];
    g[0] = get_genx(n, k);
    g[1] = get_geny(n, k);
    c_sha256.preimage_bit_length <== sha256_preimage_bit_length;
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            c_sha256.coordinates[i][j] <== g[i][j];
            c_sha256.coordinates[2+i][j] <== public_key[i][j];
            c_sha256.coordinates[4+i][j] <== h.out[i][j];
            c_sha256.coordinates[6+i][j] <== nullifier[i][j];
            c_sha256.coordinates[8+i][j] <== g_pow_r.out[i][j];
            c_sha256.coordinates[10+i][j] <== h_pow_r.out[i][j];
        }
    }

    // check that the input c is the same as the hash value c
    component c_bits[k];
    for (var i = 0; i < k; i++) {
        c_bits[i] = Num2Bits(n);
        c_bits[i].in <== c[i];
    }

    for (var i = 0; i < k; i++) {
        for (var j = 0; j < n; j++) {
            // We may have 3 registers of 86 bits, which means we end up getting two extra 0 bits which don't have to be equal to the sha256 hash
            // TODO: verify that we don't have to equate these to 0
            if (i*k + j < 256) {
                c_sha256.out[i*n + j] === c_bits[k-1-i].out[n-1-j]; // The sha256 output is little endian, whereas the c_bits is big endian (both at the register and bit level)
            }
        }
    }
}

template a_div_b_pow_c(n, k) {
    signal input a[2][k];
    signal input b[2][k];
    signal input c[k];
    signal output out[2][k];

    // Calculates b^c. Note that the spec uses multiplicative notation to preserve intuitions about
    // discrete log, and these comments follow the spec to make comparison simpler. But the circom-ecdsa library uses
    // additive notation. This is why we appear to calculate an expnentiation using a multiplication component.
    component b_pow_c = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        b_pow_c.scalar[i] <== c[i];
        b_pow_c.point[0][i] <== b[0][i];
        b_pow_c.point[1][i] <== b[1][i];
    }

    // Calculates inverse of b^c by finding the modular inverse of its y coordinate
    var prime[100] = get_secp256k1_prime(n, k);
    component b_pow_c_inv_y = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        b_pow_c_inv_y.a[i] <== prime[i];
        b_pow_c_inv_y.b[i] <== b_pow_c.out[1][i];
    }
    b_pow_c_inv_y.underflow === 0;

    // Calculates a^s * (b^c)-1
    component final_result = Secp256k1AddUnequal(n, k);
    for (var i = 0; i < k; i++) {
        final_result.a[0][i] <== a[0][i];
        final_result.a[1][i] <== a[1][i];
        final_result.b[0][i] <== b_pow_c.out[0][i];
        final_result.b[1][i] <== b_pow_c_inv_y.out[i];
    }

    for (var i = 0; i < k; i++) {
        out[0][i] <== final_result.out[0][i];
        out[1][i] <== final_result.out[1][i];
    }
}

template sha256_12_coordinates(n, k) {
    signal input coordinates[12][k];
    signal input preimage_bit_length;
    signal output out[256];

    // compress coordinates
    component compressors[6];
    for (var i = 0; i < 6; i++) {
        compressors[i] = compress_ec_point(n, k);
        for (var j = 0; j < k; j++) {
            compressors[i].uncompressed[0][j] <== coordinates[2*i][j];
            compressors[i].uncompressed[1][j] <== coordinates[2*i + 1][j];
        }
    }

    // decompose coordinates inputs into binary
    component binary[6*33];
    for (var i = 0; i < 6; i++) { // for each compressor
        for (var j = 0; j < 33; j++) { // for each byte
            binary[33*i + j] = Num2Bits(8);
            binary[33*i + j].in <== compressors[i].compressed[j];
        }
    }

    var message_bits = 6*33*8; // 6 compressed coordinates of 33 bytes
    var total_bits = (message_bits \ 512) * 512;
    if (message_bits % 512 != 0) {
        total_bits += 512;
    }

    component sha256 = Sha256Hash(total_bits);
    for (var i = 0; i < 6*33; i++) {
        for (var j = 0; j < 8; j++) {
            sha256.msg[8*i + 7 - j] <== binary[i].out[j]; // Num2Bits is little endian, but compressed EC key form is big endian
        }
    }

    for (var i = message_bits; i < total_bits; i++) {
        sha256.msg[i] <== 0;
    }

    // Message is padded with 1, a series of 0s, then the bit length of the message https://en.wikipedia.org/wiki/SHA-2#Pseudocode:~:text=append%20a%20single%20%271%27%20bit
    // TODO: move padding calculating into upstream repo to simplify API
    for (var i = 0; i < total_bits - 64; i++) {
        if (i == 1584) {
            sha256.padded_bits[1584] <== 1;
        } else {
            sha256.padded_bits[i] <== sha256.msg[i];
        }
    }

    component bit_length_binary = Num2Bits(64);
    bit_length_binary.in <== preimage_bit_length;
    for (var i = 0; i < 64; i++) {
        sha256.padded_bits[total_bits - i - 1] <== bit_length_binary.out[i];
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha256.out[i];
    }
}

// We use elliptic curve points in uncompressed form to do elliptic curve arithmetic, but we use them in compressed form when
// hashing to save constraints (as hash cost is generally parameterised in the input length).
// Elliptic curves are symmteric about the x-axis, and for every possible x coordinate there are exactly
// 2 possible y coordinates. Over a prime field, one of those points is even and the other is odd.
// The convention is to represent the even point with the byte 02, and the odd point with the byte 03.
// Because our hash functions work over bytes, our output is a 33 byte array.
template compress_ec_point(n, k) {
    assert(n == 64 && k == 4);
    signal input uncompressed[2][k];
    signal output compressed[33];

    compressed[0] <-- uncompressed[1][0] % 2 + 2;
    var bytes_per_register = 32/k;
    for (var i = 0; i < 32; i++) {
        compressed[32-i] <-- uncompressed[0][i \ bytes_per_register] \ (256 ** (i % bytes_per_register)) % 256;
    }

    component verify = verify_ec_compression(n, k);
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < k; j++) {
            verify.uncompressed[i][j] <== uncompressed[i][j];
        }
    }
    for (var i = 0; i < 33; i++) {
        verify.compressed[i] <== compressed[i];
    }
}

// We have a separate internal compression verification template for testing purposes. An adversarial prover
// can set any compressed values, so it's useful to be able to test adversarial inputs.
template verify_ec_compression(n, k) {
    signal input uncompressed[2][k];
    signal input compressed[33];

    // Get the bit string of the smallest register
    // Make sure the least significant bit's evenness matches the evenness specified by the first byte in the compressed version
    component num2bits = Num2Bits(n);
    num2bits.in <== uncompressed[1][0]; // Note, circom-ecdsa uses little endian, so we check the 0th register of the y value
    compressed[0] === num2bits.out[0] + 2;

    // Make sure the compressed and uncompressed x coordinates represent the same number
    // l_bytes is an algebraic expression for the bytes of each register
    var l_bytes[k];
    for (var i = 1; i < 33; i++) {
        var j = i - 1; // ignores the first byte specifying the compressed y coordinate
        l_bytes[j \ 8] += compressed[33-i] * (256 ** (j % 8));
    }

    for (var i = 0; i < k; i++) {
        uncompressed[0][i] === l_bytes[i];
    }
}
