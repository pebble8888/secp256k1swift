//
//  testrand_impl.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/04.
//  Copyright © 2018年 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation
@testable import secp256k1

var secp256k1_test_rng = secp256k1_rfc6979_hmac_sha256_t()
var secp256k1_test_rng_precomputed = [UInt32](repeating: 0, count: 8)
var secp256k1_test_rng_precomputed_used: Int = 8;
var secp256k1_test_rng_integer:UInt64 = 0
var secp256k1_test_rng_integer_bits_left: Int = 0;

func secp256k1_rand_seed(_ seed16: [UInt8]) {
    secp256k1_rfc6979_hmac_sha256_initialize(&secp256k1_test_rng, seed16, 16);
}

func secp256k1_rand32() -> UInt32 {
    if (secp256k1_test_rng_precomputed_used == 8) {
        var v = [UInt8](repeating: 0, count: 256)
        secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, &v, outlen: UInt(v.count));
        secp256k1_test_rng_precomputed = v.toLEUInt32()!
        secp256k1_test_rng_precomputed_used = 0;
    }
    let ret = secp256k1_test_rng_precomputed[secp256k1_test_rng_precomputed_used];
    secp256k1_test_rng_precomputed_used += 1
    return ret
}

// ex: random value from 00000 to 11111 for bits = 5
func secp256k1_rand_bits(_ bits: Int) -> UInt32 {
    var ret: UInt32
    if (secp256k1_test_rng_integer_bits_left < bits) {
        secp256k1_test_rng_integer |= ((UInt64(secp256k1_rand32())) << secp256k1_test_rng_integer_bits_left);
        secp256k1_test_rng_integer_bits_left += 32;
    }
    ret = secp256k1_test_rng_integer.lo
    secp256k1_test_rng_integer >>= bits
    secp256k1_test_rng_integer_bits_left -= bits
    ret &= (UInt32.max >> (32 - bits))
    return ret
}

func secp256k1_rand_int(_ range: UInt32) -> UInt32 {
    /* We want a uniform integer between 0 and range-1, inclusive.
     * B is the smallest number such that range <= 2**B.
     * two mechanisms implemented here:
     * - generate B bits numbers until one below range is found, and return it
     * - find the largest multiple M of range that is <= 2**(B+A), generate B+A
     *   bits numbers until one below M is found, and return it modulo range
     * The second mechanism consumes A more bits of entropy in every iteration,
     * but may need fewer iterations due to M being closer to 2**(B+A) then
     * range is to 2**B. The array below (indexed by B) contains a 0 when the
     * first mechanism is to be used, and the number A otherwise.
     */
    let addbits: [Int] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 0]
    var trange: UInt32
    var mult: UInt32
    var bits: Int = 0;
    if (range <= 1) {
        return 0;
    }
    trange = range - 1;
    while (trange > 0) {
        trange >>= 1;
        bits += 1
    }
    if (addbits[bits] != 0) {
        bits = bits + addbits[bits];
        mult = (UInt32.max >> (32 - bits)) / range;
        trange = range * mult;
    } else {
        trange = range;
        mult = 1;
    }
    while(true) {
        let x: UInt32 = secp256k1_rand_bits(bits);
        if (x < trange) {
            return (mult == 1) ? x : (x % range);
        }
    }
}

func secp256k1_rand256(_ b32: inout [UInt8], from: Int = 0) {
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, &b32, from: from, outlen: 32);
}

func secp256k1_rand_bytes_test(_ bytes: inout [UInt8], from: Int, _ len: UInt) {
    assert(bytes.count >= from + Int(len))
    var bits: UInt = 0
    // set 0 in [0, from)
    for i in from ..< from + Int(len) {
        bytes[i] = 0
    }
    // set random byte in [from, from + len)
    while bits < len * 8 {
        // now : [1, 64]
        var now: Int = Int(1 + (secp256k1_rand_bits(6) * secp256k1_rand_bits(5) + 16) / 31)
        let val: UInt32 = secp256k1_rand_bits(1)
        while now > 0 && bits < len * 8 {
            bytes[from + Int(bits / 8)] |= UInt8(val << (bits % 8))
            now -= 1
            bits += 1
        }
    }
}

// get random 32bytes
func secp256k1_rand256_test(_ b32: inout [UInt8]) {
    assert(b32.count == 32)
    secp256k1_rand_bytes_test(&b32, from: 0, 32)
}
