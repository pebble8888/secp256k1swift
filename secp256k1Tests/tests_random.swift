//
//  tests_random.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/11.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation
@testable import secp256k1

/***** RANDOM TESTS *****/

func test_rand_bits(_ rand32: Int, _ bits: Int) {
    /* (1-1/2^B)^rounds[B] < 1/10^9, so rounds is the number of iterations to
     * get a false negative chance below once in a billion */
    let rounds :[UInt] /* [7] */ = [1, 30, 73, 156, 322, 653, 1316]
    /* We try multiplying the results with various odd numbers, which shouldn't
     * influence the uniform distribution modulo a power of 2. */
    let mults :[UInt32] /* [6] */ = [1, 3, 21, 289, 0x9999, 0x80402011]
    /* We only select up to 6 bits from the output to analyse */
    let usebits: UInt = bits > 6 ? UInt(6) : UInt(bits)
    let maxshift: UInt = UInt(bits) - UInt(usebits)
    /* For each of the maxshift+1 usebits-bit sequences inside a bits-bit
       number, track all observed outcomes, one per bit in a uint64_t. */
    var x :[[UInt64]] = [[UInt64]](repeating: [UInt64](repeating: 0, count:27), count: 6) //[6][27] = {{0}};
    /* Multiply the output of all rand calls with the odd number m, which
       should not change the uniformity of its distribution. */
    for _ in 0 ..< rounds[Int(usebits)] {
        let r: UInt32 = (rand32 != 0 ? secp256k1_rand32() : secp256k1_rand_bits(bits));
        CHECK((UInt64(r) >> bits) == 0)
        for m in 0 ..< mults.count {
            let val = UInt64(r) * UInt64(mults[m]) // overflow
            let rm: UInt32 = val.lo
            for shift in 0 ... Int(maxshift) {
                let s = (rm >> shift) & ((1 << usebits) - 1)
                let v = UInt64(1) << s
                x[m][shift] |= v
            }
        }
    }
    for m in 0 ..< mults.count {
        for shift in 0 ... Int(maxshift) {
            /* Test that the lower usebits bits of x[shift] are 1 */
            let v = (~x[m][shift]) << (64 - (1 << usebits))
            CHECK(v == 0);
        }
    }
}

/* Subrange must be a whole divisor of range, and at most 64 */
func test_rand_int(_ range: UInt32, _ subrange: UInt32) {
    /* (1-1/subrange)^rounds < 1/10^9 */
    let rounds: Int = Int((subrange * 2073) / 100)
    var x: UInt64 = 0;
    CHECK((range % subrange) == 0);
    for _ in 0 ..< rounds {
        var r: UInt32 = secp256k1_rand_int(range);
        CHECK(r < range);
        r = r % subrange;
        x |= (UInt64(1) << r);
    }
    /* Test that the lower subrange bits of x are 1. */
    CHECK(((~x) << (64 - subrange)) == 0);
}

func run_rand_bits() {
    test_rand_bits(1, 32);
    for b in 1 ... 32 {
        test_rand_bits(0, b);
    }
}

func run_rand_int() {
    let ms:[UInt32] = [1, 3, 17, 1000, 13771, 999999, 33554432]
    let ss:[UInt32] = [1, 3, 6, 9, 13, 31, 64]
    for m in 0 ..< ms.count {
        for s in 0 ..< ss.count {
            test_rand_int(ms[m] * ss[s], ss[s]);
        }
    }
}
