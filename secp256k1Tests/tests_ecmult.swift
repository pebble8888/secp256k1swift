//
//  tests_ecmult.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/16.
//  Copyright © 2018年 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation
@testable import secp256k1

/***** ECMULT TESTS *****/

func test_ec_combine() {
    var sum : secp256k1_scalar = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0)
    var data = [secp256k1_pubkey](repeating: secp256k1_pubkey(), count: 6)
    var d = [secp256k1_pubkey](repeating: secp256k1_pubkey(), count: 6)
    var sd = secp256k1_pubkey()
    var sd2 = secp256k1_pubkey()
    var Qj = secp256k1_gej()
    var Q = secp256k1_ge()
    guard let ctx = ctx else {
        assert(false)
        return
    }
    for i in 1...6 {
        var s = secp256k1_scalar()
        random_scalar_order_test(&s);
        secp256k1_scalar_add(&sum, sum, s)
        secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &Qj, s)
        secp256k1_ge_set_gej(&Q, &Qj)
        secp256k1_pubkey_save(&data[i - 1], &Q)
        d[i - 1] = data[i - 1]
        secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &Qj, sum)
        secp256k1_ge_set_gej(&Q, &Qj)
        secp256k1_pubkey_save(&sd, &Q)
        CHECK(secp256k1_ec_pubkey_combine(ctx, &sd2, d, UInt(i)))
        CHECK(sd.equal(sd2))
    }
}

func run_ec_combine() {
    print("count \(g_count * 8)")
    for i in 0 ..< g_count * 8 {
        if i % 50 == 0 {
            print("\(i) ", terminator:"")
        }
        test_ec_combine()
    }
}

func run_ecmult_chain() {
    /* random starting point A (on the curve) */
    let a = SECP256K1_GEJ_CONST(
        0x8b30bbe9, 0xae2a9906, 0x96b22f67, 0x0709dff3,
        0x727fd8bc, 0x04d3362c, 0x6c7bf458, 0xe2846004,
        0xa357ae91, 0x5c4a6528, 0x1309edf2, 0x0504740f,
        0x0eb33439, 0x90216b4f, 0x81063cb6, 0x5f2f7e0f
    );
    /* two random initial factors xn and gn */
    var xn = SECP256K1_SCALAR_CONST(
        0x84cc5452, 0xf7fde1ed, 0xb4d38a8c, 0xe9b1b84c,
        0xcef31f14, 0x6e569be9, 0x705d357a, 0x42985407
    );
    var gn = SECP256K1_SCALAR_CONST(
        0xa1e58d22, 0x553dcd42, 0xb2398062, 0x5d4c57a9,
        0x6e9323d4, 0x2b3152e5, 0xca2c3990, 0xedc7c9de
    );
    /* two small multipliers to be applied to xn and gn in every iteration: */
    let xf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x1337);
    let gf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x7113);
    /* accumulators with the resulting coefficients to A and G */
    var ae = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    var ge = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* actual points */
    var x = secp256k1_gej()
    var x2 = secp256k1_gej()
    
    /* the point being computed */
    x = a;
    guard let ctx = ctx else { fatalError() }
    for i in 0 ..< 200*g_count {
        /* in each iteration, compute X = xn*X + gn*G; */
        secp256k1_ecmult(ctx.ecmult_ctx, &x, x, xn, gn);
        /* also compute ae and ge: the actual accumulated factors for A and G */
        /* if X was (ae*A+ge*G), xn*X + gn*G results in (xn*ae*A + (xn*ge+gn)*G) */
        secp256k1_scalar_mul(&ae, ae, xn);
        secp256k1_scalar_mul(&ge, ge, xn);
        secp256k1_scalar_add(&ge, ge, gn);
        /* modify xn and gn */
        secp256k1_scalar_mul(&xn, xn, xf);
        secp256k1_scalar_mul(&gn, gn, gf);
        
        /* verify */
        if (i == 19999) {
            /* expected result after 19999 iterations */
            var rp = SECP256K1_GEJ_CONST(
                0xD6E96687, 0xF9B10D09, 0x2A6F3543, 0x9D86CEBE,
                0xA4535D0D, 0x409F5358, 0x6440BD74, 0xB933E830,
                0xB95CBCA2, 0xC77DA786, 0x539BE8FD, 0x53354D2D,
                0x3B4F566A, 0xE6580454, 0x07ED6015, 0xEE1B2A88
            );
            
            secp256k1_gej_neg(&rp, rp);
            var dummy = secp256k1_fe()
            secp256k1_gej_add_var(&rp, rp, x, &dummy);
            CHECK(secp256k1_gej_is_infinity(rp));
        }
    }
    /* redo the computation, but directly with the resulting ae and ge coefficients: */
    secp256k1_ecmult(ctx.ecmult_ctx, &x2, a, ae, ge);
    secp256k1_gej_neg(&x2, x2);
    var dummy = secp256k1_fe()
    secp256k1_gej_add_var(&x2, x2, x, &dummy);
    CHECK(secp256k1_gej_is_infinity(x2));
}

func test_point_times_order(_ point: secp256k1_gej) {
    /* X * (point + G) + (order-X) * (pointer + G) = 0 */
    var x = secp256k1_scalar()
    var nx = secp256k1_scalar()
    let zero: secp256k1_scalar = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    let one: secp256k1_scalar = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    var res1 = secp256k1_gej()
    var res2 = secp256k1_gej()
    var res3 = secp256k1_ge()
    var pub = [UInt8](repeating: 0, count: 65)
    var psize: UInt = 65;
    random_scalar_order_test(&x);
    secp256k1_scalar_negate(&nx, x);
    guard let ctx = ctx else { fatalError() }
    secp256k1_ecmult(ctx.ecmult_ctx, &res1, point, x, x); /* calc res1 = x * point + x * G; */
    secp256k1_ecmult(ctx.ecmult_ctx, &res2, point, nx, nx); /* calc res2 = (order - x) * point + (order - x) * G; */
    var dummy = secp256k1_fe()
    secp256k1_gej_add_var(&res1, res1, res2, &dummy);
    CHECK(secp256k1_gej_is_infinity(res1));
    CHECK(!secp256k1_gej_is_valid_var(res1));
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(res3));
    CHECK(!secp256k1_ge_is_valid_var(res3));
    CHECK(!secp256k1_eckey_pubkey_serialize(&res3, &pub, &psize, false));
    psize = 65;
    CHECK(!secp256k1_eckey_pubkey_serialize(&res3, &pub, &psize, true));
    /* check zero/one edge cases */
    secp256k1_ecmult(ctx.ecmult_ctx, &res1, point, zero, zero);
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(res3));
    secp256k1_ecmult(ctx.ecmult_ctx, &res1, point, one, zero);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_gej(res3, point);
    secp256k1_ecmult(ctx.ecmult_ctx, &res1, point, zero, one);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_ge(res3, secp256k1_ge_const_g);
}

func run_point_times_order() {
    var x: secp256k1_fe = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2);
    let xr: secp256k1_fe = SECP256K1_FE_CONST(
        0x7603CB59, 0xB0EF6C63, 0xFE608479, 0x2A0C378C,
        0xDB3233A8, 0x0F8A9A09, 0xA877DEAD, 0x31B38C45
    );
    for _ in 0 ..< 500 {
        var p = secp256k1_ge()
        if (secp256k1_ge_set_xo_var(&p, x, true)) {
            var j = secp256k1_gej()
            CHECK(secp256k1_ge_is_valid_var(p));
            secp256k1_gej_set_ge(&j, p);
            CHECK(secp256k1_gej_is_valid_var(j));
            test_point_times_order(j);
        }
        secp256k1_fe_sqr(&x, x);
    }
    secp256k1_fe_normalize_var(&x);
    CHECK(secp256k1_fe_equal_var(x, xr));
}

func ecmult_const_random_mult() {
    /* random starting point A (on the curve) */
    let a: secp256k1_ge = SECP256K1_GE_CONST(
        0x6d986544, 0x57ff52b8, 0xcf1b8126, 0x5b802a5b,
        0xa97f9263, 0xb1e88044, 0x93351325, 0x91bc450a,
        0x535c59f7, 0x325e5d2b, 0xc391fbe8, 0x3c12787c,
        0x337e4a98, 0xe82a9011, 0x0123ba37, 0xdd769c7d
    );
    /* random initial factor xn */
    let xn = SECP256K1_SCALAR_CONST(
        0x649d4f77, 0xc4242df7, 0x7f2079c9, 0x14530327,
        0xa31b876a, 0xd2d8ce2a, 0x2236d5c6, 0xd7b2029b
    );
    /* expected xn * A (from sage) */
    let expected_b = SECP256K1_GE_CONST(
        0x23773684, 0x4d209dc7, 0x098a786f, 0x20d06fcd,
        0x070a38bf, 0xc11ac651, 0x03004319, 0x1e2a8786,
        0xed8c3b8e, 0xc06dd57b, 0xd06ea66e, 0x45492b0f,
        0xb84e4e1b, 0xfb77e21f, 0x96baae2a, 0x63dec956
    );
    var b = secp256k1_gej()
    secp256k1_ecmult_const(&b, a, xn);
    
    CHECK(secp256k1_ge_is_valid_var(a));
    ge_equals_gej(expected_b, b);
}

func ecmult_const_commutativity() {
    var a = secp256k1_scalar()
    var b = secp256k1_scalar()
    var res1 = secp256k1_gej()
    var res2 = secp256k1_gej()
    var mid1 = secp256k1_ge()
    var mid2 = secp256k1_ge()
    random_scalar_order_test(&a);
    random_scalar_order_test(&b);
    
    secp256k1_ecmult_const(&res1, secp256k1_ge_const_g, a);
    secp256k1_ecmult_const(&res2, secp256k1_ge_const_g, b);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    secp256k1_ecmult_const(&res1, mid1, b);
    secp256k1_ecmult_const(&res2, mid2, a);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    ge_equals_ge(mid1, mid2);
}

func ecmult_const_mult_zero_one() {
    let zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    let one = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    var negone = secp256k1_scalar()
    var res1 = secp256k1_gej()
    var res2 = secp256k1_ge()
    var point = secp256k1_ge()
    secp256k1_scalar_negate(&negone, one);
    
    random_group_element_test(&point);
    secp256k1_ecmult_const(&res1, point, zero);
    secp256k1_ge_set_gej(&res2, &res1);
    CHECK(secp256k1_ge_is_infinity(res2));
    secp256k1_ecmult_const(&res1, point, one);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(res2, point);
    secp256k1_ecmult_const(&res1, point, negone);
    secp256k1_gej_neg(&res1, res1);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(res2, point);
}

func ecmult_const_chain_multiply() {
    /* Check known result (randomly generated test problem from sage) */
    let scalar = SECP256K1_SCALAR_CONST(
        0x4968d524, 0x2abf9b7a, 0x466abbcf, 0x34b11b6d,
        0xcd83d307, 0x827bed62, 0x05fad0ce, 0x18fae63b
    );
    let expected_point = SECP256K1_GEJ_CONST(
        0x5494c15d, 0x32099706, 0xc2395f94, 0x348745fd,
        0x757ce30e, 0x4e8c90fb, 0xa2bad184, 0xf883c69f,
        0x5d195d20, 0xe191bf7f, 0x1be3e55f, 0x56a80196,
        0x6071ad01, 0xf1462f66, 0xc997fa94, 0xdb858435
    );
    var point = secp256k1_gej()
    var res = secp256k1_ge()
    
    secp256k1_gej_set_ge(&point, secp256k1_ge_const_g);
    for _ in 0 ..< 100 {
        var tmp = secp256k1_ge()
        secp256k1_ge_set_gej(&tmp, &point);
        secp256k1_ecmult_const(&point, tmp, scalar);
    }
    secp256k1_ge_set_gej(&res, &point);
    ge_equals_gej(res, expected_point);
}

func run_ecmult_const_tests() {
    ecmult_const_mult_zero_one();
    ecmult_const_random_mult();
    ecmult_const_commutativity();
    ecmult_const_chain_multiply();
}

func test_wnaf(_ number: secp256k1_scalar, _ w: Int) {
    var x = secp256k1_scalar()
    var two = secp256k1_scalar()
    var t = secp256k1_scalar()
    var wnaf = [Int](repeating: 0, count: 256)
    var zeroes: Int = -1;
    var bits:Int
    secp256k1_scalar_set_int(&x, 0);
    secp256k1_scalar_set_int(&two, 2);
    bits = secp256k1_ecmult_wnaf(&wnaf, 256, number, w);
    CHECK(bits <= 256);
    for i in stride(from: bits-1, through: 0, by: -1){
        let v: Int = wnaf[i];
        secp256k1_scalar_mul(&x, x, two);
        if v != 0 {
            CHECK(zeroes == -1 || zeroes >= w-1); /* check that distance between non-zero elements is at least w-1 */
            zeroes=0;
            CHECK((v & 1) == 1); /* check non-zero elements are odd */
            CHECK(v <= (1 << (w-1)) - 1); /* check range below */
            CHECK(v >= -(1 << (w-1)) - 1); /* check range above */
        } else {
            CHECK(zeroes != -1); /* check that no unnecessary zero padding exists */
            zeroes += 1
        }
        if (v >= 0) {
            secp256k1_scalar_set_int(&t, UInt(v));
        } else {
            secp256k1_scalar_set_int(&t, UInt(-v));
            secp256k1_scalar_negate(&t, t);
        }
        secp256k1_scalar_add(&x, x, t);
    }
    CHECK(secp256k1_scalar_eq(x, number)); /* check that wnaf represents number */
}

func test_constant_wnaf_negate(_ number: secp256k1_scalar) {
    var neg1: secp256k1_scalar = number;
    var neg2: secp256k1_scalar = number;
    var sign1: Int = 1;
    var sign2: Int = 1;
    
    if (secp256k1_scalar_get_bits(neg1, UInt(0), UInt(1)) == 0) {
        secp256k1_scalar_negate(&neg1, neg1);
        sign1 = -1;
    }
    sign2 = secp256k1_scalar_cond_negate(&neg2, secp256k1_scalar_is_even(neg2) ? 1 : 0);
    CHECK(sign1 == sign2);
    CHECK(secp256k1_scalar_eq(neg1, neg2));
}

func test_constant_wnaf(_ number: secp256k1_scalar, _ w: Int) {
    var x = secp256k1_scalar()
    var shift = secp256k1_scalar()
    var wnaf = [Int](repeating: 0, count:256)
    var skew:Int
    var num: secp256k1_scalar = number
    
    secp256k1_scalar_set_int(&x, 0);
    secp256k1_scalar_set_int(&shift, 1 << w);
    /* With USE_ENDOMORPHISM on we only consider 128-bit numbers */
    /*
     #ifdef USE_ENDOMORPHISM
     for (i = 0; i < 16; ++i) {
     secp256k1_scalar_shr_int(&num, 8);
     }
     #endif
     */
    skew = secp256k1_wnaf_const(&wnaf, num, w);
    
    for i in stride(from: WNAF_SIZE(w), through: 0, by: -1) {
        var t = secp256k1_scalar()
        let v:Int = wnaf[i];
        CHECK(v != 0); /* check nonzero */
        CHECK(v & 1 != 0);  /* check parity */
        CHECK(v > -(1 << w)); /* check range above */
        CHECK(v < (1 << w));  /* check range below */
        
        secp256k1_scalar_mul(&x, x, shift);
        if (v >= 0) {
            secp256k1_scalar_set_int(&t, UInt(v));
        } else {
            secp256k1_scalar_set_int(&t, UInt(-v));
            secp256k1_scalar_negate(&t, t);
        }
        secp256k1_scalar_add(&x, x, t);
    }
    /* Skew num because when encoding numbers as odd we use an offset */
    secp256k1_scalar_cadd_bit(&num, skew == 2 ? UInt(1) : UInt(0), 1);
    CHECK(secp256k1_scalar_eq(x, num));
}

func run_wnaf() {
    var n = secp256k1_scalar()
    
    /* Sanity check: 1 and 2 are the smallest odd and even numbers and should
     *               have easier-to-diagnose failure modes  */
    n.d[0] = 1;
    test_constant_wnaf(n, 4);
    n.d[0] = 2;
    test_constant_wnaf(n, 4);
    /* Random tests */
    for i in 0 ..< g_count {
        random_scalar_order(&n);
        test_wnaf(n, 4+(i%10));
        test_constant_wnaf_negate(n);
        test_constant_wnaf(n, 4 + (i % 10));
    }
    secp256k1_scalar_set_int(&n, 0);
    CHECK(secp256k1_scalar_cond_negate(&n, 1) == -1);
    CHECK(secp256k1_scalar_is_zero(n));
    CHECK(secp256k1_scalar_cond_negate(&n, 0) == 1);
    CHECK(secp256k1_scalar_is_zero(n));
}

func test_ecmult_constants() {
    /* Test ecmult_gen() for [0..36) and [order-36..0). */
    var x = secp256k1_scalar()
    var r = secp256k1_gej()
    var ng = secp256k1_ge()
    secp256k1_ge_neg(&ng, secp256k1_ge_const_g);
    guard let ctx = ctx else { fatalError() }
    for i in 0 ..< 36 {
        secp256k1_scalar_set_int(&x, UInt(i));
        secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &r, x);
        for j in 0 ..< i {
            if (j == i - 1) {
                ge_equals_gej(secp256k1_ge_const_g, r);
            }
            secp256k1_gej_add_ge(&r, r, ng);
        }
        CHECK(secp256k1_gej_is_infinity(r));
    }
    for i in 1...36 {
        secp256k1_scalar_set_int(&x, UInt(i));
        secp256k1_scalar_negate(&x, x);
        secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &r, x);
        for j in 0 ..< i {
            if (j == i - 1) {
                ge_equals_gej(ng, r);
            }
            secp256k1_gej_add_ge(&r, r, secp256k1_ge_const_g);
        }
        CHECK(secp256k1_gej_is_infinity(r));
    }
}

func run_ecmult_constants() {
    test_ecmult_constants();
}

func test_ecmult_gen_blind() {
    /* Test ecmult_gen() blinding and confirm that the blinding changes, the affine points match, and the z's don't match. */
    var key = secp256k1_scalar()
    var b = secp256k1_scalar()
    var seed32 = [UInt8](repeating: 0, count: 32)
    var pgej = secp256k1_gej()
    var pgej2 = secp256k1_gej()
    var i = secp256k1_gej()
    var pge = secp256k1_ge()
    random_scalar_order_test(&key);
    guard var ctx = ctx else { fatalError() }
    secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &pgej, key);
    secp256k1_rand256(&seed32);
    b = ctx.ecmult_gen_ctx.blind;
    i = ctx.ecmult_gen_ctx.initial;
    secp256k1_ecmult_gen_blind(&ctx.ecmult_gen_ctx, seed32);
    CHECK(!secp256k1_scalar_eq(b, ctx.ecmult_gen_ctx.blind));
    secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &pgej2, key);
    CHECK(!gej_xyz_equals_gej(pgej, pgej2));
    CHECK(!gej_xyz_equals_gej(i, ctx.ecmult_gen_ctx.initial));
    secp256k1_ge_set_gej(&pge, &pgej);
    ge_equals_gej(pge, pgej2);
}

func test_ecmult_gen_blind_reset() {
    /* Test ecmult_gen() blinding reset and confirm that the blinding is consistent. */
    var b = secp256k1_scalar()
    var initial = secp256k1_gej()
    guard var ctx = ctx else { fatalError() }
    secp256k1_ecmult_gen_blind(&ctx.ecmult_gen_ctx, nil);
    b = ctx.ecmult_gen_ctx.blind;
    initial = ctx.ecmult_gen_ctx.initial;
    secp256k1_ecmult_gen_blind(&ctx.ecmult_gen_ctx, nil);
    CHECK(secp256k1_scalar_eq(b, ctx.ecmult_gen_ctx.blind));
    CHECK(gej_xyz_equals_gej(initial, ctx.ecmult_gen_ctx.initial));
}

func run_ecmult_gen_blind() {
    test_ecmult_gen_blind_reset();
    for _ in 0 ..< 10 {
        test_ecmult_gen_blind();
    }
}
