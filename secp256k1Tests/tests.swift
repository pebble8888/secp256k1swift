//
//  tests.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/11.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation
@testable import secp256k1

//#include "secp256k1.c"
//#include "include/secp256k1.h"
//#include "testrand_impl.h"

/*
#ifdef ENABLE_OPENSSL_TESTS
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif

#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"

#if !defined(VG_CHECK)
# if defined(VALGRIND)
#  include <valgrind/memcheck.h>
#  define VG_UNDEF(x,y) VALGRIND_MAKE_MEM_UNDEFINED((x),(y))
#  define VG_CHECK(x,y) VALGRIND_CHECK_MEM_IS_DEFINED((x),(y))
# else
#  define VG_UNDEF(x,y)
#  define VG_CHECK(x,y)
# endif
#endif
*/

//func VG_UNDEF(_ x: inout Any, _ y: Any){
//}
func VG_CHECK(_ x: Any, _ y: Any){
}

func CHECK(_ cond: Bool, _ line: Int = #line)
{
    assert(cond, "line \(line)")
}

func VERIFY_CHECK(_ cond: Bool, _ line: Int = #line)
{
    assert(cond, "line \(line)")
}

var g_count:Int = 64
var ctx: secp256k1_context?

func counting_illegal_callback_fn(_ str: String, _ data: UnsafeMutableRawPointer?) {
    /* Dummy callback function that just counts. */
    if let data = data {
        let d = data.bindMemory(to: Int32.self, capacity: 1)
        d.pointee += 1
    }
}

func uncounting_illegal_callback_fn(_ str: String, _ data: UnsafeMutableRawPointer?) {
    /* Dummy callback function that just counts (backwards). */
    if let data = data {
        let d = data.bindMemory(to: Int32.self, capacity: 1)
        d.pointee -= 1
    }
}

func random_field_element_test(_ fe: inout secp256k1_fe) {
    repeat {
        var b32 = [UInt8](repeating: 0, count:32)
        secp256k1_rand256_test(&b32);
        if (secp256k1_fe_set_b32(&fe, b32)) {
            break;
        }
    } while true
}

func random_field_element_magnitude(_ fe: inout secp256k1_fe) {
    var zero = secp256k1_fe()
    let n: Int = Int(secp256k1_rand_int(9))
    secp256k1_fe_normalize(&fe);
    if (n == 0) {
        return;
    }
    secp256k1_fe_clear(&zero);
    secp256k1_fe_negate(&zero, zero, 0);
    secp256k1_fe_mul_int(&zero, UInt32(n - 1));
    secp256k1_fe_add(&fe, zero);
    VERIFY_CHECK(fe.magnitude == n);
}

func random_group_element_test(_ ge: inout secp256k1_ge) {
    var fe = secp256k1_fe()
    repeat {
        random_field_element_test(&fe);
        if (secp256k1_ge_set_xo_var(&ge, fe, secp256k1_rand_bits(1) != 0)) {
            secp256k1_fe_normalize(&ge.y);
            break;
        }
    } while(true);
}

func random_group_element_jacobian_test(_ gej: inout secp256k1_gej, _ ge: secp256k1_ge) {
    var z2 = secp256k1_fe()
    var z3 = secp256k1_fe()
    repeat {
        random_field_element_test(&gej.z);
        if (!secp256k1_fe_is_zero(gej.z)) {
            break;
        }
    } while true;
    secp256k1_fe_sqr(&z2, gej.z);
    secp256k1_fe_mul(&z3, z2, gej.z);
    secp256k1_fe_mul(&gej.x, ge.x, z2);
    secp256k1_fe_mul(&gej.y, ge.y, z3);
    gej.infinity = ge.infinity;
}

func random_scalar_order_test(_ num: inout secp256k1_scalar) {
    repeat {
        var b32 = [UInt8](repeating:0, count:32)
        var overflow = false
        secp256k1_rand256_test(&b32);
        secp256k1_scalar_set_b32(&num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while true
}

func random_scalar_order(_ num: inout secp256k1_scalar) {
    repeat {
        var b32 = [UInt8](repeating: 0, count: 32)
        var overflow: Bool = false
        secp256k1_rand256(&b32);
        secp256k1_scalar_set_b32(&num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while true
}

func run_context_tests() {
    var pubkey = secp256k1_pubkey()
    var zero_pubkey = secp256k1_pubkey()
    var sig = secp256k1_ecdsa_signature()
    var ctmp = [UInt8](repeating:0, count:32)
    var ecount:Int32
    var ecount2:Int32
    var none: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_NONE)!
    var sign: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_SIGN)!
    var vrfy: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_VERIFY)!
    var both: secp256k1_context = secp256k1_context_create([.SECP256K1_CONTEXT_SIGN, .SECP256K1_CONTEXT_VERIFY])!

    var pubj = secp256k1_gej()
    var pub = secp256k1_ge()
    var msg = secp256k1_scalar()
    var key = secp256k1_scalar()
    var nonce = secp256k1_scalar()
    var sigr = secp256k1_scalar()
    var sigs = secp256k1_scalar()

    //memset(&zero_pubkey, 0, sizeof(zero_pubkey));
    zero_pubkey.clear()

    ecount = 0;
    ecount2 = 10;
    secp256k1_context_set_illegal_callback(&vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(&sign, counting_illegal_callback_fn, &ecount2);
    secp256k1_context_set_error_callback(&sign, counting_illegal_callback_fn, nil);
    //CHECK(vrfy.error_callback.fn != sign.error_callback.fn);

    /*** clone and destroy all of them to make sure cloning was complete ***/
    var ctx_tmp = secp256k1_context()

    ctx_tmp = none; none = secp256k1_context_clone(none); secp256k1_context_destroy(&ctx_tmp);
    ctx_tmp = sign; sign = secp256k1_context_clone(sign); secp256k1_context_destroy(&ctx_tmp);
    ctx_tmp = vrfy; vrfy = secp256k1_context_clone(vrfy); secp256k1_context_destroy(&ctx_tmp);
    ctx_tmp = both; both = secp256k1_context_clone(both); secp256k1_context_destroy(&ctx_tmp);

    /* Verify that the error callback makes it across the clone. */
    //CHECK(vrfy.error_callback.fn != sign.error_callback.fn);
    /* And that it resets back to default. */
    secp256k1_context_set_error_callback(&sign, nil, nil);
    //CHECK(vrfy.error_callback.fn == sign.error_callback.fn);

    /*** attempt to use them ***/
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(both.ecmult_gen_ctx, &pubj, key);
    secp256k1_ge_set_gej(&pub, &pubj);

    /* Verify context-type checking illegal-argument errors. */
    for i in 0 ..< 32 {
        ctmp[i] = 1
    }
    CHECK(secp256k1_ec_pubkey_create(vrfy, &pubkey, ctmp) == false);
    CHECK(ecount == 1);
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(sign, &pubkey, ctmp) == true);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ecdsa_sign(vrfy, &sig, ctmp, ctmp, nil, nil) == false);
    CHECK(ecount == 2);
    //VG_UNDEF(&sig, sizeof(sig));
    CHECK(secp256k1_ecdsa_sign(sign, &sig, ctmp, ctmp, nil, nil) == true);
    //VG_CHECK(&sig, sizeof(sig));
    CHECK(ecount2 == 10);
    CHECK(secp256k1_ecdsa_verify(sign, sig, ctmp, pubkey) == false);
    CHECK(ecount2 == 11);
    CHECK(secp256k1_ecdsa_verify(vrfy, sig, ctmp, pubkey) == true);
    CHECK(ecount == 2);
    CHECK(secp256k1_ec_pubkey_tweak_add(sign, &pubkey, ctmp) == false);
    CHECK(ecount2 == 12);
    CHECK(secp256k1_ec_pubkey_tweak_add(vrfy, &pubkey, ctmp) == true);
    CHECK(ecount == 2);
    CHECK(secp256k1_ec_pubkey_tweak_mul(sign, &pubkey, ctmp) == false);
    CHECK(ecount2 == 13);
    CHECK(secp256k1_ec_pubkey_negate(vrfy, &pubkey) == true);
    CHECK(ecount == 2);
    CHECK(secp256k1_ec_pubkey_negate(sign, &pubkey) == true);
    CHECK(ecount == 2);
    var dummy_pubkey = secp256k1_pubkey()
    CHECK(secp256k1_ec_pubkey_negate(sign, &dummy_pubkey) == false);
    CHECK(ecount2 == 14);
    CHECK(secp256k1_ec_pubkey_negate(vrfy, &zero_pubkey) == false);
    CHECK(ecount == 3);
    CHECK(secp256k1_ec_pubkey_tweak_mul(vrfy, &pubkey, ctmp) == false);
    CHECK(ecount == 3);
    CHECK(secp256k1_context_randomize(&vrfy, ctmp) == false);
    CHECK(ecount == 4);
    //CHECK(secp256k1_context_randomize(&sign, nil) == 1);
    //CHECK(ecount2 == 14);
    secp256k1_context_set_illegal_callback(&vrfy, nil, nil);
    secp256k1_context_set_illegal_callback(&sign, nil, nil);

    /* This shouldn't leak memory, due to already-set tests. */
    secp256k1_ecmult_gen_context_build(&sign.ecmult_gen_ctx, nil)
    secp256k1_ecmult_context_build(&vrfy.ecmult_ctx, nil);

    /* obtain a working nonce */
    var dummy_recid: Int = 0
    repeat {
        random_scalar_order_test(&nonce);
    } while(!secp256k1_ecdsa_sig_sign(both.ecmult_gen_ctx, &sigr, &sigs, key, msg, nonce, &dummy_recid));

    /* try signing */
    CHECK(secp256k1_ecdsa_sig_sign(sign.ecmult_gen_ctx, &sigr, &sigs, key, msg, nonce, &dummy_recid));
    CHECK(secp256k1_ecdsa_sig_sign(both.ecmult_gen_ctx, &sigr, &sigs, key, msg, nonce, &dummy_recid));

    /* try verifying */
    CHECK(secp256k1_ecdsa_sig_verify(vrfy.ecmult_ctx, sigr, sigs, pub, msg));
    CHECK(secp256k1_ecdsa_sig_verify(both.ecmult_ctx, sigr, sigs, pub, msg));

    /* cleanup */
    secp256k1_context_destroy(&none);
    secp256k1_context_destroy(&sign);
    secp256k1_context_destroy(&vrfy);
    secp256k1_context_destroy(&both);
    /* Defined as no-op. */
    //secp256k1_context_destroy(nil);
}

/***** ECMULT TESTS *****/

fileprivate func test_ec_combine() {
    var sum: secp256k1_scalar = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
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
        CHECK(secp256k1_ec_pubkey_combine(ctx, &sd2, d, i))
        CHECK(sd.equal(sd2))
    }
}

func run_ec_combine() {
    for _ in 0 ..< g_count * 8 {
         test_ec_combine()
    }
}

/*
func run_ecmult_chain() {
    /* random starting point A (on the curve) */
    secp256k1_gej a = SECP256K1_GEJ_CONST(
        0x8b30bbe9, 0xae2a9906, 0x96b22f67, 0x0709dff3,
        0x727fd8bc, 0x04d3362c, 0x6c7bf458, 0xe2846004,
        0xa357ae91, 0x5c4a6528, 0x1309edf2, 0x0504740f,
        0x0eb33439, 0x90216b4f, 0x81063cb6, 0x5f2f7e0f
    );
    /* two random initial factors xn and gn */
    secp256k1_scalar xn = SECP256K1_SCALAR_CONST(
        0x84cc5452, 0xf7fde1ed, 0xb4d38a8c, 0xe9b1b84c,
        0xcef31f14, 0x6e569be9, 0x705d357a, 0x42985407
    );
    secp256k1_scalar gn = SECP256K1_SCALAR_CONST(
        0xa1e58d22, 0x553dcd42, 0xb2398062, 0x5d4c57a9,
        0x6e9323d4, 0x2b3152e5, 0xca2c3990, 0xedc7c9de
    );
    /* two small multipliers to be applied to xn and gn in every iteration: */
    static const secp256k1_scalar xf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x1337);
    static const secp256k1_scalar gf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x7113);
    /* accumulators with the resulting coefficients to A and G */
    secp256k1_scalar ae = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_scalar ge = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* actual points */
    secp256k1_gej x;
    secp256k1_gej x2;
    int i;

    /* the point being computed */
    x = a;
    for (i = 0; i < 200*g_count; i++) {
        /* in each iteration, compute X = xn*X + gn*G; */
        secp256k1_ecmult(&ctx.ecmult_ctx, &x, &x, &xn, &gn);
        /* also compute ae and ge: the actual accumulated factors for A and G */
        /* if X was (ae*A+ge*G), xn*X + gn*G results in (xn*ae*A + (xn*ge+gn)*G) */
        secp256k1_scalar_mul(&ae, &ae, &xn);
        secp256k1_scalar_mul(&ge, &ge, &xn);
        secp256k1_scalar_add(&ge, &ge, &gn);
        /* modify xn and gn */
        secp256k1_scalar_mul(&xn, &xn, &xf);
        secp256k1_scalar_mul(&gn, &gn, &gf);

        /* verify */
        if (i == 19999) {
            /* expected result after 19999 iterations */
            secp256k1_gej rp = SECP256K1_GEJ_CONST(
                0xD6E96687, 0xF9B10D09, 0x2A6F3543, 0x9D86CEBE,
                0xA4535D0D, 0x409F5358, 0x6440BD74, 0xB933E830,
                0xB95CBCA2, 0xC77DA786, 0x539BE8FD, 0x53354D2D,
                0x3B4F566A, 0xE6580454, 0x07ED6015, 0xEE1B2A88
            );

            secp256k1_gej_neg(&rp, &rp);
            secp256k1_gej_add_var(&rp, &rp, &x, NULL);
            CHECK(secp256k1_gej_is_infinity(&rp));
        }
    }
    /* redo the computation, but directly with the resulting ae and ge coefficients: */
    secp256k1_ecmult(&ctx.ecmult_ctx, &x2, &a, &ae, &ge);
    secp256k1_gej_neg(&x2, &x2);
    secp256k1_gej_add_var(&x2, &x2, &x, NULL);
    CHECK(secp256k1_gej_is_infinity(&x2));
}

func test_point_times_order(_ point: secp256k1_gej) {
    /* X * (point + G) + (order-X) * (pointer + G) = 0 */
    secp256k1_scalar x;
    secp256k1_scalar nx;
    secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_scalar one = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_gej res1, res2;
    secp256k1_ge res3;
    unsigned char pub[65];
    size_t psize = 65;
    random_scalar_order_test(&x);
    secp256k1_scalar_negate(&nx, &x);
    secp256k1_ecmult(&ctx.ecmult_ctx, &res1, point, &x, &x); /* calc res1 = x * point + x * G; */
    secp256k1_ecmult(&ctx.ecmult_ctx, &res2, point, &nx, &nx); /* calc res2 = (order - x) * point + (order - x) * G; */
    secp256k1_gej_add_var(&res1, &res1, &res2, NULL);
    CHECK(secp256k1_gej_is_infinity(&res1));
    CHECK(secp256k1_gej_is_valid_var(&res1) == 0);
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(&res3));
    CHECK(secp256k1_ge_is_valid_var(&res3) == 0);
    CHECK(secp256k1_eckey_pubkey_serialize(&res3, pub, &psize, 0) == 0);
    psize = 65;
    CHECK(secp256k1_eckey_pubkey_serialize(&res3, pub, &psize, 1) == 0);
    /* check zero/one edge cases */
    secp256k1_ecmult(&ctx.ecmult_ctx, &res1, point, &zero, &zero);
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(&res3));
    secp256k1_ecmult(&ctx.ecmult_ctx, &res1, point, &one, &zero);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_gej(&res3, point);
    secp256k1_ecmult(&ctx.ecmult_ctx, &res1, point, &zero, &one);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_ge(&res3, &secp256k1_ge_const_g);
}

func run_point_times_order() {
    int i;
    secp256k1_fe x = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2);
    static const secp256k1_fe xr = SECP256K1_FE_CONST(
        0x7603CB59, 0xB0EF6C63, 0xFE608479, 0x2A0C378C,
        0xDB3233A8, 0x0F8A9A09, 0xA877DEAD, 0x31B38C45
    );
    for (i = 0; i < 500; i++) {
        secp256k1_ge p;
        if (secp256k1_ge_set_xo_var(&p, &x, 1)) {
            secp256k1_gej j;
            CHECK(secp256k1_ge_is_valid_var(&p));
            secp256k1_gej_set_ge(&j, &p);
            CHECK(secp256k1_gej_is_valid_var(&j));
            test_point_times_order(&j);
        }
        secp256k1_fe_sqr(&x, &x);
    }
    secp256k1_fe_normalize_var(&x);
    CHECK(secp256k1_fe_equal_var(&x, &xr));
}

func ecmult_const_random_mult() {
    /* random starting point A (on the curve) */
    secp256k1_ge a = SECP256K1_GE_CONST(
        0x6d986544, 0x57ff52b8, 0xcf1b8126, 0x5b802a5b,
        0xa97f9263, 0xb1e88044, 0x93351325, 0x91bc450a,
        0x535c59f7, 0x325e5d2b, 0xc391fbe8, 0x3c12787c,
        0x337e4a98, 0xe82a9011, 0x0123ba37, 0xdd769c7d
    );
    /* random initial factor xn */
    secp256k1_scalar xn = SECP256K1_SCALAR_CONST(
        0x649d4f77, 0xc4242df7, 0x7f2079c9, 0x14530327,
        0xa31b876a, 0xd2d8ce2a, 0x2236d5c6, 0xd7b2029b
    );
    /* expected xn * A (from sage) */
    secp256k1_ge expected_b = SECP256K1_GE_CONST(
        0x23773684, 0x4d209dc7, 0x098a786f, 0x20d06fcd,
        0x070a38bf, 0xc11ac651, 0x03004319, 0x1e2a8786,
        0xed8c3b8e, 0xc06dd57b, 0xd06ea66e, 0x45492b0f,
        0xb84e4e1b, 0xfb77e21f, 0x96baae2a, 0x63dec956
    );
    secp256k1_gej b;
    secp256k1_ecmult_const(&b, &a, &xn);

    CHECK(secp256k1_ge_is_valid_var(&a));
    ge_equals_gej(&expected_b, &b);
}

func ecmult_const_commutativity() {
    secp256k1_scalar a;
    secp256k1_scalar b;
    secp256k1_gej res1;
    secp256k1_gej res2;
    secp256k1_ge mid1;
    secp256k1_ge mid2;
    random_scalar_order_test(&a);
    random_scalar_order_test(&b);

    secp256k1_ecmult_const(&res1, &secp256k1_ge_const_g, &a);
    secp256k1_ecmult_const(&res2, &secp256k1_ge_const_g, &b);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    secp256k1_ecmult_const(&res1, &mid1, &b);
    secp256k1_ecmult_const(&res2, &mid2, &a);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    ge_equals_ge(&mid1, &mid2);
}

func ecmult_const_mult_zero_one() {
    secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_scalar one = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_scalar negone;
    secp256k1_gej res1;
    secp256k1_ge res2;
    secp256k1_ge point;
    secp256k1_scalar_negate(&negone, &one);

    random_group_element_test(&point);
    secp256k1_ecmult_const(&res1, &point, &zero);
    secp256k1_ge_set_gej(&res2, &res1);
    CHECK(secp256k1_ge_is_infinity(&res2));
    secp256k1_ecmult_const(&res1, &point, &one);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(&res2, &point);
    secp256k1_ecmult_const(&res1, &point, &negone);
    secp256k1_gej_neg(&res1, &res1);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(&res2, &point);
}

func ecmult_const_chain_multiply() {
    /* Check known result (randomly generated test problem from sage) */
    const secp256k1_scalar scalar = SECP256K1_SCALAR_CONST(
        0x4968d524, 0x2abf9b7a, 0x466abbcf, 0x34b11b6d,
        0xcd83d307, 0x827bed62, 0x05fad0ce, 0x18fae63b
    );
    const secp256k1_gej expected_point = SECP256K1_GEJ_CONST(
        0x5494c15d, 0x32099706, 0xc2395f94, 0x348745fd,
        0x757ce30e, 0x4e8c90fb, 0xa2bad184, 0xf883c69f,
        0x5d195d20, 0xe191bf7f, 0x1be3e55f, 0x56a80196,
        0x6071ad01, 0xf1462f66, 0xc997fa94, 0xdb858435
    );
    secp256k1_gej point;
    secp256k1_ge res;
    int i;

    secp256k1_gej_set_ge(&point, &secp256k1_ge_const_g);
    for (i = 0; i < 100; ++i) {
        secp256k1_ge tmp;
        secp256k1_ge_set_gej(&tmp, &point);
        secp256k1_ecmult_const(&point, &tmp, &scalar);
    }
    secp256k1_ge_set_gej(&res, &point);
    ge_equals_gej(&res, &expected_point);
}

func run_ecmult_const_tests() {
    ecmult_const_mult_zero_one();
    ecmult_const_random_mult();
    ecmult_const_commutativity();
    ecmult_const_chain_multiply();
}
 */

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
    //for (i = bits-1; i >= 0; i--) {
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
    skew = secp256k1_wnaf_const(&wnaf, &num, w);

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

/*
#if USE_ENDOMORPHISM
/***** ENDOMORPHISH TESTS *****/
func test_scalar_split() {
    secp256k1_scalar full;
    secp256k1_scalar s1, slam;
    const unsigned char zero[32] = {0};
    unsigned char tmp[32];

    random_scalar_order_test(&full);
    secp256k1_scalar_split_lambda(&s1, &slam, &full);

    /* check that both are <= 128 bits in size */
    if (secp256k1_scalar_is_high(&s1)) {
        secp256k1_scalar_negate(&s1, &s1);
    }
    if (secp256k1_scalar_is_high(&slam)) {
        secp256k1_scalar_negate(&slam, &slam);
    }

    secp256k1_scalar_get_b32(tmp, &s1);
    CHECK(memcmp(zero, tmp, 16) == 0);
    secp256k1_scalar_get_b32(tmp, &slam);
    CHECK(memcmp(zero, tmp, 16) == 0);
}

func run_endomorphism_tests() {
    test_scalar_split();
}
#endif
 */

/*
func ec_pubkey_parse_pointtest(_ input: [UInt8], _ xvalid: Int, _ yvalid: Int) {
    unsigned char pubkeyc[65];
    secp256k1_pubkey pubkey;
    secp256k1_ge ge;
    size_t pubkeyclen;
    int32_t ecount;
    ecount = 0;
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
    for (pubkeyclen = 3; pubkeyclen <= 65; pubkeyclen++) {
        /* Smaller sizes are tested exhaustively elsewhere. */
        int32_t i;
        memcpy(&pubkeyc[1], input, 64);
        //VG_UNDEF(&pubkeyc[pubkeyclen], 65 - pubkeyclen);
        for (i = 0; i < 256; i++) {
            /* Try all type bytes. */
            int xpass;
            int ypass;
            int ysign;
            pubkeyc[0] = i;
            /* What sign does this point have? */
            ysign = (input[63] & 1) + 2;
            /* For the current type (i) do we expect parsing to work? Handled all of compressed/uncompressed/hybrid. */
            xpass = xvalid && (pubkeyclen == 33) && ((i & 254) == 2);
            /* Do we expect a parse and re-serialize as uncompressed to give a matching y? */
            ypass = xvalid && yvalid && ((i & 4) == ((pubkeyclen == 65) << 2)) &&
                ((i == 4) || ((i & 251) == ysign)) && ((pubkeyclen == 33) || (pubkeyclen == 65));
            if (xpass || ypass) {
                /* These cases must parse. */
                unsigned char pubkeyo[65];
                size_t outl;
                memset(&pubkey, 0, sizeof(pubkey));
                //VG_UNDEF(&pubkey, sizeof(pubkey));
                ecount = 0;
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);
                VG_CHECK(&pubkey, sizeof(pubkey));
                outl = 65;
                //VG_UNDEF(pubkeyo, 65);
                CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyo, &outl, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
                VG_CHECK(pubkeyo, outl);
                CHECK(outl == 33);
                CHECK(memcmp(&pubkeyo[1], &pubkeyc[1], 32) == 0);
                CHECK((pubkeyclen != 33) || (pubkeyo[0] == pubkeyc[0]));
                if (ypass) {
                    /* This test isn't always done because we decode with alternative signs, so the y won't match. */
                    CHECK(pubkeyo[0] == ysign);
                    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 1);
                    memset(&pubkey, 0, sizeof(pubkey));
                    //VG_UNDEF(&pubkey, sizeof(pubkey));
                    secp256k1_pubkey_save(&pubkey, &ge);
                    VG_CHECK(&pubkey, sizeof(pubkey));
                    outl = 65;
                    //VG_UNDEF(pubkeyo, 65);
                    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyo, &outl, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
                    VG_CHECK(pubkeyo, outl);
                    CHECK(outl == 65);
                    CHECK(pubkeyo[0] == 4);
                    CHECK(memcmp(&pubkeyo[1], input, 64) == 0);
                }
                CHECK(ecount == 0);
            } else {
                /* These cases must fail to parse. */
                memset(&pubkey, 0xfe, sizeof(pubkey));
                ecount = 0;
                //VG_UNDEF(&pubkey, sizeof(pubkey));
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 0);
                VG_CHECK(&pubkey, sizeof(pubkey));
                CHECK(ecount == 0);
                CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
                CHECK(ecount == 1);
            }
        }
    }
    secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
}

func run_ec_pubkey_parse_test() {
    let SECP256K1_EC_PARSE_TEST_NVALID = 12
    const unsigned char valid[SECP256K1_EC_PARSE_TEST_NVALID][64] = {
        {
            /* Point with leading and trailing zeros in x and y serialization. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x52,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0xef, 0xa1, 0x7b, 0x77, 0x61, 0xe1, 0xe4, 0x27, 0x06, 0x98, 0x9f, 0xb4, 0x83,
            0xb8, 0xd2, 0xd4, 0x9b, 0xf7, 0x8f, 0xae, 0x98, 0x03, 0xf0, 0x99, 0xb8, 0x34, 0xed, 0xeb, 0x00
        },
        {
            /* Point with x equal to a 3rd root of unity.*/
            0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
            0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Point with largest x. (1/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0x0e, 0x99, 0x4b, 0x14, 0xea, 0x72, 0xf8, 0xc3, 0xeb, 0x95, 0xc7, 0x1e, 0xf6, 0x92, 0x57, 0x5e,
            0x77, 0x50, 0x58, 0x33, 0x2d, 0x7e, 0x52, 0xd0, 0x99, 0x5c, 0xf8, 0x03, 0x88, 0x71, 0xb6, 0x7d,
        },
        {
            /* Point with largest x. (2/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0xf1, 0x66, 0xb4, 0xeb, 0x15, 0x8d, 0x07, 0x3c, 0x14, 0x6a, 0x38, 0xe1, 0x09, 0x6d, 0xa8, 0xa1,
            0x88, 0xaf, 0xa7, 0xcc, 0xd2, 0x81, 0xad, 0x2f, 0x66, 0xa3, 0x07, 0xfb, 0x77, 0x8e, 0x45, 0xb2,
        },
        {
            /* Point with smallest x. (1/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Point with smallest x. (2/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        },
        {
            /* Point with largest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with largest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with largest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with smallest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Point with smallest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Point with smallest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        }
    };
#define SECP256K1_EC_PARSE_TEST_NXVALID (4)
    const unsigned char onlyxvalid[SECP256K1_EC_PARSE_TEST_NXVALID][64] = {
        {
            /* Valid if y overflow ignored (y = 1 mod p). (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* Valid if y overflow ignored (y = 1 mod p). (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* Valid if y overflow ignored (y = 1 mod p). (3/3)*/
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* x on curve, y is from y^2 = x^3 + 8. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        }
    };
#define SECP256K1_EC_PARSE_TEST_NINVALID (7)
    const unsigned char invalid[SECP256K1_EC_PARSE_TEST_NINVALID][64] = {
        {
            /* x is third root of -8, y is -1 * (x^3+7); also on the curve for y^2 = x^3 + 9. */
            0x0a, 0x2d, 0x2b, 0xa9, 0x35, 0x07, 0xf1, 0xdf, 0x23, 0x37, 0x70, 0xc2, 0xa7, 0x97, 0x96, 0x2c,
            0xc6, 0x1f, 0x6d, 0x15, 0xda, 0x14, 0xec, 0xd4, 0x7d, 0x8d, 0x27, 0xae, 0x1c, 0xd5, 0xf8, 0x53,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        },
        {
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0xf4, 0x84, 0x14, 0x5c, 0xb0, 0x14, 0x9b, 0x82, 0x5d, 0xff, 0x41, 0x2f, 0xa0, 0x52, 0xa8, 0x3f,
            0xcb, 0x72, 0xdb, 0x61, 0xd5, 0x6f, 0x37, 0x70, 0xce, 0x06, 0x6b, 0x73, 0x49, 0xa2, 0xaa, 0x28,
        },
        {
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0x0b, 0x7b, 0xeb, 0xa3, 0x4f, 0xeb, 0x64, 0x7d, 0xa2, 0x00, 0xbe, 0xd0, 0x5f, 0xad, 0x57, 0xc0,
            0x34, 0x8d, 0x24, 0x9e, 0x2a, 0x90, 0xc8, 0x8f, 0x31, 0xf9, 0x94, 0x8b, 0xb6, 0x5d, 0x52, 0x07,
        },
        {
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x8f, 0x53, 0x7e, 0xef, 0xdf, 0xc1, 0x60, 0x6a, 0x07, 0x27, 0xcd, 0x69, 0xb4, 0xa7, 0x33, 0x3d,
            0x38, 0xed, 0x44, 0xe3, 0x93, 0x2a, 0x71, 0x79, 0xee, 0xcb, 0x4b, 0x6f, 0xba, 0x93, 0x60, 0xdc,
        },
        {
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x70, 0xac, 0x81, 0x10, 0x20, 0x3e, 0x9f, 0x95, 0xf8, 0xd8, 0x32, 0x96, 0x4b, 0x58, 0xcc, 0xc2,
            0xc7, 0x12, 0xbb, 0x1c, 0x6c, 0xd5, 0x8e, 0x86, 0x11, 0x34, 0xb4, 0x8f, 0x45, 0x6c, 0x9b, 0x53
        }
    };
    const unsigned char pubkeyc[66] = {
        /* Serialization of G. */
        0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
        0xB8, 0x00
    };
    unsigned char sout[65];
    unsigned char shortkey[2];
    secp256k1_ge ge;
    secp256k1_pubkey pubkey;
    size_t len;
    int32_t i;
    int32_t ecount;
    int32_t ecount2;
    ecount = 0;
    /* Nothing should be reading this far into pubkeyc. */
    //VG_UNDEF(&pubkeyc[65], 1);
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
    /* Zero length claimed, fail, zeroize, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(shortkey, 2);
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 0) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* Length one claimed, fail, zeroize, no illegal arg error. */
    for (i = 0; i < 256 ; i++) {
        memset(&pubkey, 0xfe, sizeof(pubkey));
        ecount = 0;
        shortkey[0] = i;
        //VG_UNDEF(&shortkey[1], 1);
        //VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 1) == 0);
        VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
        CHECK(ecount == 1);
    }
    /* Length two claimed, fail, zeroize, no illegal arg error. */
    for (i = 0; i < 65536 ; i++) {
        memset(&pubkey, 0xfe, sizeof(pubkey));
        ecount = 0;
        shortkey[0] = i & 255;
        shortkey[1] = i >> 8;
        //VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 2) == 0);
        VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
        CHECK(ecount == 1);
    }
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    /* 33 bytes claimed on otherwise valid input starting with 0x04, fail, zeroize output, no illegal arg error. */
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 33) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* NULL pubkey, illegal arg error. Pubkey isn't rewritten before this step, since it's NULL into the parser. */
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, pubkeyc, 65) == 0);
    CHECK(ecount == 2);
    /* NULL input string. Illegal arg and zeroize output. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, NULL, 65) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 1);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 2);
    /* 64 bytes claimed on input starting with 0x04, fail, zeroize output, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 64) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* 66 bytes claimed, fail, zeroize output, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 66) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* Valid parse. */
    memset(&pubkey, 0, sizeof(pubkey));
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 65) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    //VG_UNDEF(&ge, sizeof(ge));
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 1);
    VG_CHECK(&ge.x, sizeof(ge.x));
    VG_CHECK(&ge.y, sizeof(ge.y));
    VG_CHECK(&ge.infinity, sizeof(ge.infinity));
    ge_equals_ge(&secp256k1_ge_const_g, &ge);
    CHECK(ecount == 0);
    /* secp256k1_ec_pubkey_serialize illegal args. */
    ecount = 0;
    len = 65;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, NULL, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 0);
    CHECK(ecount == 1);
    CHECK(len == 0);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, sout, NULL, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 0);
    CHECK(ecount == 2);
    len = 65;
    //VG_UNDEF(sout, 65);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, sout, &len, NULL, SECP256K1_EC_UNCOMPRESSED) == 0);
    VG_CHECK(sout, 65);
    CHECK(ecount == 3);
    CHECK(len == 0);
    len = 65;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, sout, &len, &pubkey, ~0) == 0);
    CHECK(ecount == 4);
    CHECK(len == 0);
    len = 65;
    //VG_UNDEF(sout, 65);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, sout, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
    VG_CHECK(sout, 65);
    CHECK(ecount == 4);
    CHECK(len == 65);
    /* Multiple illegal args. Should still set arg error only once. */
    ecount = 0;
    ecount2 = 11;
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, NULL, 65) == 0);
    CHECK(ecount == 1);
    /* Does the illegal arg callback actually change the behavior? */
    secp256k1_context_set_illegal_callback(ctx, uncounting_illegal_callback_fn, &ecount2);
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, NULL, 65) == 0);
    CHECK(ecount == 1);
    CHECK(ecount2 == 10);
    secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
    /* Try a bunch of prefabbed points with all possible encodings. */
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NVALID; i++) {
        ec_pubkey_parse_pointtest(valid[i], 1, 1);
    }
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NXVALID; i++) {
        ec_pubkey_parse_pointtest(onlyxvalid[i], 1, 0);
    }
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NINVALID; i++) {
        ec_pubkey_parse_pointtest(invalid[i], 0, 0);
    }
}

func run_eckey_edge_case_test() {
    const unsigned char orderc[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    const unsigned char zeros[sizeof(secp256k1_pubkey)] = {0x00};
    unsigned char ctmp[33];
    unsigned char ctmp2[33];
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey2;
    secp256k1_pubkey pubkey_one;
    secp256k1_pubkey pubkey_negone;
    const secp256k1_pubkey *pubkeys[3];
    size_t len;
    int32_t ecount;
    /* Group order is too large, reject. */
    CHECK(secp256k1_ec_seckey_verify(ctx, orderc) == 0);
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, orderc) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* Maximum value is too large, reject. */
    memset(ctmp, 255, 32);
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* Zero is too small, reject. */
    memset(ctmp, 0, 32);
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* One must be accepted. */
    ctmp[31] = 0x01;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1);
    memset(&pubkey, 0, sizeof(pubkey));
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_one = pubkey;
    /* Group order + 1 is too large, reject. */
    memcpy(ctmp, orderc, 32);
    ctmp[31] = 0x42;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 0);
    memset(&pubkey, 1, sizeof(pubkey));
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* -1 must be accepted. */
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1);
    memset(&pubkey, 0, sizeof(pubkey));
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_negone = pubkey;
    /* Tweak of zero leaves the value changed. */
    memset(ctmp2, 0, 32);
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, ctmp2) == 1);
    CHECK(memcmp(orderc, ctmp, 31) == 0 && ctmp[31] == 0x40);
    memcpy(&pubkey2, &pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1);
    CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Multiply tweak of zero zeroizes the output. */
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, ctmp2) == 0);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, ctmp2) == 0);
    CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    /* Overflowing key tweak zeroizes. */
    memcpy(ctmp, orderc, 32);
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, orderc) == 0);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    memcpy(ctmp, orderc, 32);
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, orderc) == 0);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    memcpy(ctmp, orderc, 32);
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, orderc) == 0);
    CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, orderc) == 0);
    CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    /* Private key tweaks results in a key of zero. */
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp2, ctmp) == 0);
    CHECK(memcmp(zeros, ctmp2, 32) == 0);
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 0);
    CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    /* Tweak computation wraps and results in a key of 1. */
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp2, ctmp) == 1);
    CHECK(memcmp(ctmp2, zeros, 31) == 0 && ctmp2[31] == 1);
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1);
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, ctmp2) == 1);
    CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Tweak mul * 2 = 1+1. */
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 1);
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == 1);
    CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Test argument errors. */
    ecount = 0;
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
    CHECK(ecount == 0);
    /* Zeroize pubkey on parse error. */
    memset(&pubkey, 0, 32);
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == 0);
    CHECK(ecount == 1);
    CHECK(memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    memset(&pubkey2, 0, 32);
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp(&pubkey2, zeros, sizeof(pubkey2)) == 0);
    /* Plain argument errors. */
    ecount = 0;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_ec_seckey_verify(ctx, NULL) == 0);
    CHECK(ecount == 1);
    ecount = 0;
    memset(ctmp2, 0, 32);
    ctmp2[31] = 4;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, NULL, ctmp2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, NULL) == 0);
    CHECK(ecount == 2);
    ecount = 0;
    memset(ctmp2, 0, 32);
    ctmp2[31] = 4;
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, NULL, ctmp2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, NULL) == 0);
    CHECK(ecount == 2);
    ecount = 0;
    memset(ctmp2, 0, 32);
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, NULL, ctmp2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, ctmp, NULL) == 0);
    CHECK(ecount == 2);
    ecount = 0;
    memset(ctmp2, 0, 32);
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, NULL, ctmp2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, ctmp, NULL) == 0);
    CHECK(ecount == 2);
    ecount = 0;
    CHECK(secp256k1_ec_pubkey_create(ctx, NULL, ctmp) == 0);
    CHECK(ecount == 1);
    memset(&pubkey, 1, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* secp256k1_ec_pubkey_combine tests. */
    ecount = 0;
    pubkeys[0] = &pubkey_one;
    //VG_UNDEF(&pubkeys[0], sizeof(secp256k1_pubkey *));
    //VG_UNDEF(&pubkeys[1], sizeof(secp256k1_pubkey *));
    //VG_UNDEF(&pubkeys[2], sizeof(secp256k1_pubkey *));
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 0) == 0);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_combine(ctx, NULL, pubkeys, 1) == 0);
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 2);
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, NULL, 1) == 0);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 3);
    pubkeys[0] = &pubkey_negone;
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 1) == 1);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp2, &len, &pubkey_negone, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(memcmp(ctmp, ctmp2, 33) == 0);
    /* Result is infinity. */
    pubkeys[0] = &pubkey_one;
    pubkeys[1] = &pubkey_negone;
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == 0);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 3);
    /* Passes through infinity but comes out one. */
    pubkeys[2] = &pubkey_one;
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 3) == 1);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp, &len, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, ctmp2, &len, &pubkey_one, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(memcmp(ctmp, ctmp2, 33) == 0);
    /* Adds to two. */
    pubkeys[1] = &pubkey_one;
    memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == 1);
    VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
}

func random_sign(_ sigr: inout secp256k1_scalar, _ sigs: inout secp256k1_scalar, _ key secp256k1_scalar, _ msg: secp256k1_scalar, _ recid: inout Int) {
    secp256k1_scalar nonce;
    do {
        random_scalar_order_test(&nonce);
    } while(!secp256k1_ecdsa_sig_sign(&ctx.ecmult_gen_ctx, sigr, sigs, key, msg, &nonce, recid));
}

func test_ecdsa_sign_verify() {
    secp256k1_gej pubj;
    secp256k1_ge pub;
    secp256k1_scalar one;
    secp256k1_scalar msg, key;
    secp256k1_scalar sigr, sigs;
    int recid;
    int getrec;
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(&ctx.ecmult_gen_ctx, &pubj, &key);
    secp256k1_ge_set_gej(&pub, &pubj);
    getrec = secp256k1_rand_bits(1);
    random_sign(&sigr, &sigs, &key, &msg, getrec?&recid:NULL);
    if (getrec) {
        CHECK(recid >= 0 && recid < 4);
    }
    CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sigr, &sigs, &pub, &msg));
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_add(&msg, &msg, &one);
    CHECK(!secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sigr, &sigs, &pub, &msg));
}

func run_ecdsa_sign_verify() {
    for i in 0 ..< 10*g_count {
        test_ecdsa_sign_verify();
    }
}

/** Dummy nonce generation function that just uses a precomputed nonce, and fails if it is not accepted. Use only for testing. */
func precomputed_nonce_function(_ nonce32: inout [UInt8], _ msg32: [UInt8], _ key32: [UInt8], _ algo16: [UInt8], void *data, _ counter: UInt) -> Bool {
    (void)msg32;
    (void)key32;
    (void)algo16;
    memcpy(nonce32, data, 32);
    return (counter == 0);
}

static int nonce_function_test_fail(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   /* Dummy nonce generator that has a fatal error on the first counter value. */
   if (counter == 0) {
       return 0;
   }
   return nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter - 1);
}

func nonce_function_test_retry(_ nonce32: inout [UInt8], _ msg32: inout [UInt8], _ key32: [UInt8], _ algo16: [UInt8], void *data, _ counter: UInt) -> Bool {
   /* Dummy nonce generator that produces unacceptable nonces for the first several counter values. */
   if (counter < 3) {
       memset(nonce32, counter==0 ? 0 : 255, 32);
       if (counter == 2) {
           nonce32[31]--;
       }
       return 1;
   }
   if (counter < 5) {
       static const unsigned char order[] = {
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
           0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
           0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
       };
       memcpy(nonce32, order, 32);
       if (counter == 4) {
           nonce32[31]++;
       }
       return 1;
   }
   /* Retry rate of 6979 is negligible esp. as we only call this in deterministic tests. */
   /* If someone does fine a case where it retries for secp256k1, we'd like to know. */
   if (counter > 5) {
       return 0;
   }
   return nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter - 5);
}

func is_empty_signature(const secp256k1_ecdsa_signature *sig) -> Bool {
    static const unsigned char res[sizeof(secp256k1_ecdsa_signature)] = {0};
    return memcmp(sig, res, sizeof(secp256k1_ecdsa_signature)) == 0;
}

func test_ecdsa_end_to_end() {
    unsigned char extra[32] = {0x00};
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char privkey2[32];
    secp256k1_ecdsa_signature signature[6];
    secp256k1_scalar r, s;
    unsigned char sig[74];
    size_t siglen = 74;
    unsigned char pubkeyc[65];
    size_t pubkeyclen = 65;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubkey_tmp;
    unsigned char seckey[300];
    size_t seckeylen = 300;

    /* Generate a random key and message. */
    {
        secp256k1_scalar msg, key;
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_scalar_get_b32(message, &msg);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Verify exporting and importing public key. */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, secp256k1_rand_bits(1) == 1 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
    memset(&pubkey, 0, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);

    /* Verify negation changes the key and changes it back */
    memcpy(&pubkey_tmp, &pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) != 0);
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == 1);
    CHECK(memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) == 0);

    /* Verify private key import and export. */
    CHECK(ec_privkey_export_der(ctx, seckey, &seckeylen, privkey, secp256k1_rand_bits(1) == 1));
    CHECK(ec_privkey_import_der(ctx, privkey2, seckey, seckeylen) == 1);
    CHECK(memcmp(privkey, privkey2, 32) == 0);

    /* Optionally tweak the keys using addition. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_add(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (secp256k1_rand_int(3) == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_mul(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Sign. */
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[4], message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[1], message, privkey, NULL, extra) == 1);
    extra[31] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[2], message, privkey, NULL, extra) == 1);
    extra[31] = 0;
    extra[0] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[3], message, privkey, NULL, extra) == 1);
    CHECK(memcmp(&signature[0], &signature[4], sizeof(signature[0])) == 0);
    CHECK(memcmp(&signature[0], &signature[1], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[2], &signature[3], sizeof(signature[0])) != 0);
    /* Verify. */
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
    /* Test lower-S form, malleate, verify and fail, test again, malleate again */
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[0]));
    secp256k1_ecdsa_signature_load(ctx, &r, &s, &signature[0]);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 0);
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &signature[5], &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecdsa_signature_save(&signature[5], &r, &s);
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, NULL, &signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[5], message, &pubkey) == 1);
    CHECK(memcmp(&signature[5], &signature[0], 64) == 0);

    /* Serialize/parse DER and verify again */
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    memset(&signature[0], 0, sizeof(signature[0]));
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    /* Serialize/destroy/parse DER and verify again. */
    siglen = 74;
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    sig[secp256k1_rand_int(siglen)] += 1 + secp256k1_rand_int(255);
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 0 ||
          secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 0);
}

func test_random_pubkeys() {
    secp256k1_ge elem;
    secp256k1_ge elem2;
    unsigned char in[65];
    /* Generate some randomly sized pubkeys. */
    size_t len = secp256k1_rand_bits(2) == 0 ? 65 : 33;
    if (secp256k1_rand_bits(2) == 0) {
        len = secp256k1_rand_bits(6);
    }
    if (len == 65) {
      in[0] = secp256k1_rand_bits(1) ? 4 : (secp256k1_rand_bits(1) ? 6 : 7);
    } else {
      in[0] = secp256k1_rand_bits(1) ? 2 : 3;
    }
    if (secp256k1_rand_bits(3) == 0) {
        in[0] = secp256k1_rand_bits(8);
    }
    if (len > 1) {
        secp256k1_rand256(&in[1]);
    }
    if (len > 33) {
        secp256k1_rand256(&in[33]);
    }
    if (secp256k1_eckey_pubkey_parse(&elem, in, len)) {
        unsigned char out[65];
        unsigned char firstb;
        int res;
        size_t size = len;
        firstb = in[0];
        /* If the pubkey can be parsed, it should round-trip... */
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, out, &size, len == 33));
        CHECK(size == len);
        CHECK(memcmp(&in[1], &out[1], len-1) == 0);
        /* ... except for the type of hybrid inputs. */
        if ((in[0] != 6) && (in[0] != 7)) {
            CHECK(in[0] == out[0]);
        }
        size = 65;
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, in, &size, 0));
        CHECK(size == 65);
        CHECK(secp256k1_eckey_pubkey_parse(&elem2, in, size));
        ge_equals_ge(&elem,&elem2);
        /* Check that the X9.62 hybrid type is checked. */
        in[0] = secp256k1_rand_bits(1) ? 6 : 7;
        res = secp256k1_eckey_pubkey_parse(&elem2, in, size);
        if (firstb == 2 || firstb == 3) {
            if (in[0] == firstb + 4) {
              CHECK(res);
            } else {
              CHECK(!res);
            }
        }
        if (res) {
            ge_equals_ge(&elem,&elem2);
            CHECK(secp256k1_eckey_pubkey_serialize(&elem, out, &size, 0));
            CHECK(memcmp(&in[1], &out[1], 64) == 0);
        }
    }
}

func run_random_pubkeys() {
    for i in 0 ..< 10*g_count {
        test_random_pubkeys();
    }
}

func run_ecdsa_end_to_end() {
    for i in 0 ..< 64*g_count {
        test_ecdsa_end_to_end();
    }
}

func test_ecdsa_der_parse(_ sig: [UInt8], _ siglen: UInt, _ certainly_der: Int, _ certainly_not_der: Int) -> Bool {
    static const unsigned char zeroes[32] = {0};
#if ENABLE_OPENSSL_TESTS
    static const unsigned char max_scalar[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
    };
#endif

    int ret = 0;

    secp256k1_ecdsa_signature sig_der;
    unsigned char roundtrip_der[2048];
    unsigned char compact_der[64];
    size_t len_der = 2048;
    int parsed_der = 0, valid_der = 0, roundtrips_der = 0;

    secp256k1_ecdsa_signature sig_der_lax;
    unsigned char roundtrip_der_lax[2048];
    unsigned char compact_der_lax[64];
    size_t len_der_lax = 2048;
    int parsed_der_lax = 0, valid_der_lax = 0, roundtrips_der_lax = 0;

#if ENABLE_OPENSSL_TESTS
    ECDSA_SIG *sig_openssl;
    const unsigned char *sigptr;
    unsigned char roundtrip_openssl[2048];
    int len_openssl = 2048;
    int parsed_openssl, valid_openssl = 0, roundtrips_openssl = 0;
#endif

    parsed_der = secp256k1_ecdsa_signature_parse_der(ctx, &sig_der, sig, siglen);
    if (parsed_der) {
        ret |= (!secp256k1_ecdsa_signature_serialize_compact(ctx, compact_der, &sig_der)) << 0;
        valid_der = (memcmp(compact_der, zeroes, 32) != 0) && (memcmp(compact_der + 32, zeroes, 32) != 0);
    }
    if (valid_der) {
        ret |= (!secp256k1_ecdsa_signature_serialize_der(ctx, roundtrip_der, &len_der, &sig_der)) << 1;
        roundtrips_der = (len_der == siglen) && memcmp(roundtrip_der, sig, siglen) == 0;
    }

    parsed_der_lax = ecdsa_signature_parse_der_lax(ctx, &sig_der_lax, sig, siglen);
    if (parsed_der_lax) {
        ret |= (!secp256k1_ecdsa_signature_serialize_compact(ctx, compact_der_lax, &sig_der_lax)) << 10;
        valid_der_lax = (memcmp(compact_der_lax, zeroes, 32) != 0) && (memcmp(compact_der_lax + 32, zeroes, 32) != 0);
    }
    if (valid_der_lax) {
        ret |= (!secp256k1_ecdsa_signature_serialize_der(ctx, roundtrip_der_lax, &len_der_lax, &sig_der_lax)) << 11;
        roundtrips_der_lax = (len_der_lax == siglen) && memcmp(roundtrip_der_lax, sig, siglen) == 0;
    }

    if (certainly_der) {
        ret |= (!parsed_der) << 2;
    }
    if (certainly_not_der) {
        ret |= (parsed_der) << 17;
    }
    if (valid_der) {
        ret |= (!roundtrips_der) << 3;
    }

    if (valid_der) {
        ret |= (!roundtrips_der_lax) << 12;
        ret |= (len_der != len_der_lax) << 13;
        ret |= (memcmp(roundtrip_der_lax, roundtrip_der, len_der) != 0) << 14;
    }
    ret |= (roundtrips_der != roundtrips_der_lax) << 15;
    if (parsed_der) {
        ret |= (!parsed_der_lax) << 16;
    }

#if ENABLE_OPENSSL_TESTS
    sig_openssl = ECDSA_SIG_new();
    sigptr = sig;
    parsed_openssl = (d2i_ECDSA_SIG(&sig_openssl, &sigptr, siglen) != NULL);
    if (parsed_openssl) {
        valid_openssl = !BN_is_negative(sig_openssl.r) && !BN_is_negative(sig_openssl.s) && BN_num_bits(sig_openssl.r) > 0 && BN_num_bits(sig_openssl.r) <= 256 && BN_num_bits(sig_openssl.s) > 0 && BN_num_bits(sig_openssl.s) <= 256;
        if (valid_openssl) {
            unsigned char tmp[32] = {0};
            BN_bn2bin(sig_openssl.r, tmp + 32 - BN_num_bytes(sig_openssl.r));
            valid_openssl = memcmp(tmp, max_scalar, 32) < 0;
        }
        if (valid_openssl) {
            unsigned char tmp[32] = {0};
            BN_bn2bin(sig_openssl.s, tmp + 32 - BN_num_bytes(sig_openssl.s));
            valid_openssl = memcmp(tmp, max_scalar, 32) < 0;
        }
    }
    len_openssl = i2d_ECDSA_SIG(sig_openssl, NULL);
    if (len_openssl <= 2048) {
        unsigned char *ptr = roundtrip_openssl;
        CHECK(i2d_ECDSA_SIG(sig_openssl, &ptr) == len_openssl);
        roundtrips_openssl = valid_openssl && ((size_t)len_openssl == siglen) && (memcmp(roundtrip_openssl, sig, siglen) == 0);
    } else {
        len_openssl = 0;
    }
    ECDSA_SIG_free(sig_openssl);

    ret |= (parsed_der && !parsed_openssl) << 4;
    ret |= (valid_der && !valid_openssl) << 5;
    ret |= (roundtrips_openssl && !parsed_der) << 6;
    ret |= (roundtrips_der != roundtrips_openssl) << 7;
    if (roundtrips_openssl) {
        ret |= (len_der != (size_t)len_openssl) << 8;
        ret |= (memcmp(roundtrip_der, roundtrip_openssl, len_der) != 0) << 9;
    }
#endif
    return ret;
}

func assign_big_endian(_ ptr: inout [UInt8], _ ptrlen: UInt, _ val: UInt32) {
    //size_t i
    for i in 0 ..< ptrlen {
        int shift = ptrlen - 1 - i;
        if (shift >= 4) {
            ptr[i] = 0;
        } else {
            ptr[i] = (val >> shift) & 0xFF;
        }
    }
}

func damage_array(_ sig: inout [UInt8], _ len: inout UInt) {
    int pos;
    int action = secp256k1_rand_bits(3);
    if (action < 1 && *len > 3) {
        /* Delete a byte. */
        pos = secp256k1_rand_int(*len);
        memmove(sig + pos, sig + pos + 1, *len - pos - 1);
        (*len)--;
        return;
    } else if (action < 2 && *len < 2048) {
        /* Insert a byte. */
        pos = secp256k1_rand_int(1 + *len);
        memmove(sig + pos + 1, sig + pos, *len - pos);
        sig[pos] = secp256k1_rand_bits(8);
        (*len)++;
        return;
    } else if (action < 4) {
        /* Modify a byte. */
        sig[secp256k1_rand_int(*len)] += 1 + secp256k1_rand_int(255);
        return;
    } else { /* action < 8 */
        /* Modify a bit. */
        sig[secp256k1_rand_int(*len)] ^= 1 << secp256k1_rand_bits(3);
        return;
    }
}

func random_ber_signature(_ sig: inout [UInt8], _ len: inout UInt, int* certainly_der, int* certainly_not_der) {
    int der;
    int nlow[2], nlen[2], nlenlen[2], nhbit[2], nhbyte[2], nzlen[2];
    size_t tlen, elen, glen;
    int indet;
    int n;

    *len = 0;
    der = secp256k1_rand_bits(2) == 0;
    *certainly_der = der;
    *certainly_not_der = 0;
    indet = der ? 0 : secp256k1_rand_int(10) == 0;

    for (n = 0; n < 2; n++) {
        /* We generate two classes of numbers: nlow==1 "low" ones (up to 32 bytes), nlow==0 "high" ones (32 bytes with 129 top bits set, or larger than 32 bytes) */
        nlow[n] = der ? 1 : (secp256k1_rand_bits(3) != 0);
        /* The length of the number in bytes (the first byte of which will always be nonzero) */
        nlen[n] = nlow[n] ? secp256k1_rand_int(33) : 32 + secp256k1_rand_int(200) * secp256k1_rand_int(8) / 8;
        CHECK(nlen[n] <= 232);
        /* The top bit of the number. */
        nhbit[n] = (nlow[n] == 0 && nlen[n] == 32) ? 1 : (nlen[n] == 0 ? 0 : secp256k1_rand_bits(1));
        /* The top byte of the number (after the potential hardcoded 16 0xFF characters for "high" 32 bytes numbers) */
        nhbyte[n] = nlen[n] == 0 ? 0 : (nhbit[n] ? 128 + secp256k1_rand_bits(7) : 1 + secp256k1_rand_int(127));
        /* The number of zero bytes in front of the number (which is 0 or 1 in case of DER, otherwise we extend up to 300 bytes) */
        nzlen[n] = der ? ((nlen[n] == 0 || nhbit[n]) ? 1 : 0) : (nlow[n] ? secp256k1_rand_int(3) : secp256k1_rand_int(300 - nlen[n]) * secp256k1_rand_int(8) / 8);
        if (nzlen[n] > ((nlen[n] == 0 || nhbit[n]) ? 1 : 0)) {
            *certainly_not_der = 1;
        }
        CHECK(nlen[n] + nzlen[n] <= 300);
        /* The length of the length descriptor for the number. 0 means short encoding, anything else is long encoding. */
        nlenlen[n] = nlen[n] + nzlen[n] < 128 ? 0 : (nlen[n] + nzlen[n] < 256 ? 1 : 2);
        if (!der) {
            /* nlenlen[n] max 127 bytes */
            int add = secp256k1_rand_int(127 - nlenlen[n]) * secp256k1_rand_int(16) * secp256k1_rand_int(16) / 256;
            nlenlen[n] += add;
            if (add != 0) {
                *certainly_not_der = 1;
            }
        }
        CHECK(nlen[n] + nzlen[n] + nlenlen[n] <= 427);
    }

    /* The total length of the data to go, so far */
    tlen = 2 + nlenlen[0] + nlen[0] + nzlen[0] + 2 + nlenlen[1] + nlen[1] + nzlen[1];
    CHECK(tlen <= 856);

    /* The length of the garbage inside the tuple. */
    elen = (der || indet) ? 0 : secp256k1_rand_int(980 - tlen) * secp256k1_rand_int(8) / 8;
    if (elen != 0) {
        *certainly_not_der = 1;
    }
    tlen += elen;
    CHECK(tlen <= 980);

    /* The length of the garbage after the end of the tuple. */
    glen = der ? 0 : secp256k1_rand_int(990 - tlen) * secp256k1_rand_int(8) / 8;
    if (glen != 0) {
        *certainly_not_der = 1;
    }
    CHECK(tlen + glen <= 990);

    /* Write the tuple header. */
    sig[(*len)++] = 0x30;
    if (indet) {
        /* Indeterminate length */
        sig[(*len)++] = 0x80;
        *certainly_not_der = 1;
    } else {
        int tlenlen = tlen < 128 ? 0 : (tlen < 256 ? 1 : 2);
        if (!der) {
            int add = secp256k1_rand_int(127 - tlenlen) * secp256k1_rand_int(16) * secp256k1_rand_int(16) / 256;
            tlenlen += add;
            if (add != 0) {
                *certainly_not_der = 1;
            }
        }
        if (tlenlen == 0) {
            /* Short length notation */
            sig[(*len)++] = tlen;
        } else {
            /* Long length notation */
            sig[(*len)++] = 128 + tlenlen;
            assign_big_endian(sig + *len, tlenlen, tlen);
            *len += tlenlen;
        }
        tlen += tlenlen;
    }
    tlen += 2;
    CHECK(tlen + glen <= 1119);

    for (n = 0; n < 2; n++) {
        /* Write the integer header. */
        sig[(*len)++] = 0x02;
        if (nlenlen[n] == 0) {
            /* Short length notation */
            sig[(*len)++] = nlen[n] + nzlen[n];
        } else {
            /* Long length notation. */
            sig[(*len)++] = 128 + nlenlen[n];
            assign_big_endian(sig + *len, nlenlen[n], nlen[n] + nzlen[n]);
            *len += nlenlen[n];
        }
        /* Write zero padding */
        while (nzlen[n] > 0) {
            sig[(*len)++] = 0x00;
            nzlen[n]--;
        }
        if (nlen[n] == 32 && !nlow[n]) {
            /* Special extra 16 0xFF bytes in "high" 32-byte numbers */
            int i;
            for (i = 0; i < 16; i++) {
                sig[(*len)++] = 0xFF;
            }
            nlen[n] -= 16;
        }
        /* Write first byte of number */
        if (nlen[n] > 0) {
            sig[(*len)++] = nhbyte[n];
            nlen[n]--;
        }
        /* Generate remaining random bytes of number */
        secp256k1_rand_bytes_test(sig + *len, nlen[n]);
        *len += nlen[n];
        nlen[n] = 0;
    }

    /* Generate random garbage inside tuple. */
    secp256k1_rand_bytes_test(sig + *len, elen);
    *len += elen;

    /* Generate end-of-contents bytes. */
    if (indet) {
        sig[(*len)++] = 0;
        sig[(*len)++] = 0;
        tlen += 2;
    }
    CHECK(tlen + glen <= 1121);

    /* Generate random garbage outside tuple. */
    secp256k1_rand_bytes_test(sig + *len, glen);
    *len += glen;
    tlen += glen;
    CHECK(tlen <= 1121);
    CHECK(tlen == *len);
}

func run_ecdsa_der_parse() {
    //int i,j;
    for i in  0 .. < 200 * g_count {
        unsigned char buffer[2048];
        size_t buflen = 0;
        int certainly_der = 0;
        int certainly_not_der = 0;
        random_ber_signature(buffer, &buflen, &certainly_der, &certainly_not_der);
        CHECK(buflen <= 2048);
        for j in 0 ..< 16 {
            int ret = 0;
            if (j > 0) {
                damage_array(buffer, &buflen);
                /* We don't know anything anymore about the DERness of the result */
                certainly_der = 0;
                certainly_not_der = 0;
            }
            ret = test_ecdsa_der_parse(buffer, buflen, certainly_der, certainly_not_der);
            if (ret != 0) {
                size_t k;
                fprintf(stderr, "Failure %x on ", ret);
                for (k = 0; k < buflen; k++) {
                    fprintf(stderr, "%02x ", buffer[k]);
                }
                fprintf(stderr, "\n");
            }
            CHECK(ret == 0);
        }
    }
}

/* Tests several edge cases. */
void test_ecdsa_edge_cases(void) {
    int t;
    secp256k1_ecdsa_signature sig;

    /* Test the case where ECDSA recomputes a point that is infinity. */
    {
        secp256k1_gej keyj;
        secp256k1_ge key;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_negate(&ss, &ss);
        secp256k1_scalar_inverse(&ss, &ss);
        secp256k1_scalar_set_int(&sr, 1);
        secp256k1_ecmult_gen(&ctx.ecmult_gen_ctx, &keyj, &sr);
        secp256k1_ge_set_gej(&key, &keyj);
        msg = ss;
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
    }

    /* Verify signature with r of zero fails. */
    {
        const unsigned char pubkey_mods_zero[33] = {
            0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0,
            0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
            0x41
        };
        secp256k1_ge key;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 0);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey_mods_zero, 33));
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
    }

    /* Verify signature with s of zero fails. */
    {
        const unsigned char pubkey[33] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01
        };
        secp256k1_ge key;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 0);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 1);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
    }

    /* Verify signature with message 0 passes. */
    {
        const unsigned char pubkey[33] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02
        };
        const unsigned char pubkey2[33] = {
            0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0,
            0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
            0x43
        };
        secp256k1_ge key;
        secp256k1_ge key2;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 2);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 2);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_eckey_pubkey_parse(&key2, pubkey2, 33));
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 1);
        secp256k1_scalar_negate(&ss, &ss);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 1);
        secp256k1_scalar_set_int(&ss, 1);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 0);
    }

    /* Verify signature with message 1 passes. */
    {
        const unsigned char pubkey[33] = {
            0x02, 0x14, 0x4e, 0x5a, 0x58, 0xef, 0x5b, 0x22,
            0x6f, 0xd2, 0xe2, 0x07, 0x6a, 0x77, 0xcf, 0x05,
            0xb4, 0x1d, 0xe7, 0x4a, 0x30, 0x98, 0x27, 0x8c,
            0x93, 0xe6, 0xe6, 0x3c, 0x0b, 0xc4, 0x73, 0x76,
            0x25
        };
        const unsigned char pubkey2[33] = {
            0x02, 0x8a, 0xd5, 0x37, 0xed, 0x73, 0xd9, 0x40,
            0x1d, 0xa0, 0x33, 0xd2, 0xdc, 0xf0, 0xaf, 0xae,
            0x34, 0xcf, 0x5f, 0x96, 0x4c, 0x73, 0x28, 0x0f,
            0x92, 0xc0, 0xf6, 0x9d, 0xd9, 0xb2, 0x09, 0x10,
            0x62
        };
        const unsigned char csr[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
            0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xeb
        };
        secp256k1_ge key;
        secp256k1_ge key2;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 1);
        secp256k1_scalar_set_b32(&sr, csr, NULL);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_eckey_pubkey_parse(&key2, pubkey2, 33));
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 1);
        secp256k1_scalar_negate(&ss, &ss);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 1);
        secp256k1_scalar_set_int(&ss, 2);
        secp256k1_scalar_inverse_var(&ss, &ss);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key2, &msg) == 0);
    }

    /* Verify signature with message -1 passes. */
    {
        const unsigned char pubkey[33] = {
            0x03, 0xaf, 0x97, 0xff, 0x7d, 0x3a, 0xf6, 0xa0,
            0x02, 0x94, 0xbd, 0x9f, 0x4b, 0x2e, 0xd7, 0x52,
            0x28, 0xdb, 0x49, 0x2a, 0x65, 0xcb, 0x1e, 0x27,
            0x57, 0x9c, 0xba, 0x74, 0x20, 0xd5, 0x1d, 0x20,
            0xf1
        };
        const unsigned char csr[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
            0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee
        };
        secp256k1_ge key;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 1);
        secp256k1_scalar_negate(&msg, &msg);
        secp256k1_scalar_set_b32(&sr, csr, NULL);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        secp256k1_scalar_negate(&ss, &ss);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 1);
        secp256k1_scalar_set_int(&ss, 3);
        secp256k1_scalar_inverse_var(&ss, &ss);
        CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sr, &ss, &key, &msg) == 0);
    }

    /* Signature where s would be zero. */
    {
        secp256k1_pubkey pubkey;
        size_t siglen;
        int32_t ecount;
        unsigned char signature[72];
        static const unsigned char nonce[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        static const unsigned char nonce2[32] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
        };
        const unsigned char key[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        unsigned char msg[32] = {
            0x86, 0x41, 0x99, 0x81, 0x06, 0x23, 0x44, 0x53,
            0xaa, 0x5f, 0x9d, 0x6a, 0x31, 0x78, 0xf4, 0xf7,
            0xb8, 0x12, 0xe0, 0x0b, 0x81, 0x7a, 0x77, 0x62,
            0x65, 0xdf, 0xdd, 0x31, 0xb9, 0x3e, 0x29, 0xa9,
        };
        ecount = 0;
        secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == 0);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == 0);
        msg[31] = 0xaa;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_ecdsa_sign(ctx, NULL, msg, key, precomputed_nonce_function, nonce2) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, NULL, key, precomputed_nonce_function, nonce2) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, NULL, precomputed_nonce_function, nonce2) == 0);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == 1);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, key) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, NULL, msg, &pubkey) == 0);
        CHECK(ecount == 4);
        CHECK(secp256k1_ecdsa_verify(ctx, &sig, NULL, &pubkey) == 0);
        CHECK(ecount == 5);
        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, NULL) == 0);
        CHECK(ecount == 6);
        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) == 1);
        CHECK(ecount == 6);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, NULL) == 0);
        CHECK(ecount == 7);
        /* That pubkeyload fails via an ARGCHECK is a little odd but makes sense because pubkeys are an opaque data type. */
        CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) == 0);
        CHECK(ecount == 8);
        siglen = 72;
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, NULL, &siglen, &sig) == 0);
        CHECK(ecount == 9);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, NULL, &sig) == 0);
        CHECK(ecount == 10);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, NULL) == 0);
        CHECK(ecount == 11);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &sig) == 1);
        CHECK(ecount == 11);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, NULL, signature, siglen) == 0);
        CHECK(ecount == 12);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, NULL, siglen) == 0);
        CHECK(ecount == 13);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, signature, siglen) == 1);
        CHECK(ecount == 13);
        siglen = 10;
        /* Too little room for a signature does not fail via ARGCHECK. */
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &sig) == 0);
        CHECK(ecount == 13);
        ecount = 0;
        CHECK(secp256k1_ecdsa_signature_normalize(ctx, NULL, NULL) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, NULL, &sig) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, signature, NULL) == 0);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig) == 1);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, NULL, signature) == 0);
        CHECK(ecount == 4);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, NULL) == 0);
        CHECK(ecount == 5);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature) == 1);
        CHECK(ecount == 5);
        memset(signature, 255, 64);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature) == 0);
        CHECK(ecount == 5);
        secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
    }

    /* Nonce function corner cases. */
    for (t = 0; t < 2; t++) {
        static const unsigned char zero[32] = {0x00};
        int i;
        unsigned char key[32];
        unsigned char msg[32];
        secp256k1_ecdsa_signature sig2;
        secp256k1_scalar sr[512], ss;
        const unsigned char *extra;
        extra = t == 0 ? NULL : zero;
        memset(msg, 0, 32);
        msg[31] = 1;
        /* High key results in signature failure. */
        memset(key, 0xFF, 32);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, NULL, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* Zero key results in signature failure. */
        memset(key, 0, 32);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, NULL, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* Nonce function failure results in signature failure. */
        key[31] = 1;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_fail, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* The retry loop successfully makes its way to the first good value. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_retry, extra) == 1);
        CHECK(!is_empty_signature(&sig));
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nonce_function_rfc6979, extra) == 1);
        CHECK(!is_empty_signature(&sig2));
        CHECK(memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function is deterministic. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
        CHECK(!is_empty_signature(&sig2));
        CHECK(memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function changes output with different messages. */
        for(i = 0; i < 256; i++) {
            int j;
            msg[0] = i;
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
            CHECK(!is_empty_signature(&sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, &sig2);
            for (j = 0; j < i; j++) {
                CHECK(!secp256k1_scalar_eq(&sr[i], &sr[j]));
            }
        }
        msg[0] = 0;
        msg[31] = 2;
        /* The default nonce function changes output with different keys. */
        for(i = 256; i < 512; i++) {
            int j;
            key[0] = i - 256;
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
            CHECK(!is_empty_signature(&sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, &sig2);
            for (j = 0; j < i; j++) {
                CHECK(!secp256k1_scalar_eq(&sr[i], &sr[j]));
            }
        }
        key[0] = 0;
    }

    {
        /* Check that optional nonce arguments do not have equivalent effect. */
        const unsigned char zeros[32] = {0};
        unsigned char nonce[32];
        unsigned char nonce2[32];
        unsigned char nonce3[32];
        unsigned char nonce4[32];
        //VG_UNDEF(nonce,32);
        //VG_UNDEF(nonce2,32);
        //VG_UNDEF(nonce3,32);
        //VG_UNDEF(nonce4,32);
        CHECK(nonce_function_rfc6979(nonce, zeros, zeros, NULL, NULL, 0) == 1);
        VG_CHECK(nonce,32);
        CHECK(nonce_function_rfc6979(nonce2, zeros, zeros, zeros, NULL, 0) == 1);
        VG_CHECK(nonce2,32);
        CHECK(nonce_function_rfc6979(nonce3, zeros, zeros, NULL, (void *)zeros, 0) == 1);
        VG_CHECK(nonce3,32);
        CHECK(nonce_function_rfc6979(nonce4, zeros, zeros, zeros, (void *)zeros, 0) == 1);
        VG_CHECK(nonce4,32);
        CHECK(memcmp(nonce, nonce2, 32) != 0);
        CHECK(memcmp(nonce, nonce3, 32) != 0);
        CHECK(memcmp(nonce, nonce4, 32) != 0);
        CHECK(memcmp(nonce2, nonce3, 32) != 0);
        CHECK(memcmp(nonce2, nonce4, 32) != 0);
        CHECK(memcmp(nonce3, nonce4, 32) != 0);
    }


    /* Privkey export where pubkey is the point at infinity. */
    {
        unsigned char privkey[300];
        unsigned char seckey[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        };
        size_t outlen = 300;
        CHECK(!ec_privkey_export_der(ctx, privkey, &outlen, seckey, 0));
        outlen = 300;
        CHECK(!ec_privkey_export_der(ctx, privkey, &outlen, seckey, 1));
    }
}

func run_ecdsa_edge_cases() {
    test_ecdsa_edge_cases()
}

#if ENABLE_OPENSSL_TESTS
EC_KEY *get_openssl_key(_ key32: [UInt8]) {
    unsigned char privkey[300];
    size_t privkeylen;
    const unsigned char* pbegin = privkey;
    int compr = secp256k1_rand_bits(1);
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    CHECK(ec_privkey_export_der(ctx, privkey, &privkeylen, key32, compr));
    CHECK(d2i_ECPrivateKey(&ec_key, &pbegin, privkeylen));
    CHECK(EC_KEY_check_key(ec_key));
    return ec_key;
}

func test_ecdsa_openssl() {
    secp256k1_gej qj;
    secp256k1_ge q;
    secp256k1_scalar sigr, sigs;
    secp256k1_scalar one;
    secp256k1_scalar msg2;
    secp256k1_scalar key, msg;
    EC_KEY *ec_key;
    unsigned int sigsize = 80;
    size_t secp_sigsize = 80;
    unsigned char message[32];
    unsigned char signature[80];
    unsigned char key32[32];
    secp256k1_rand256_test(message);
    secp256k1_scalar_set_b32(&msg, message, NULL);
    random_scalar_order_test(&key);
    secp256k1_scalar_get_b32(key32, &key);
    secp256k1_ecmult_gen(&ctx.ecmult_gen_ctx, &qj, &key);
    secp256k1_ge_set_gej(&q, &qj);
    ec_key = get_openssl_key(key32);
    CHECK(ec_key != NULL);
    CHECK(ECDSA_sign(0, message, sizeof(message), signature, &sigsize, ec_key));
    CHECK(secp256k1_ecdsa_sig_parse(&sigr, &sigs, signature, sigsize));
    CHECK(secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sigr, &sigs, &q, &msg));
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_add(&msg2, &msg, &one);
    CHECK(!secp256k1_ecdsa_sig_verify(&ctx.ecmult_ctx, &sigr, &sigs, &q, &msg2));

    random_sign(&sigr, &sigs, &key, &msg, NULL);
    CHECK(secp256k1_ecdsa_sig_serialize(signature, &secp_sigsize, &sigr, &sigs));
    CHECK(ECDSA_verify(0, message, sizeof(message), signature, secp_sigsize, ec_key) == 1);

    EC_KEY_free(ec_key);
}

func run_ecdsa_openssl() {
    for i in 0 ..< 10*g_count {
        test_ecdsa_openssl()
    }
}
#endif

/*
#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/tests_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/tests_impl.h"
#endif
 */
*/

func test_main(_ count: Int, _ ch:String?) {
    var seed16 = [UInt8](repeating: 0, count:16)
    var run32 = [UInt8](repeating: 0, count:32)
    /* find iteration count */
    /*
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    }
     */
    
    /* find random seed */
    //if (argc > 2) {
    if let ch = ch {
        seed16 = ch.unhexlify()
        /*
        var pos: Int = 0
        //const char* ch = argv[2];
        while (pos < 16 && ch[0] != 0 && ch[1] != 0) {
            var sh: UInt16 //unsigned short sh;
            if (sscanf(ch, "%2hx", &sh)) {
                seed16[pos] = sh;
            } else {
                break;
            }
            ch += 2
            pos += 1
        }
        */
        assert(seed16.count == 16)
    } else {
        let frand: UnsafeMutablePointer<FILE>? = fopen("/dev/urandom", "r");
        
        if (frand == nil || fread(&seed16, seed16.count, 1, frand) == 0 ) {
            let t: UInt64 = UInt64(time(nil)) * UInt64(1337)
            seed16[0] ^= UInt8(t)
            seed16[1] ^= UInt8(t >> 8)
            seed16[2] ^= UInt8(t >> 16)
            seed16[3] ^= UInt8(t >> 24)
            seed16[4] ^= UInt8(t >> 32)
            seed16[5] ^= UInt8(t >> 40)
            seed16[6] ^= UInt8(t >> 48)
            seed16[7] ^= UInt8(t >> 56)
        }
        fclose(frand);
    }
    secp256k1_rand_seed(seed16);
    
    print(String(format: "test count = %i\n", count))
    print(String(format: "random seed = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", seed16[0], seed16[1], seed16[2], seed16[3], seed16[4], seed16[5], seed16[6], seed16[7], seed16[8], seed16[9], seed16[10], seed16[11], seed16[12], seed16[13], seed16[14], seed16[15]))
    
    /* initialize */
    /*
    run_context_tests();
     */
    /* TODO
    ctx = secp256k1_context_create([SECP256K1_FLAGS.SECP256K1_CONTEXT_SIGN, SECP256K1_FLAGS.SECP256K1_CONTEXT_VERIFY])
    if (secp256k1_rand_bits(1)) {
        secp256k1_rand256(run32);
        CHECK(secp256k1_context_randomize(ctx, secp256k1_rand_bits(1) ? run32 : nil))
    }
     */
    /*
    run_rand_bits(); // pass
    run_rand_int(); // pass

    run_sha256_tests(); // pass
    run_hmac_sha256_tests(); // pass
    run_rfc6979_hmac_sha256_tests(); // pass
     */

    /*
     #ifndef USE_NUM_NONE
     /* num tests */
     run_num_smalltests();
     #endif
     */
    
    /* scalar tests */
    run_scalar_tests(); // pass

    /* field tests */
    /*
    run_field_inv(); // pass
    run_field_inv_var(); // pass
    run_field_inv_all_var(); // pass
    run_field_misc(); // pass
    run_field_convert(); // pass
    run_sqr(); // pass
    run_sqrt(); // pass
     */

    /* group tests */
    /*
    run_ge(); // pass
 */
    /*
    run_group_decompress();
     */
    
    /* ecmult tests */
    run_wnaf(); // fail
    /*
    run_point_times_order();
    run_ecmult_chain();
     */
    run_ecmult_constants();
    run_ecmult_gen_blind();
    /*
    run_ecmult_const_tests();
     */
    
    run_ec_combine();
    /*
    /* endomorphism tests */
    #if USE_ENDOMORPHISM
        run_endomorphism_tests();
    #endif
    
    /* EC point parser test */
    run_ec_pubkey_parse_test();
    
    /* EC key edge cases */
    run_eckey_edge_case_test();
    
    #if ENABLE_MODULE_ECDH
        /* ecdh tests */
        run_ecdh_tests();
    #endif
    
    /* ecdsa tests */
    run_random_pubkeys();
    run_ecdsa_der_parse();
    run_ecdsa_sign_verify();
    run_ecdsa_end_to_end();
    run_ecdsa_edge_cases();
    #if ENABLE_OPENSSL_TESTS
        run_ecdsa_openssl()
    #endif
    
    #if ENABLE_MODULE_RECOVERY
        /* ECDSA pubkey recovery tests */
        run_recovery_tests();
    #endif
    
    secp256k1_rand256(run32);
    print("random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]);
    
    /* shutdown */
    secp256k1_context_destroy(ctx);
    */ // TODO
}
