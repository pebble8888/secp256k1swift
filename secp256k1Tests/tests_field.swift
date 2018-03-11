//
//  tests_field.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/11.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation
@testable import secp256k1

/***** FIELD TESTS *****/
func random_fe(_ x: inout secp256k1_fe) {
    //unsigned char bin[32];
    var bin = [UInt8](repeating: 0, count: 32)
    repeat {
        secp256k1_rand256(&bin);
        if (secp256k1_fe_set_b32(&x, bin)) {
            return;
        }
    } while true
}
/*
func random_fe_test(_ x: inout secp256k1_fe) {
    unsigned char bin[32];
    do {
        secp256k1_rand256_test(bin);
        if (secp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}
 */
 
func random_fe_non_zero(_ nz: inout secp256k1_fe) {
    var tries: Int = 10;
    tries -= 1
    while (tries >= 0) {
        random_fe(&nz);
        secp256k1_fe_normalize(&nz);
        if (!secp256k1_fe_is_zero(nz)) {
            break;
        }
        tries -= 1
    }
    /* Infinitesimal probability of spurious failure here */
    CHECK(tries >= 0);
}

func random_fe_non_square(_ ns: inout secp256k1_fe) {
    var r = secp256k1_fe()
    random_fe_non_zero(&ns);
    if (secp256k1_fe_sqrt(&r, ns)) {
        secp256k1_fe_negate(&ns, ns, 1);
    }
}

func check_fe_equal(_ a: secp256k1_fe, _ b: secp256k1_fe) -> Bool {
    var an: secp256k1_fe = a
    var bn: secp256k1_fe = b
    secp256k1_fe_normalize_weak(&an)
    secp256k1_fe_normalize_var(&bn)
    return secp256k1_fe_equal_var(an, bn)
}

func check_fe_inverse(_ a: secp256k1_fe, _ ai: secp256k1_fe) -> Bool {
    var x = secp256k1_fe()
    let one: secp256k1_fe = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1)
    secp256k1_fe_mul(&x, a, ai)
    return check_fe_equal(x, one)
}
func run_field_convert() {
    let b32:[UInt8] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40
    ]
    let fes: secp256k1_fe_storage = SECP256K1_FE_STORAGE_CONST(
        0x00010203, 0x04050607, 0x11121314, 0x15161718,
        0x22232425, 0x26272829, 0x33343536, 0x37383940
    );
    let fe: secp256k1_fe = SECP256K1_FE_CONST(
        0x00010203, 0x04050607, 0x11121314, 0x15161718,
        0x22232425, 0x26272829, 0x33343536, 0x37383940
    );
    var fe2 = secp256k1_fe()
    var b322 = [UInt8](repeating: 0, count: 32)
    var fes2 = secp256k1_fe_storage()
    /* Check conversions to fe. */
    CHECK(secp256k1_fe_set_b32(&fe2, b32));
    CHECK(secp256k1_fe_equal_var(fe, fe2));
    secp256k1_fe_from_storage(&fe2, fes);
    CHECK(secp256k1_fe_equal_var(fe, fe2));
    /* Check conversion from fe. */
    secp256k1_fe_get_b32(&b322, fe);
    CHECK(b322.elementsEqual(b32));
    secp256k1_fe_to_storage(&fes2, fe);
    CHECK(fes2.equal(fes))
}

func fe_memcmp(_ a: secp256k1_fe, _ b: secp256k1_fe) -> Int {
    var t: secp256k1_fe = b
#if VERIFY
    t.magnitude = a.magnitude;
    t.normalized = a.normalized;
#endif
    //return memcmp(a, &t, sizeof(secp256k1_fe));
    return a.equal(t) ? 0 : 1
}

func run_field_misc() {
    var x = secp256k1_fe()
    var y = secp256k1_fe()
    var z = secp256k1_fe()
    var q = secp256k1_fe()
    let fe5: secp256k1_fe = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 5)
    for i in 0 ..< 5*g_count {
        var xs = secp256k1_fe_storage()
        var ys = secp256k1_fe_storage()
        var zs = secp256k1_fe_storage()
        random_fe(&x);
        random_fe_non_zero(&y);
        /* Test the fe equality and comparison operations. */
        CHECK(secp256k1_fe_cmp_var(x, x) == 0);
        CHECK(secp256k1_fe_equal_var(x, x));
        z = x;
        secp256k1_fe_add(&z, y);
        /* Test fe conditional move; z is not normalized here. */
        q = x;
        secp256k1_fe_cmov(&x, z, false);
        VERIFY_CHECK(!x.normalized && x.magnitude == z.magnitude);
        secp256k1_fe_cmov(&x, x, true);
        CHECK(fe_memcmp(x, z) != 0);
        CHECK(fe_memcmp(x, q) == 0);
        secp256k1_fe_cmov(&q, z, true);
        VERIFY_CHECK(!q.normalized && q.magnitude == z.magnitude);
        CHECK(fe_memcmp(q, z) == 0);
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&z);
        CHECK(!secp256k1_fe_equal_var(x, z));
        secp256k1_fe_normalize_var(&q);
        secp256k1_fe_cmov(&q, z, (i&1) != 0);
        VERIFY_CHECK(q.normalized && q.magnitude == 1);
        for j in 0 ..< 6 {
            secp256k1_fe_negate(&z, z, UInt32(j) + 1);
            secp256k1_fe_normalize_var(&q);
            secp256k1_fe_cmov(&q, z, (j&1) != 0);
            VERIFY_CHECK(!q.normalized && q.magnitude == (j+2));
        }
        secp256k1_fe_normalize_var(&z);
        /* Test storage conversion and conditional moves. */
        secp256k1_fe_to_storage(&xs, x);
        secp256k1_fe_to_storage(&ys, y);
        secp256k1_fe_to_storage(&zs, z);
        secp256k1_fe_storage_cmov(&zs, xs, false);
        secp256k1_fe_storage_cmov(&zs, zs, true);
        CHECK(!xs.equal(zs)) // memcmp(&xs, &zs, sizeof(xs)) != 0);
        secp256k1_fe_storage_cmov(&ys, xs, true);
        CHECK(xs.equal(ys)) // memcmp(&xs, &ys, sizeof(xs)) == 0);
        secp256k1_fe_from_storage(&x, xs);
        secp256k1_fe_from_storage(&y, ys);
        secp256k1_fe_from_storage(&z, zs);
        /* Test that mul_int, mul, and add agree. */
        secp256k1_fe_add(&y, x);
        secp256k1_fe_add(&y, x);
        z = x;
        secp256k1_fe_mul_int(&z, 3);
        CHECK(check_fe_equal(y, z));
        secp256k1_fe_add(&y, x);
        secp256k1_fe_add(&z, x);
        CHECK(check_fe_equal(z, y));
        z = x;
        secp256k1_fe_mul_int(&z, 5);
        secp256k1_fe_mul(&q, x, fe5);
        CHECK(check_fe_equal(z, q));
        secp256k1_fe_negate(&x, x, 1);
        secp256k1_fe_add(&z, x);
        secp256k1_fe_add(&q, x);
        CHECK(check_fe_equal(y, z));
        CHECK(check_fe_equal(q, y));
    }
}

func run_field_inv() {
    var x = secp256k1_fe()
    var xi = secp256k1_fe()
    var xii = secp256k1_fe()
    for _ in 0 ..< 10*g_count {
        random_fe_non_zero(&x)
        secp256k1_fe_inv(&xi, x)
        CHECK(check_fe_inverse(x, xi))
        secp256k1_fe_inv(&xii, xi)
        CHECK(check_fe_equal(x, xii))
    }
}
func run_field_inv_var() {
    var x = secp256k1_fe()
    var xi = secp256k1_fe()
    var xii = secp256k1_fe()
    for _ in 0 ..< 10*g_count {
        random_fe_non_zero(&x);
        secp256k1_fe_inv_var(&xi, x);
        CHECK(check_fe_inverse(x, xi));
        secp256k1_fe_inv_var(&xii, xi);
        CHECK(check_fe_equal(x, xii));
    }
}

func run_field_inv_all_var() {
    var x = [secp256k1_fe](repeating: secp256k1_fe() , count: 16)
    var xi = [secp256k1_fe](repeating: secp256k1_fe() , count: 16)
    var xii = [secp256k1_fe](repeating: secp256k1_fe() , count: 16)
    /* Check it's safe to call for 0 elements */
    secp256k1_fe_inv_all_var(&xi, x, 0);
    for _ in 0 ..< g_count {
        let len: Int = Int(secp256k1_rand_int(15)) + 1
        for j in 0 ..< len {
            random_fe_non_zero(&x[j])
        }
        secp256k1_fe_inv_all_var(&xi, x, UInt(len));
        for j in 0 ..< len {
            CHECK(check_fe_inverse(x[j], xi[j]));
        }
        secp256k1_fe_inv_all_var(&xii, xi, UInt(len));
        for j in 0 ..< len {
            CHECK(check_fe_equal(x[j], xii[j]));
        }
    }
}

func run_sqr() {
    var x = secp256k1_fe()
    var s = secp256k1_fe()
    secp256k1_fe_set_int(&x, 1);
    secp256k1_fe_negate(&x, x, 1);

    for _ in 1 ... 512 {
        secp256k1_fe_mul_int(&x, 2);
        secp256k1_fe_normalize(&x);
        secp256k1_fe_sqr(&s, x);
    }
}

func test_sqrt(_ a: secp256k1_fe, _ k: secp256k1_fe?) {
    var r1 = secp256k1_fe()
    var r2 = secp256k1_fe()
    let v: Bool = secp256k1_fe_sqrt(&r1, a)
    CHECK(!v == (k == nil))

    if let k = k {
        /* Check that the returned root is +/- the given known answer */
        secp256k1_fe_negate(&r2, r1, 1);
        secp256k1_fe_add(&r1, k); secp256k1_fe_add(&r2, k);
        secp256k1_fe_normalize(&r1); secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_is_zero(r1) || secp256k1_fe_is_zero(r2));
    }
}

func run_sqrt() {
    var ns = secp256k1_fe()
    var x = secp256k1_fe()
    var s = secp256k1_fe()
    var t = secp256k1_fe()

    /* Check sqrt(0) is 0 */
    secp256k1_fe_set_int(&x, 0);
    secp256k1_fe_sqr(&s, x);
    test_sqrt(s, x);

    /* Check sqrt of small squares (and their negatives) */
    for i in 1 ... 100 {
        secp256k1_fe_set_int(&x, UInt32(i));
        secp256k1_fe_sqr(&s, x);
        test_sqrt(s, x);
        secp256k1_fe_negate(&t, s, 1);
        test_sqrt(t, nil);
    }

    /* Consistency checks for large random values */
    for _ in 0 ..< 10 {
        random_fe_non_square(&ns);
        for _ in 0 ..< g_count {
            random_fe(&x);
            secp256k1_fe_sqr(&s, x);
            test_sqrt(s, x);
            secp256k1_fe_negate(&t, s, 1);
            test_sqrt(t, nil);
            secp256k1_fe_mul(&t, s, ns);
            test_sqrt(t, nil);
        }
    }
}

