//
//  tests_num.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/11.
//  Copyright © 2018年 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation
@testable import secp256k1

/*
/***** NUM TESTS *****/

#ifndef USE_NUM_NONE
func random_num_negate(secp256k1_num *num) {
    if (secp256k1_rand_bits(1) != 0) {
        secp256k1_num_negate(num);
    }
}

func random_num_order_test(secp256k1_num *num) {
    secp256k1_scalar sc;
    random_scalar_order_test(&sc);
    secp256k1_scalar_get_num(num, &sc);
}

func random_num_order(secp256k1_num *num) {
    secp256k1_scalar sc;
    random_scalar_order(&sc);
    secp256k1_scalar_get_num(num, &sc);
}

func test_num_negate(void) {
    secp256k1_num n1;
    secp256k1_num n2;
    random_num_order_test(&n1); /* n1 = R */
    random_num_negate(&n1);
    secp256k1_num_copy(&n2, &n1); /* n2 = R */
    secp256k1_num_sub(&n1, &n2, &n1); /* n1 = n2-n1 = 0 */
    CHECK(secp256k1_num_is_zero(&n1));
    secp256k1_num_copy(&n1, &n2); /* n1 = R */
    secp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(!secp256k1_num_is_zero(&n1));
    secp256k1_num_add(&n1, &n2, &n1); /* n1 = n2+n1 = 0 */
    CHECK(secp256k1_num_is_zero(&n1));
    secp256k1_num_copy(&n1, &n2); /* n1 = R */
    secp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(secp256k1_num_is_neg(&n1) != secp256k1_num_is_neg(&n2));
    secp256k1_num_negate(&n1); /* n1 = R */
    CHECK(secp256k1_num_eq(&n1, &n2));
}

func test_num_add_sub() {
    int i;
    secp256k1_scalar s;
    secp256k1_num n1;
    secp256k1_num n2;
    secp256k1_num n1p2, n2p1, n1m2, n2m1;
    random_num_order_test(&n1); /* n1 = R1 */
    if (secp256k1_rand_bits(1)) {
        random_num_negate(&n1);
    }
    random_num_order_test(&n2); /* n2 = R2 */
    if (secp256k1_rand_bits(1)) {
        random_num_negate(&n2);
    }
    secp256k1_num_add(&n1p2, &n1, &n2); /* n1p2 = R1 + R2 */
    secp256k1_num_add(&n2p1, &n2, &n1); /* n2p1 = R2 + R1 */
    secp256k1_num_sub(&n1m2, &n1, &n2); /* n1m2 = R1 - R2 */
    secp256k1_num_sub(&n2m1, &n2, &n1); /* n2m1 = R2 - R1 */
    CHECK(secp256k1_num_eq(&n1p2, &n2p1));
    CHECK(!secp256k1_num_eq(&n1p2, &n1m2));
    secp256k1_num_negate(&n2m1); /* n2m1 = -R2 + R1 */
    CHECK(secp256k1_num_eq(&n2m1, &n1m2));
    CHECK(!secp256k1_num_eq(&n2m1, &n1));
    secp256k1_num_add(&n2m1, &n2m1, &n2); /* n2m1 = -R2 + R1 + R2 = R1 */
    CHECK(secp256k1_num_eq(&n2m1, &n1));
    CHECK(!secp256k1_num_eq(&n2p1, &n1));
    secp256k1_num_sub(&n2p1, &n2p1, &n2); /* n2p1 = R2 + R1 - R2 = R1 */
    CHECK(secp256k1_num_eq(&n2p1, &n1));

    /* check is_one */
    secp256k1_scalar_set_int(&s, 1);
    secp256k1_scalar_get_num(&n1, &s);
    CHECK(secp256k1_num_is_one(&n1));
    /* check that 2^n + 1 is never 1 */
    secp256k1_scalar_get_num(&n2, &s);
    for (i = 0; i < 250; ++i) {
        secp256k1_num_add(&n1, &n1, &n1);    /* n1 *= 2 */
        secp256k1_num_add(&n1p2, &n1, &n2);  /* n1p2 = n1 + 1 */
        CHECK(!secp256k1_num_is_one(&n1p2));
    }
}

func test_num_mod() {
    int i;
    secp256k1_scalar s;
    secp256k1_num order, n;

    /* check that 0 mod anything is 0 */
    random_scalar_order_test(&s);
    secp256k1_scalar_get_num(&order, &s);
    secp256k1_scalar_set_int(&s, 0);
    secp256k1_scalar_get_num(&n, &s);
    secp256k1_num_mod(&n, &order);
    CHECK(secp256k1_num_is_zero(&n));

    /* check that anything mod 1 is 0 */
    secp256k1_scalar_set_int(&s, 1);
    secp256k1_scalar_get_num(&order, &s);
    secp256k1_scalar_get_num(&n, &s);
    secp256k1_num_mod(&n, &order);
    CHECK(secp256k1_num_is_zero(&n));

    /* check that increasing the number past 2^256 does not break this */
    random_scalar_order_test(&s);
    secp256k1_scalar_get_num(&n, &s);
    /* multiply by 2^8, which'll test this case with high probability */
    for (i = 0; i < 8; ++i) {
        secp256k1_num_add(&n, &n, &n);
    }
    secp256k1_num_mod(&n, &order);
    CHECK(secp256k1_num_is_zero(&n));
}

func test_num_jacobi() {
    secp256k1_scalar sqr;
    secp256k1_scalar small;
    secp256k1_scalar five;  /* five is not a quadratic residue */
    secp256k1_num order, n;
    int i;
    /* squares mod 5 are 1, 4 */
    const int jacobi5[10] = { 0, 1, -1, -1, 1, 0, 1, -1, -1, 1 };

    /* check some small values with 5 as the order */
    secp256k1_scalar_set_int(&five, 5);
    secp256k1_scalar_get_num(&order, &five);
    for (i = 0; i < 10; ++i) {
        secp256k1_scalar_set_int(&small, i);
        secp256k1_scalar_get_num(&n, &small);
        CHECK(secp256k1_num_jacobi(&n, &order) == jacobi5[i]);
    }

    /** test large values with 5 as group order */
    secp256k1_scalar_get_num(&order, &five);
    /* we first need a scalar which is not a multiple of 5 */
    do {
        secp256k1_num fiven;
        random_scalar_order_test(&sqr);
        secp256k1_scalar_get_num(&fiven, &five);
        secp256k1_scalar_get_num(&n, &sqr);
        secp256k1_num_mod(&n, &fiven);
    } while (secp256k1_num_is_zero(&n));
    /* next force it to be a residue. 2 is a nonresidue mod 5 so we can
     * just multiply by two, i.e. add the number to itself */
    if (secp256k1_num_jacobi(&n, &order) == -1) {
        secp256k1_num_add(&n, &n, &n);
    }

    /* test residue */
    CHECK(secp256k1_num_jacobi(&n, &order) == 1);
    /* test nonresidue */
    secp256k1_num_add(&n, &n, &n);
    CHECK(secp256k1_num_jacobi(&n, &order) == -1);

    /** test with secp group order as order */
    secp256k1_scalar_order_get_num(&order);
    random_scalar_order_test(&sqr);
    secp256k1_scalar_sqr(&sqr, &sqr);
    /* test residue */
    secp256k1_scalar_get_num(&n, &sqr);
    CHECK(secp256k1_num_jacobi(&n, &order) == 1);
    /* test nonresidue */
    secp256k1_scalar_mul(&sqr, &sqr, &five);
    secp256k1_scalar_get_num(&n, &sqr);
    CHECK(secp256k1_num_jacobi(&n, &order) == -1);
    /* test multiple of the order*/
    CHECK(secp256k1_num_jacobi(&order, &order) == 0);

    /* check one less than the order */
    secp256k1_scalar_set_int(&small, 1);
    secp256k1_scalar_get_num(&n, &small);
    secp256k1_num_sub(&n, &order, &n);
    CHECK(secp256k1_num_jacobi(&n, &order) == 1);  /* sage confirms this is 1 */
}

func run_num_smalltests() {
    int i;
    for (i = 0; i < 100*g_count; i++) {
        test_num_negate();
        test_num_add_sub();
        test_num_mod();
        test_num_jacobi();
    }
}
#endif
 */
