//
//  tests_endomorphism.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/17.
//  Copyright © 2018年 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation

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
