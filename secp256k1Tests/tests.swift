//
//  tests.swift
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

#if ENABLE_MODULE_ECDH
//#include "modules/ecdh/tests_impl.h"
#endif
 
//#if ENABLE_MODULE_RECOVERY
//#include "modules/recovery/tests_impl.h"
//#endif

func timelog(_ s:String)
{
    print("\(Date()) \(s)")
}

struct TestType : OptionSet {
    let rawValue: Int
    static let hash = TestType(rawValue: 1 << 0)
    static let scalar = TestType(rawValue: 1 << 1)
    static let field = TestType(rawValue: 1 << 2)
    static let group = TestType(rawValue: 1 << 3)
    static let ecmult = TestType(rawValue: 1 << 4)
    static let ec = TestType(rawValue: 1 << 5)
    static let ecdsa = TestType(rawValue: 1 << 6)
    static let recovery = TestType(rawValue: 1 << 7)
    static let context = TestType(rawValue: 1 << 8)
    static let all: TestType
        = [.hash, .scalar, .field, .group, .ecmult, .ec, .ecdsa, .recovery, .context]
}

func test_main(_ count: Int, _ ch:String?, _ type: TestType) {
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
    
    timelog(String(format: "test count = %i", count))
    timelog(String(format: "random seed = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", seed16[0], seed16[1], seed16[2], seed16[3], seed16[4], seed16[5], seed16[6], seed16[7], seed16[8], seed16[9], seed16[10], seed16[11], seed16[12], seed16[13], seed16[14], seed16[15]))
    
    /* initialize */
    if type.contains(.context) {
        timelog("run_context_tests")
        run_context_tests()
    }

    ctx = secp256k1_context_create([SECP256K1_FLAGS.SECP256K1_CONTEXT_SIGN, SECP256K1_FLAGS.SECP256K1_CONTEXT_VERIFY])
    guard var ctx = ctx else { fatalError() }
    if secp256k1_rand_bits(1) != 0 {
        secp256k1_rand256(&run32);
        if secp256k1_rand_bits(1) != 0 {
            CHECK(secp256k1_context_randomize(&ctx, run32))
        } else {
            CHECK(secp256k1_context_randomize(&ctx, nil))
        }
    }
    if type.contains(.hash) {
        timelog("run_rand_bits")
        run_rand_bits()
    
        timelog("run_rand_init")
        run_rand_int()

        timelog("run_sha256_tests")
        run_sha256_tests()
    
        timelog("run_hmac_sha256_tests")
        run_hmac_sha256_tests()
    
        timelog("run_rfc6979_hmac_sha256_tests")
        run_rfc6979_hmac_sha256_tests()
    }

    /*
     #ifndef USE_NUM_NONE
     /* num tests */
     run_num_smalltests();
     #endif
     */
    
    if type.contains(.scalar) {
        /* scalar tests */
        timelog("run_scalar_tests")
        run_scalar_tests()
    }

    if type.contains(.field) {
        /* field tests */
        timelog("run_field_inv")
        run_field_inv()
    
        timelog("run_field_inv_var")
        run_field_inv_var()
    
        timelog("run_field_inv_all_var")
        run_field_inv_all_var()
    
        timelog("run_field_misc")
        run_field_misc()
    
        timelog("run_field_convert")
        run_field_convert()
    
        timelog("run_sqr")
        run_sqr()
    
        timelog("run_sqrt")
        run_sqrt()
    }

    if type.contains(.group) {
        /* group tests */
        timelog("run_ge")
        run_ge()
    
        timelog("run_group_decompress")
        run_group_decompress()
    }

    if type.contains(.ecmult){
        /* ecmult tests */
        timelog("run_wnaf")
        run_wnaf()
    
        timelog("run_point_times_order")
        run_point_times_order()
    
        timelog("run_ecmult_chain")
        run_ecmult_chain()
    
        timelog("run_ecmult_constants")
        run_ecmult_constants()
    
        timelog("run_ecmult_gen_blind")
        run_ecmult_gen_blind()
    
        timelog("run_ecmult_const_tests")
        run_ecmult_const_tests()
    }

    if type.contains(.ec) {
        timelog("run_ec_combine")
        run_ec_combine()

        /*
        /* endomorphism tests */
        #if USE_ENDOMORPHISM
            run_endomorphism_tests();
        #endif
         */
    
        /* EC point parser test */
        timelog("run_ec_pubkey_parse_test")
        run_ec_pubkey_parse_test();

        /* EC key edge cases */
        timelog("run_eckey_edge_case_test")
        run_eckey_edge_case_test();
    }

    /*
    #if ENABLE_MODULE_ECDH
        /* ecdh tests */
        run_ecdh_tests();
    #endif
     */
    
    if type.contains(.ecdsa) {
        /* ecdsa tests */
        timelog("run_random_pubkeys")
        run_random_pubkeys()
    
        timelog("run_ecdsa_der_parse")
        run_ecdsa_der_parse()
    
        timelog("run_ecdsa_sign_verify")
        run_ecdsa_sign_verify()
    
        timelog("run_rcdsa_ends_to_end")
        run_ecdsa_end_to_end()
    
        timelog("run_ecdsa_edge_cases")
        run_ecdsa_edge_cases()
    }
     
    #if ENABLE_OPENSSL_TESTS
        run_ecdsa_openssl()
    #endif
    
    if type.contains(.recovery) {
        /* ECDSA pubkey recovery tests */
        run_recovery_tests();
    }

    timelog("secp256k1_rand256")
    secp256k1_rand256(&run32);
    timelog(String(format:"random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]))
    /* shutdown */
    secp256k1_context_destroy(&ctx);
}
