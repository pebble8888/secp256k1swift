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

func ec_pubkey_parse_pointtest(_ input: [UInt8], _ xvalid: Bool, _ yvalid: Bool) {
    var pubkeyc = [UInt8](repeating: 0, count: 65)
    var pubkey = secp256k1_pubkey()
    var ge = secp256k1_ge();
    var ecount:Int32
    guard var ctx = ctx else { fatalError() }
    ecount = 0;
    secp256k1_context_set_illegal_callback(&ctx, counting_illegal_callback_fn, &ecount);
    for pubkeyclen in 3 ... 65 {
        /* Smaller sizes are tested exhaustively elsewhere. */
        memcpy(&pubkeyc[1], input, 64);
        //VG_UNDEF(&pubkeyc[pubkeyclen], 65 - pubkeyclen);
        for i in 0 ..< 256 {
            /* Try all type bytes. */
            var xpass: Bool
            var ypass: Bool
            var ysign: Int
            pubkeyc[0] = UInt8(i);
            /* What sign does this point have? */
            ysign = Int((input[63] & 1) + 2);
            /* For the current type (i) do we expect parsing to work? Handled all of compressed/uncompressed/hybrid. */
            xpass = xvalid && (pubkeyclen == 33) && ((i & 254) == 2);
            /* Do we expect a parse and re-serialize as uncompressed to give a matching y? */
            ypass = xvalid && yvalid && ((i & 4) == ((pubkeyclen == 65 ? 1 : 0) << 2)) &&
                ((i == 4) || ((i & 251) == ysign)) && ((pubkeyclen == 33) || (pubkeyclen == 65));
            if (xpass || ypass) {
                /* These cases must parse. */
                var pubkeyo = [UInt8](repeating: 0, count: 65)
                var outl: UInt
                //memset(&pubkey, 0, sizeof(pubkey));
                pubkey.clear()
                //VG_UNDEF(&pubkey, sizeof(pubkey));
                ecount = 0;
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, UInt(pubkeyclen)) == true);
                //VG_CHECK(pubkey, sizeof(pubkey));
                outl = 65;
                //VG_UNDEF(pubkeyo, 65);
                CHECK(secp256k1_ec_pubkey_serialize(ctx, &pubkeyo, &outl, pubkey, .SECP256K1_EC_COMPRESSED) == true);
                //VG_CHECK(pubkeyo, outl);
                CHECK(outl == 33);
                //CHECK(memcmp(&pubkeyo[1], &pubkeyc[1], 32) == 0);
                for i in 1 ..< 33 {
                    CHECK(pubkeyo[i] == pubkeyc[i])
                }
                CHECK((pubkeyclen != 33) || (pubkeyo[0] == pubkeyc[0]));
                if (ypass) {
                    /* This test isn't always done because we decode with alternative signs, so the y won't match. */
                    CHECK(pubkeyo[0] == ysign);
                    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == true);
                    //memset(&pubkey, 0, sizeof(pubkey));
                    pubkey.clear()
                    //VG_UNDEF(&pubkey, sizeof(pubkey));
                    secp256k1_pubkey_save(&pubkey, &ge);
                    //VG_CHECK(&pubkey, sizeof(pubkey));
                    outl = 65;
                    //VG_UNDEF(pubkeyo, 65);
                    CHECK(secp256k1_ec_pubkey_serialize(ctx, &pubkeyo, &outl, pubkey, .SECP256K1_EC_UNCOMPRESSED) == true);
                    VG_CHECK(pubkeyo, outl);
                    CHECK(outl == 65);
                    CHECK(pubkeyo[0] == 4);
                    //CHECK(memcmp(&pubkeyo[1], input, 64) == 0);
                    for i in 0 ..< 64 {
                        CHECK(pubkeyo[i+1] == input[i])
                    }
                }
                CHECK(ecount == 0);
            } else {
                /* These cases must fail to parse. */
                //memset(&pubkey, 0xfe, sizeof(pubkey));
                for i in 0 ..< 64 {
                    pubkey.data[i] = 0xfe
                }
                ecount = 0;
                //VG_UNDEF(&pubkey, sizeof(pubkey));
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, UInt(pubkeyclen)) == false);
                //VG_CHECK(&pubkey, sizeof(pubkey));
                CHECK(ecount == 0);
                CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
                CHECK(ecount == 1);
            }
        }
    }
    secp256k1_context_set_illegal_callback(&ctx, nil, nil);
}

func run_ec_pubkey_parse_test() {
    let SECP256K1_EC_PARSE_TEST_NVALID = 12
    let valid:[[UInt8]] /*[SECP256K1_EC_PARSE_TEST_NVALID][64] */ = [
        [
            /* Point with leading and trailing zeros in x and y serialization. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x52,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0xef, 0xa1, 0x7b, 0x77, 0x61, 0xe1, 0xe4, 0x27, 0x06, 0x98, 0x9f, 0xb4, 0x83,
            0xb8, 0xd2, 0xd4, 0x9b, 0xf7, 0x8f, 0xae, 0x98, 0x03, 0xf0, 0x99, 0xb8, 0x34, 0xed, 0xeb, 0x00
        ],
        [
            /* Point with x equal to a 3rd root of unity.*/
            0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
            0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        ],
        [
            /* Point with largest x. (1/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0x0e, 0x99, 0x4b, 0x14, 0xea, 0x72, 0xf8, 0xc3, 0xeb, 0x95, 0xc7, 0x1e, 0xf6, 0x92, 0x57, 0x5e,
            0x77, 0x50, 0x58, 0x33, 0x2d, 0x7e, 0x52, 0xd0, 0x99, 0x5c, 0xf8, 0x03, 0x88, 0x71, 0xb6, 0x7d,
        ],
        [
            /* Point with largest x. (2/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0xf1, 0x66, 0xb4, 0xeb, 0x15, 0x8d, 0x07, 0x3c, 0x14, 0x6a, 0x38, 0xe1, 0x09, 0x6d, 0xa8, 0xa1,
            0x88, 0xaf, 0xa7, 0xcc, 0xd2, 0x81, 0xad, 0x2f, 0x66, 0xa3, 0x07, 0xfb, 0x77, 0x8e, 0x45, 0xb2,
        ],
        [
            /* Point with smallest x. (1/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        ],
        [
            /* Point with smallest x. (2/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        ],
        [
            /* Point with largest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        ],
        [
            /* Point with largest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        ],
        [
            /* Point with largest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        ],
        [
            /* Point with smallest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        [
            /* Point with smallest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        [
            /* Point with smallest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ]
    ];
    let SECP256K1_EC_PARSE_TEST_NXVALID = 4
    let onlyxvalid: [[UInt8]] /*[SECP256K1_EC_PARSE_TEST_NXVALID][64] */ = [
        [
            /* Valid if y overflow ignored (y = 1 mod p). (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        ],
        [
            /* Valid if y overflow ignored (y = 1 mod p). (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        ],
        [
            /* Valid if y overflow ignored (y = 1 mod p). (3/3)*/
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        ],
        [
            /* x on curve, y is from y^2 = x^3 + 8. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        ]
    ];
    let SECP256K1_EC_PARSE_TEST_NINVALID = 7
    let invalid: [[UInt8]] /*[SECP256K1_EC_PARSE_TEST_NINVALID][64] */ = [
        [
            /* x is third root of -8, y is -1 * (x^3+7); also on the curve for y^2 = x^3 + 9. */
            0x0a, 0x2d, 0x2b, 0xa9, 0x35, 0x07, 0xf1, 0xdf, 0x23, 0x37, 0x70, 0xc2, 0xa7, 0x97, 0x96, 0x2c,
            0xc6, 0x1f, 0x6d, 0x15, 0xda, 0x14, 0xec, 0xd4, 0x7d, 0x8d, 0x27, 0xae, 0x1c, 0xd5, 0xf8, 0x53,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ],
        [
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        ],
        [
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        ],
        [
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0xf4, 0x84, 0x14, 0x5c, 0xb0, 0x14, 0x9b, 0x82, 0x5d, 0xff, 0x41, 0x2f, 0xa0, 0x52, 0xa8, 0x3f,
            0xcb, 0x72, 0xdb, 0x61, 0xd5, 0x6f, 0x37, 0x70, 0xce, 0x06, 0x6b, 0x73, 0x49, 0xa2, 0xaa, 0x28,
        ],
        [
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0x0b, 0x7b, 0xeb, 0xa3, 0x4f, 0xeb, 0x64, 0x7d, 0xa2, 0x00, 0xbe, 0xd0, 0x5f, 0xad, 0x57, 0xc0,
            0x34, 0x8d, 0x24, 0x9e, 0x2a, 0x90, 0xc8, 0x8f, 0x31, 0xf9, 0x94, 0x8b, 0xb6, 0x5d, 0x52, 0x07,
        ],
        [
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x8f, 0x53, 0x7e, 0xef, 0xdf, 0xc1, 0x60, 0x6a, 0x07, 0x27, 0xcd, 0x69, 0xb4, 0xa7, 0x33, 0x3d,
            0x38, 0xed, 0x44, 0xe3, 0x93, 0x2a, 0x71, 0x79, 0xee, 0xcb, 0x4b, 0x6f, 0xba, 0x93, 0x60, 0xdc,
        ],
        [
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x70, 0xac, 0x81, 0x10, 0x20, 0x3e, 0x9f, 0x95, 0xf8, 0xd8, 0x32, 0x96, 0x4b, 0x58, 0xcc, 0xc2,
            0xc7, 0x12, 0xbb, 0x1c, 0x6c, 0xd5, 0x8e, 0x86, 0x11, 0x34, 0xb4, 0x8f, 0x45, 0x6c, 0x9b, 0x53
        ]
    ];
    let pubkeyc: [UInt8] /*[66] */ = [
        /* Serialization of G. */
        0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
        0xB8, 0x00
    ];
    var sout = [UInt8](repeating: 0, count: 65)
    var shortkey = [UInt8](repeating: 0, count: 2)
    var ge = secp256k1_ge()
    var pubkey = secp256k1_pubkey()
    var len: UInt
    var ecount:Int32
    var ecount2:Int32
    ecount = 0;
    /* Nothing should be reading this far into pubkeyc. */
    //VG_UNDEF(&pubkeyc[65], 1);
    guard var ctx = ctx else { fatalError() }
    secp256k1_context_set_illegal_callback(&ctx, counting_illegal_callback_fn, &ecount);
    /* Zero length claimed, fail, zeroize, no illegal arg error. */
    // memset(&pubkey, 0xfe, sizeof(pubkey));
    for i in 0 ..< 64 {
        pubkey.data[i] = 0xfe
    }
    ecount = 0;
    //VG_UNDEF(shortkey, 2);
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 0) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
    CHECK(ecount == 1);
    /* Length one claimed, fail, zeroize, no illegal arg error. */
    for i in 0 ..< 256 {
        //memset(&pubkey, 0xfe, sizeof(pubkey));
        for k in 0 ..< 64 {
            pubkey.data[k] = 0xfe
        }
        ecount = 0;
        shortkey[0] = UInt8(i);
        //VG_UNDEF(&shortkey[1], 1);
        //VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 1) == false);
        //VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
        CHECK(ecount == 1);
    }
    /* Length two claimed, fail, zeroize, no illegal arg error. */
    for i in 0 ..< 65536 {
        //memset(&pubkey, 0xfe, sizeof(pubkey));
        for k in 0 ..< 64 {
            pubkey.data[k] = 0xfe
        }
        ecount = 0;
        shortkey[0] = UInt8(i & 255)
        shortkey[1] = UInt8(i >> 8)
        //VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 2) == false);
        //VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
        CHECK(ecount == 1);
    }
    //memset(&pubkey, 0xfe, sizeof(pubkey));
    for k in 0 ..< 64 {
        pubkey.data[k] = 0xfe
    }
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    /* 33 bytes claimed on otherwise valid input starting with 0x04, fail, zeroize output, no illegal arg error. */
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 33) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
    CHECK(ecount == 1);
    /* NULL pubkey, illegal arg error. Pubkey isn't rewritten before this step, since it's NULL into the parser. */
    #if false // can't create null pubkey in secp256k1swift
        var dummy = secp256k1_pubkey()
        CHECK(secp256k1_ec_pubkey_parse(ctx, &dummy, pubkeyc, 65) == false);
        CHECK(ecount == 2);
    #endif
    /* NULL input string. Illegal arg and zeroize output. */
    //memset(&pubkey, 0xfe, sizeof(pubkey));
    for k in 0 ..< 64 {
        pubkey.data[k] = 0xfe
    }
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    let input_dummy = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, input_dummy, 65) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 1);
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
    CHECK(ecount == 2);
    /* 64 bytes claimed on input starting with 0x04, fail, zeroize output, no illegal arg error. */
    //memset(&pubkey, 0xfe, sizeof(pubkey));
    for k in 0 ..< 64 {
        pubkey.data[k] = 0xfe
    }
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 64) == false);
    //VG_CHECK(pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
    CHECK(ecount == 1);
    /* 66 bytes claimed, fail, zeroize output, no illegal arg error. */
    //memset(&pubkey, 0xfe, sizeof(pubkey));
    for k in 0 ..< 64 {
        pubkey.data[k] = 0xfe
    }
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 66) == false);
    //VG_CHECK(pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == false);
    CHECK(ecount == 1);
    /* Valid parse. */
    //memset(&pubkey, 0, sizeof(pubkey));
    pubkey.clear()
    ecount = 0;
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 65) == true);
    //VG_CHECK(pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    //VG_UNDEF(&ge, sizeof(ge));
    CHECK(secp256k1_pubkey_load(ctx, &ge, pubkey) == true);
    //VG_CHECK(ge.x, sizeof(ge.x));
    //VG_CHECK(ge.y, sizeof(ge.y));
    //VG_CHECK(ge.infinity, sizeof(ge.infinity));
    ge_equals_ge(secp256k1_ge_const_g, ge);
    CHECK(ecount == 0);
    /* secp256k1_ec_pubkey_serialize illegal args. */
    ecount = 0;
    len = 65;
    var output_dummy = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &output_dummy, &len, pubkey, .SECP256K1_EC_UNCOMPRESSED) == false);
    CHECK(ecount == 1);
    CHECK(len == 0);
    var outputlen_dummy: UInt = 0
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &sout, &outputlen_dummy, pubkey, .SECP256K1_EC_UNCOMPRESSED) == false);
    CHECK(ecount == 2);
    len = 65;
    //VG_UNDEF(sout, 65);
    var pubkey_dummy = secp256k1_pubkey()
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &sout, &len, pubkey_dummy, .SECP256K1_EC_UNCOMPRESSED) == false);
    VG_CHECK(sout, 65);
    CHECK(ecount == 3);
    CHECK(len == 0);
    len = 65;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &sout, &len, pubkey, .ALL /* ~0 */) == false);
    CHECK(ecount == 4);
    CHECK(len == 0);
    len = 65;
    //VG_UNDEF(sout, 65);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &sout, &len, pubkey, .SECP256K1_EC_UNCOMPRESSED) == true);
    VG_CHECK(sout, 65);
    CHECK(ecount == 4);
    CHECK(len == 65);
    /* Multiple illegal args. Should still set arg error only once. */
    ecount = 0;
    ecount2 = 11;
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey_dummy, input_dummy, 65) == false);
    CHECK(ecount == 1);
    /* Does the illegal arg callback actually change the behavior? */
    secp256k1_context_set_illegal_callback(&ctx, uncounting_illegal_callback_fn, &ecount2);
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey_dummy, input_dummy, 65) == false);
    CHECK(ecount == 1);
    CHECK(ecount2 == 10);
    secp256k1_context_set_illegal_callback(&ctx, nil, nil);
    /* Try a bunch of prefabbed points with all possible encodings. */
    for i in 0 ..< SECP256K1_EC_PARSE_TEST_NVALID {
        ec_pubkey_parse_pointtest(valid[i], true, true);
    }
    for i in 0 ..< SECP256K1_EC_PARSE_TEST_NXVALID {
        ec_pubkey_parse_pointtest(onlyxvalid[i], true, false);
    }
    for i in 0 ..< SECP256K1_EC_PARSE_TEST_NINVALID {
        ec_pubkey_parse_pointtest(invalid[i], false, false);
    }
}

func run_eckey_edge_case_test() {
    let orderc: [UInt8] /*[32]*/ = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    ]
    let zeros = [UInt8](repeating: 0, count: 64) //sizeof(secp256k1_pubkey)] = {0x00};
    var ctmp =  [UInt8](repeating: 0, count: 33)
    var ctmp2 = [UInt8](repeating: 0, count: 33)
    var pubkey = secp256k1_pubkey()
    var pubkey2 = secp256k1_pubkey()
    var pubkey_one = secp256k1_pubkey()
    var pubkey_negone = secp256k1_pubkey()
    //const secp256k1_pubkey *pubkeys[3];
    var pubkeys = [secp256k1_pubkey](repeating: secp256k1_pubkey(), count: 3)
    var len:UInt
    var ecount:Int32
    guard var ctx = ctx else { fatalError() }
    /* Group order is too large, reject. */
    CHECK(secp256k1_ec_seckey_verify(ctx, orderc) == false);
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, orderc) == false);
    //VG_CHECK(pubkey, sizeof(pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == false);
    /* Maximum value is too large, reject. */
    //memset(ctmp, 255, 32);
    ctmp.fill(255, count: 32)
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == false);
    //memset(&pubkey, 1, sizeof(pubkey));
    pubkey.data.fill(1)
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* Zero is too small, reject. */
    //memset(ctmp, 0, 32);
    ctmp.clear(count: 32)
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == false);
    //memset(&pubkey, 1, sizeof(pubkey));
    pubkey.data.fill(1)
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* One must be accepted. */
    ctmp[31] = 0x01;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == true);
    //memset(&pubkey, 0, sizeof(pubkey));
    pubkey.clear()
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == true);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(!pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_one = pubkey;
    /* Group order + 1 is too large, reject. */
    //memcpy(ctmp, orderc, 32);
    ctmp = orderc
    ctmp[31] = 0x42;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == false);
    //memset(&pubkey, 1, sizeof(pubkey));
    pubkey.data.fill(1)
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == false);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(pubkey.is_zero()) //memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* -1 must be accepted. */
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == true);
    //memset(&pubkey, 0, sizeof(pubkey));
    pubkey.clear()
    //VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, ctmp) == true);
    //VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(!pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    pubkey_negone = pubkey;
    /* Tweak of zero leaves the value changed. */
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count:32)
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, ctmp2) == true);
    CHECK(orderc.compare(ctmp, count:31) && ctmp[31] == 0x40) //memcmp(orderc, ctmp, 31) == 0 && ctmp[31] == 0x40);
    //memcpy(&pubkey2, &pubkey, sizeof(pubkey));
    pubkey2 = pubkey
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == true);
    CHECK(pubkey.equal(pubkey2)) // memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Multiply tweak of zero zeroizes the output. */
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, ctmp2) == false);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, ctmp2) == false);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    /* Overflowing key tweak zeroizes. */
    //memcpy(ctmp, orderc, 32);
    ctmp = orderc
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, orderc) == false);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    //memcpy(ctmp, orderc, 32);
    ctmp = orderc
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, orderc) == false);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    //memcpy(ctmp, orderc, 32);
    ctmp = orderc
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, orderc) == false);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, orderc) == false);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    /* Private key tweaks results in a key of zero. */
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp2, ctmp) == false);
    CHECK(memcmp(zeros, ctmp2, 32) == 0);
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == false);
    CHECK(pubkey.is_zero()) // // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    /* Tweak computation wraps and results in a key of 1. */
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp2, ctmp) == true);
    CHECK(memcmp(ctmp2, zeros, 31) == 0 && ctmp2[31] == 1);
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == true);
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, ctmp2) == true);
    CHECK(pubkey == pubkey2) //memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Tweak mul * 2 = 1+1. */
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == true);
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == true);
    CHECK(pubkey == pubkey2) // // memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Test argument errors. */
    ecount = 0;
    secp256k1_context_set_illegal_callback(&ctx, counting_illegal_callback_fn, &ecount);
    CHECK(ecount == 0);
    /* Zeroize pubkey on parse error. */
    //memset(&pubkey, 0, 32);
    pubkey.data.fill(0, count:32)
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == false);
    CHECK(ecount == 1);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    //memset(&pubkey2, 0, 32);
    pubkey2.data.clear(count:32)
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey2, ctmp2) == false);
    CHECK(ecount == 2);
    CHECK(pubkey2.is_zero()) // //memcmp(&pubkey2, zeros, sizeof(pubkey2)) == 0);
    /* Plain argument errors. */
    ecount = 0;
    CHECK(secp256k1_ec_seckey_verify(ctx, ctmp) == true);
    CHECK(ecount == 0);
    let dummy_seckey = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ec_seckey_verify(ctx, dummy_seckey) == false);
    CHECK(ecount == 1);
    ecount = 0;
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count: 32)
    ctmp2[31] = 4;
    var dummy_pubkey = secp256k1_pubkey()
    dummy_pubkey.data = [UInt8](repeating: 0, count:0)
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &dummy_pubkey, ctmp2) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, dummy_seckey) == false);
    CHECK(ecount == 2);
    ecount = 0;
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count:32)
    ctmp2[31] = 4;
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &dummy_pubkey, ctmp2) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, dummy_seckey) == false);
    CHECK(ecount == 2);
    ecount = 0;
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count:32)
    var dummy_tmp = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &dummy_tmp, ctmp2) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, dummy_seckey) == false);
    CHECK(ecount == 2);
    ecount = 0;
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count:32)
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &dummy_tmp, ctmp2) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, dummy_tmp) == false);
    CHECK(ecount == 2);
    ecount = 0;
    CHECK(secp256k1_ec_pubkey_create(ctx, &dummy_pubkey, ctmp) == false);
    CHECK(ecount == 1);
    //memset(&pubkey, 1, sizeof(pubkey));
    pubkey.data.fill(1)
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, dummy_tmp) == false);
    CHECK(ecount == 2);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    /* secp256k1_ec_pubkey_combine tests. */
    ecount = 0;
    pubkeys[0] = pubkey_one;
    //VG_UNDEF(&pubkeys[0], sizeof(secp256k1_pubkey *));
    //VG_UNDEF(&pubkeys[1], sizeof(secp256k1_pubkey *));
    //VG_UNDEF(&pubkeys[2], sizeof(secp256k1_pubkey *));
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 0) == false);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ec_pubkey_combine(ctx, &dummy_pubkey, pubkeys, 1) == false);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 2);
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, [], 1) == false);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 3);
    pubkeys[0] = pubkey_negone;
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 1) == true);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(!pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &ctmp, &len, pubkey, .SECP256K1_EC_COMPRESSED) == true);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &ctmp2, &len, pubkey_negone, .SECP256K1_EC_COMPRESSED) == true);
    CHECK(ctmp.compare(ctmp2, count: 33))
    /* Result is infinity. */
    pubkeys[0] = pubkey_one;
    pubkeys[1] = pubkey_negone;
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == false);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) == 0);
    CHECK(ecount == 3);
    /* Passes through infinity but comes out one. */
    pubkeys[2] = pubkey_one;
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 3) == true);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(!pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    len = 33;
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &ctmp, &len, pubkey, .SECP256K1_EC_COMPRESSED) == true);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &ctmp2, &len, pubkey_one, .SECP256K1_EC_COMPRESSED) == true);
    CHECK(ctmp.compare(ctmp2, count:33))
    /* Adds to two. */
    pubkeys[1] = pubkey_one;
    //memset(&pubkey, 255, sizeof(secp256k1_pubkey));
    pubkey.data.fill(255)
    //VG_UNDEF(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(secp256k1_ec_pubkey_combine(ctx, &pubkey, pubkeys, 2) == true);
    //VG_CHECK(&pubkey, sizeof(secp256k1_pubkey));
    CHECK(!pubkey.is_zero()) //memcmp(&pubkey, zeros, sizeof(secp256k1_pubkey)) > 0);
    CHECK(ecount == 3);
    secp256k1_context_set_illegal_callback(&ctx, nil, nil);
}

func random_sign(_ sigr: inout secp256k1_scalar,
                 _ sigs: inout secp256k1_scalar,
                 _ key: secp256k1_scalar,
                 _ msg: secp256k1_scalar,
                 _ recid: inout Int)
{
    guard let ctx = ctx else { fatalError() }
    var nonce = secp256k1_scalar()
    repeat {
        random_scalar_order_test(&nonce);
    } while(!secp256k1_ecdsa_sig_sign(ctx.ecmult_gen_ctx, &sigr, &sigs, key, msg, nonce, &recid));
}

func test_ecdsa_sign_verify() {
    var pubj = secp256k1_gej()
    var pub = secp256k1_ge()
    var one = secp256k1_scalar()
    var msg = secp256k1_scalar()
    var key = secp256k1_scalar()
    var sigr = secp256k1_scalar()
    var sigs = secp256k1_scalar()
    var recid:Int = 0
    var getrec:Int
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    guard let ctx = ctx else { fatalError() }
    secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &pubj, key);
    secp256k1_ge_set_gej(&pub, &pubj);
    getrec = Int(secp256k1_rand_bits(1));
    random_sign(&sigr, &sigs, key, msg, &recid)
    if (getrec != 0) {
        CHECK(recid >= 0 && recid < 4);
    }
    CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sigr, sigs, pub, msg));
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_add(&msg, msg, one);
    CHECK(!secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sigr, sigs, pub, msg));
}

func run_ecdsa_sign_verify() {
    for _ in 0 ..< 10*g_count {
        test_ecdsa_sign_verify();
    }
}

/** Dummy nonce generation function that just uses a precomputed nonce, and fails if it is not accepted. Use only for testing. */
func precomputed_nonce_function(_ nonce32: inout [UInt8],
                                _ msg32: [UInt8],
                                _ key32: [UInt8],
                                _ algo16: [UInt8]?,
                                _ data: [UInt8]?,
                                _ counter: UInt) -> Bool
{
    //memcpy(nonce32, data, 32);
    guard let data = data else { fatalError() }
    for i in 0 ..< 32 {
        nonce32[i] = data[i]
    }
    return counter == 0
}

func nonce_function_test_fail(_ nonce32: inout [UInt8],
                              _ msg32: [UInt8],
                              _ key32: [UInt8],
                              _ algo16: [UInt8]?,
                              _ data: [UInt8]?,
                              _ counter: UInt) -> Bool
{
   /* Dummy nonce generator that has a fatal error on the first counter value. */
   if (counter == 0) {
       return false
   }
   return nonce_function_rfc6979(&nonce32, msg32, key32, algo16, data, counter - UInt(1))
}

func nonce_function_test_retry(_ nonce32: inout [UInt8],
                               _ msg32: [UInt8],
                               _ key32: [UInt8],
                               _ algo16: [UInt8]?,
                               _ data: [UInt8]?,
                               _ counter: UInt) -> Bool
{
   /* Dummy nonce generator that produces unacceptable nonces for the first several counter values. */
    if (counter < 3) {
        //memset(nonce32, counter==0 ? 0 : 255, 32);
        for i in 0 ..< 32 {
            nonce32[i] = counter == 0 ? 0 : 255
        }
        if (counter == 2) {
           nonce32[31] -= 1
        }
        return true
    }
    if (counter < 5) {
        let order: [UInt8] = [
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
           0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
           0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
        ]
        //memcpy(nonce32, order, 32);
        for i in 0 ..< 32 {
            nonce32[i] = order[i]
        }
        if (counter == 4) {
            nonce32[31] += 1
        }
        return true
    }
    /* Retry rate of 6979 is negligible esp. as we only call this in deterministic tests. */
    /* If someone does fine a case where it retries for secp256k1, we'd like to know. */
    if (counter > 5) {
        return false
    }
    return nonce_function_rfc6979(&nonce32, msg32, key32, algo16, data, counter - 5);
}

func is_empty_signature(_ sig: secp256k1_ecdsa_signature) -> Bool {
    //static const unsigned char res[sizeof(secp256k1_ecdsa_signature)] = {0};
    return sig.is_zero() // memcmp(sig, res, sizeof(secp256k1_ecdsa_signature)) == 0;
}

func test_ecdsa_end_to_end() {
    var extra = [UInt8](repeating: 0, count: 32) // = {0x00};
    var privkey = [UInt8](repeating: 0, count: 32)
    var message = [UInt8](repeating: 0, count: 32)
    var privkey2 = [UInt8](repeating: 0, count: 32)
    var signature = [secp256k1_ecdsa_signature](repeating: secp256k1_ecdsa_signature(), count: 6)
    var r = secp256k1_scalar()
    var s = secp256k1_scalar()
    var sig = [UInt8](repeating: 0, count:74)
    var siglen:UInt = 74;
    var pubkeyc = [UInt8](repeating: 0, count:65)
    var pubkeyclen:UInt = 65;
    var pubkey = secp256k1_pubkey()
    var pubkey_tmp = secp256k1_pubkey()
    var seckey = [UInt8](repeating: 0, count:300)
    var seckeylen: UInt = 300;

    /* Generate a random key and message. */
    do {
        var msg = secp256k1_scalar()
        var key = secp256k1_scalar()
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(&privkey, key);
        secp256k1_scalar_get_b32(&message, msg);
    }
    guard let ctx = ctx else { fatalError() }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == true);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == true);

    /* Verify exporting and importing public key. */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, &pubkeyc, &pubkeyclen, pubkey, secp256k1_rand_bits(1) == 1 ? .SECP256K1_EC_COMPRESSED : .SECP256K1_EC_UNCOMPRESSED));
    //memset(&pubkey, 0, sizeof(pubkey));
    pubkey.clear()
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == true);

    /* Verify negation changes the key and changes it back */
    //memcpy(&pubkey_tmp, &pubkey, sizeof(pubkey));
    pubkey_tmp = pubkey
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == true);
    CHECK(pubkey_tmp != pubkey) //memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) != 0);
    CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey_tmp) == true);
    CHECK(pubkey_tmp == pubkey) // memcmp(&pubkey_tmp, &pubkey, sizeof(pubkey)) == 0);

    /* Verify private key import and export. */
    CHECK(ec_privkey_export_der(ctx, &seckey, &seckeylen, privkey, secp256k1_rand_bits(1) != 0))
    CHECK(ec_privkey_import_der(ctx, &privkey2, seckey, Int(seckeylen)) == true)
    CHECK(privkey == privkey2)

    /* Optionally tweak the keys using addition. */
    if (secp256k1_rand_int(3) == 0) {
        var ret1:Bool
        var ret2:Bool
        var rnd = [UInt8](repeating: 0, count:32)
        var pubkey2 = secp256k1_pubkey()
        secp256k1_rand256_test(&rnd);
        ret1 = secp256k1_ec_privkey_tweak_add(ctx, &privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == false) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == true);
        CHECK(pubkey == pubkey2) // memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (secp256k1_rand_int(3) == 0) {
        var ret1:Bool
        var ret2:Bool
        var rnd = [UInt8](repeating: 0, count:32)
        var pubkey2 = secp256k1_pubkey()
        secp256k1_rand256_test(&rnd);
        ret1 = secp256k1_ec_privkey_tweak_mul(ctx, &privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == false) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == true);
        CHECK(pubkey == pubkey2) // memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Sign. */
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, nil, nil) == true);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[4], message, privkey, nil, nil) == true);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[1], message, privkey, nil, extra) == true);
    extra[31] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[2], message, privkey, nil, extra) == true);
    extra[31] = 0;
    extra[0] = 1;
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[3], message, privkey, nil, extra) == true);
    CHECK(signature[0] == signature[4])
    CHECK(signature[0] != signature[1])
    CHECK(signature[0] != signature[2])
    CHECK(signature[0] != signature[3])
    CHECK(signature[1] != signature[2])
    CHECK(signature[1] != signature[3])
    CHECK(signature[2] != signature[3])
    /* Verify. */
    CHECK(secp256k1_ecdsa_verify(ctx, signature[0], message, pubkey) == true);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[1], message, pubkey) == true);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[2], message, pubkey) == true);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[3], message, pubkey) == true);
    /* Test lower-S form, malleate, verify and fail, test again, malleate again */
    var dummy = secp256k1_ecdsa_signature()
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &dummy, signature[0]));
    secp256k1_ecdsa_signature_load(ctx, &r, &s, signature[0]);
    secp256k1_scalar_negate(&s, s);
    secp256k1_ecdsa_signature_save(&signature[5], r, s);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[5], message, pubkey) == false);
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, &dummy, signature[5]));
    CHECK(secp256k1_ecdsa_signature_normalize(ctx, &signature[5], signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &dummy, signature[5]));
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &signature[5], signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, signature[5], message, pubkey) == true);
    secp256k1_scalar_negate(&s, s);
    secp256k1_ecdsa_signature_save(&signature[5], r, s);
    CHECK(!secp256k1_ecdsa_signature_normalize(ctx, &dummy, signature[5]));
    CHECK(secp256k1_ecdsa_verify(ctx, signature[5], message, pubkey) == true);
    CHECK(signature[5] == signature[0])

    /* Serialize/parse DER and verify again */
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &sig, &siglen, signature[0]) == true)
    //memset(&signature[0], 0, sizeof(signature[0]));
    signature[0].clear()
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == true)
    CHECK(secp256k1_ecdsa_verify(ctx, signature[0], message, pubkey) == true)
    /* Serialize/destroy/parse DER and verify again. */
    siglen = 74;
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &sig, &siglen, signature[0]) == true)
    let idx = Int(secp256k1_rand_int(UInt32(siglen)))
    let val = UInt8(1) &+ UInt8(secp256k1_rand_int(255))
    sig[idx] = sig[idx] &+ UInt8(val)
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == false ||
          secp256k1_ecdsa_verify(ctx, signature[0], message, pubkey) == false)
}

func test_random_pubkeys() {
    var elem = secp256k1_ge()
    var elem2 = secp256k1_ge()
    var l_in = [UInt8](repeating: 0, count:65)
    /* Generate some randomly sized pubkeys. */
    var len: UInt = secp256k1_rand_bits(2) == 0 ? 65 : 33;
    if (secp256k1_rand_bits(2) == 0) {
        len = UInt(secp256k1_rand_bits(6));
    }
    if (len == 65) {
      l_in[0] = secp256k1_rand_bits(1) != 0 ? 4 : (secp256k1_rand_bits(1) != 0 ? 6 : 7);
    } else {
      l_in[0] = secp256k1_rand_bits(1) != 0 ? 2 : 3;
    }
    if (secp256k1_rand_bits(3) == 0) {
        l_in[0] = UInt8(secp256k1_rand_bits(8));
    }
    if (len > 1) {
        secp256k1_rand256(&l_in, from: 1)
    }
    if (len > 33) {
        secp256k1_rand256(&l_in, from: 33)
    }
    if (secp256k1_eckey_pubkey_parse(&elem, l_in, len)) {
        var out = [UInt8](repeating: 0, count:65)
        var firstb:UInt8
        var res:Bool
        var size:UInt = len;
        firstb = l_in[0];
        /* If the pubkey can be parsed, it should round-trip... */
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, &out, &size, len == 33));
        CHECK(size == len);
        CHECK(l_in.compare(index1: 1, l_in, index2: 1, count: Int(len)-1)) // memcmp(&l_in[1], &out[1], len-1) == 0);
        /* ... except for the type of hybrid inputs. */
        if ((l_in[0] != 6) && (l_in[0] != 7)) {
            CHECK(l_in[0] == out[0]);
        }
        size = 65;
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, &l_in, &size, false));
        CHECK(size == 65);
        CHECK(secp256k1_eckey_pubkey_parse(&elem2, l_in, size));
        ge_equals_ge(elem, elem2);
        /* Check that the X9.62 hybrid type is checked. */
        l_in[0] = secp256k1_rand_bits(1) != 0 ? 6 : 7;
        res = secp256k1_eckey_pubkey_parse(&elem2, l_in, size);
        if (firstb == 2 || firstb == 3) {
            if (l_in[0] == firstb + 4) {
              CHECK(res);
            } else {
              CHECK(!res);
            }
        }
        if (res) {
            ge_equals_ge(elem, elem2);
            CHECK(secp256k1_eckey_pubkey_serialize(&elem, &out, &size, false));
            CHECK(l_in.compare(index1: 1, out, index2: 1, count: 64)) // memcmp(&l_in[1], &out[1], 64) == 0);
        }
    }
}

func run_random_pubkeys() {
    for _ in 0 ..< 10*g_count {
        test_random_pubkeys();
    }
}

func run_ecdsa_end_to_end() {
    for i in 0 ..< 64*g_count {
        test_ecdsa_end_to_end();
    }
}

func test_ecdsa_der_parse(_ sig: [UInt8], _ siglen: UInt, _ certainly_der: Bool, _ certainly_not_der: Bool) -> Int {
    //let zeroes = [UInt](repeating: 0, count:32)
    /*
#if ENABLE_OPENSSL_TESTS
    static const unsigned char max_scalar[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
    };
#endif
 */

    var ret: Int = 0

    var sig_der = secp256k1_ecdsa_signature()
    var roundtrip_der = [UInt8](repeating: 0, count:2048)
    var compact_der = [UInt8](repeating: 0, count:64)
    var len_der: UInt = 2048;
    var parsed_der: Bool = false
    var valid_der: Bool = false
    var roundtrips_der: Bool = false

    var sig_der_lax = secp256k1_ecdsa_signature()
    var roundtrip_der_lax = [UInt8](repeating: 0, count: 2048)
    var compact_der_lax = [UInt8](repeating: 0, count: 64)
    var len_der_lax:UInt = 2048;
    var parsed_der_lax:Bool = false
    var valid_der_lax:Bool = false
    var roundtrips_der_lax: Bool = false

    /*
#if ENABLE_OPENSSL_TESTS
    ECDSA_SIG *sig_openssl;
    const unsigned char *sigptr;
    unsigned char roundtrip_openssl[2048];
    int len_openssl = 2048;
    int parsed_openssl, valid_openssl = 0, roundtrips_openssl = 0;
#endif
 */
    guard var ctx = ctx else { fatalError() }
    parsed_der = secp256k1_ecdsa_signature_parse_der(ctx, &sig_der, sig, siglen)
    if parsed_der {
        ret |= (!secp256k1_ecdsa_signature_serialize_compact(ctx, &compact_der, sig_der) ? 1 : 0) << 0
        valid_der = !compact_der.is_zero_first_half() && !compact_der.is_zero_second_half()
    }
    if (valid_der) {
        ret |=  (!secp256k1_ecdsa_signature_serialize_der(ctx, &roundtrip_der, &len_der, sig_der) ? 1 : 0) << 1
        roundtrips_der = (len_der == siglen) && roundtrip_der.compare(sig, count: Int(siglen))
    }

    parsed_der_lax = ecdsa_signature_parse_der_lax(&ctx, &sig_der_lax, sig, Int(siglen));
    if (parsed_der_lax) {
        ret |= (!secp256k1_ecdsa_signature_serialize_compact(ctx, &compact_der_lax, sig_der_lax) ? 1 : 0) << 10;
        valid_der_lax = (!compact_der_lax.is_zero_first_half()) && (!compact_der_lax.is_zero_second_half())
    }
    if (valid_der_lax) {
        ret |= (!secp256k1_ecdsa_signature_serialize_der(ctx, &roundtrip_der_lax, &len_der_lax, sig_der_lax) ? 1 : 0) << 11;
        roundtrips_der_lax = (len_der_lax == siglen) && roundtrip_der_lax.compare(sig, count: Int(siglen))
    }

    if (certainly_der) {
        ret |= (!parsed_der ? 1 : 0) << 2;
    }
    if (certainly_not_der) {
        ret |= (parsed_der ? 1 : 0) << 17;
    }
    if (valid_der) {
        ret |= (!roundtrips_der ? 1 : 0) << 3;
    }

    if (valid_der) {
        ret |= (!roundtrips_der_lax ? 1 : 0) << 12;
        ret |= (len_der != len_der_lax ? 1 : 0) << 13;
        ret |= (!roundtrip_der_lax.compare(roundtrip_der, count: Int(len_der)) ? 1 : 0) << 14;
    }
    ret |= (roundtrips_der != roundtrips_der_lax ? 1 : 0) << 15;
    if (parsed_der) {
        ret |= (!parsed_der_lax ? 1 : 0) << 16;
    }

    /*
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
     */
    return ret;
}

func assign_big_endian(_ ptr: inout [UInt8], from: UInt = 0, _ ptrlen: UInt, _ val: UInt32) {
    for i in Int(from) ..< Int(from + ptrlen) {
        //let shift: Int = Int(ptrlen) - 1 - i + from;
        //let shift: Int = i - Int(from)
        let shift = Int(ptrlen) + Int(from) - 1 - i
        if shift >= 4 {
            ptr[i] = 0
        } else {
            ptr[i] = UInt8((val >> shift) & 0xFF)
        }
    }
}

func damage_array(_ sig: inout [UInt8], _ len: inout Int) {
    var pos:Int
    let action:Int = Int(secp256k1_rand_bits(3))
    if (action < 1 && len > 3) {
        /* Delete a byte. */
        pos = Int(secp256k1_rand_int(UInt32(len)))
        //memmove(sig + pos, sig + pos + 1, len - pos - 1);
        for i in pos ..< Int(len) - 1 {
            sig[i] = sig[i+1]
        }
        len -= 1
    } else if (action < 2 && len < 2048) {
        /* Insert a byte. */
        pos = Int(secp256k1_rand_int(UInt32(1 + Int(len))))
        //memmove(sig + pos + 1, sig + pos, len - pos);
        for i in stride(from: Int(len) - 1, through: pos, by: -1){
            sig[1+i] = sig[i]
        }
        sig[pos] = UInt8(secp256k1_rand_bits(8))
        len += 1
    } else if (action < 4) {
        /* Modify a byte. */
        let idx = Int(secp256k1_rand_int(UInt32(len)))
        sig[idx] = sig[idx] &+ UInt8(1 &+ secp256k1_rand_int(255))
    } else { /* action < 8 */
        /* Modify a bit. */
        sig[Int(secp256k1_rand_int(UInt32(len)))] ^= UInt8(1 << secp256k1_rand_bits(3))
    }
}

func random_ber_signature(_ sig: inout [UInt8], _ len: inout Int, _ certainly_der: inout Bool, _ certainly_not_der: inout Bool) {
    var der: Bool
    var nlow = [Bool](repeating:false, count:2)
    var nlen = [Int](repeating:0, count:2)
    var nlenlen = [Int](repeating: 0, count:2)
    var nhbit = [Int](repeating: 0, count:2)
    var nhbyte = [Int](repeating: 0, count:2)
    var nzlen = [Int](repeating: 0, count:2)
    var tlen, elen, glen:Int
    var indet: Bool

    len = 0;
    der = (secp256k1_rand_bits(2) == 0)
    certainly_der = der
    certainly_not_der = false
    indet = der ? false : (secp256k1_rand_int(10) == 0)

    for n in 0 ..< 2 {
        /* We generate two classes of numbers: nlow==1 "low" ones (up to 32 bytes), nlow==0 "high" ones (32 bytes with 129 top bits set, or larger than 32 bytes) */
        nlow[n] = der ? true : (secp256k1_rand_bits(3) != 0);
        /* The length of the number in bytes (the first byte of which will always be nonzero) */
        nlen[n] = {
            if nlow[n] {
                return Int(secp256k1_rand_int(33))
            } else {
                return Int(32) + Int(secp256k1_rand_int(200) * secp256k1_rand_int(8) / 8)
            }
        }()
        CHECK(nlen[n] <= 232);
        /* The top bit of the number. */
        nhbit[n] = {
            if !nlow[n] && nlen[n] == 32 {
                return 1
            } else if nlen[n] == 0 {
                return 0
            } else {
                return Int(secp256k1_rand_bits(1))
            }
        }()
        /* The top byte of the number (after the potential hardcoded 16 0xFF characters for "high" 32 bytes numbers) */
        nhbyte[n] = {
            if nlen[n] == 0 {
                return 0
            } else if nhbit[n] != 0 {
                return 128 + Int(secp256k1_rand_bits(7))
            } else {
                return 1 + Int(secp256k1_rand_int(127))
            }
        }()
        /* The number of zero bytes in front of the number (which is 0 or 1 in case of DER, otherwise we extend up to 300 bytes) */
        nzlen[n] = {
            if der {
                return ((nlen[n] == 0 || nhbit[n] != 0) ? 1 : 0)
            } else if nlow[n] {
                return Int(secp256k1_rand_int(3))
            } else {
                return Int(secp256k1_rand_int(UInt32(300 - nlen[n])) * secp256k1_rand_int(8) / 8)
            }
        }()
        if nzlen[n] > ((nlen[n] == 0 || nhbit[n] != 0) ? 1 : 0) {
            certainly_not_der = true
        }
        CHECK(nlen[n] + nzlen[n] <= 300);
        /* The length of the length descriptor for the number. 0 means short encoding, anything else is long encoding. */
        nlenlen[n] = {
            if nlen[n] + nzlen[n] < 128 {
                return 0
            } else if nlen[n] + nzlen[n] < 256 {
                return 1
            } else {
                return 2
            }
        }()
        if (!der) {
            /* nlenlen[n] max 127 bytes */
            let add: Int = Int(secp256k1_rand_int(UInt32(127 - nlenlen[n])) * secp256k1_rand_int(16) * secp256k1_rand_int(16) / 256);
            nlenlen[n] += add;
            if add != 0 {
                certainly_not_der = true
            }
        }
        CHECK(nlen[n] + nzlen[n] + nlenlen[n] <= 427);
    }

    /* The total length of the data to go, so far */
    tlen = 2 + nlenlen[0] + nlen[0] + nzlen[0] + 2 + nlenlen[1] + nlen[1] + nzlen[1];
    CHECK(tlen <= 856);

    /* The length of the garbage inside the tuple. */
    elen = {
        if der || indet {
            return 0
        } else {
            return Int(secp256k1_rand_int(UInt32(Int(980) - Int(tlen)))) * Int(secp256k1_rand_int(8)) / 8
        }
    }()
    if elen != 0 {
        certainly_not_der = true
    }
    tlen += elen
    CHECK(tlen <= 980)

    /* The length of the garbage after the end of the tuple. */
    glen = {
        if der {
            return 0
        } else {
            return Int(secp256k1_rand_int(UInt32(990 - tlen))) * Int(secp256k1_rand_int(8)) / 8
        }
    }()
    if (glen != 0) {
        certainly_not_der = true
    }
    CHECK(tlen + glen <= 990);

    /* Write the tuple header. */
    assert(len == 0)
    sig[len] = 0x30
    len += 1
    if indet {
        /* Indeterminate length */
        sig[len] = 0x80
        len += 1
        certainly_not_der = true
    } else {
        var tlenlen: Int = tlen < 128 ? 0 : (tlen < 256 ? 1 : 2);
        if !der {
            let add: Int = Int(secp256k1_rand_int(UInt32(127 - tlenlen)))
                         * Int(secp256k1_rand_int(16))
                         * Int(secp256k1_rand_int(16)) / 256;
            tlenlen += add;
            if add != 0 {
                certainly_not_der = true
            }
        }
        if tlenlen == 0 {
            /* Short length notation */
            sig[len] = UInt8(tlen)
            len += 1
        } else {
            /* Long length notation */
            sig[len] = 128 + UInt8(tlenlen)
            len += 1
            assign_big_endian(&sig, from: UInt(len), UInt(tlenlen), UInt32(tlen))
            len = len + tlenlen
        }
        tlen += tlenlen
    }
    tlen += 2
    CHECK(tlen + glen <= 1119)

    for n in 0 ..< 2 {
        /* Write the integer header. */
        sig[len] = 0x02;
        len += 1
        if nlenlen[n] == 0 {
            /* Short length notation */
            sig[len] = UInt8(nlen[n] + nzlen[n])
            len += 1
        } else {
            /* Long length notation. */
            sig[len] = 128 + UInt8(nlenlen[n])
            len += 1
            assign_big_endian(&sig, from: UInt(len), UInt(nlenlen[n]), UInt32(nlen[n] + nzlen[n]));
            len = len + nlenlen[n]
        }
        /* Write zero padding */
        while nzlen[n] > 0 {
            sig[len] = 0x00;
            len += 1
            nzlen[n] -= 1
        }
        if nlen[n] == 32 && !nlow[n] {
            /* Special extra 16 0xFF bytes in "high" 32-byte numbers */
            for _ in 0 ..< 16 {
                sig[len] = 0xFF;
                len += 1
            }
            nlen[n] -= 16;
        }
        /* Write first byte of number */
        if nlen[n] > 0 {
            sig[len] = UInt8(nhbyte[n])
            len += 1
            nlen[n] -= 1
        }
        /* Generate remaining random bytes of number */
        secp256k1_rand_bytes_test(&sig, from: len, UInt(nlen[n]));
        len = len + nlen[n]
        nlen[n] = 0;
    }

    /* Generate random garbage inside tuple. */
    secp256k1_rand_bytes_test(&sig, from: len, UInt(elen));
    len = len + elen

    /* Generate end-of-contents bytes. */
    if indet {
        sig[len] = 0
        len += 1
        sig[len] = 0
        len += 1
        tlen += 2
    }
    CHECK(tlen + glen <= 1121);

    /* Generate random garbage outside tuple. */
    secp256k1_rand_bytes_test(&sig, from: len, UInt(glen));
    len = len + glen
    tlen += glen;
    CHECK(tlen <= 1121);
    CHECK(tlen == len);
}

func run_ecdsa_der_parse() {
    for _ in  0 ..< 200 * g_count {
        var buffer = [UInt8](repeating: 0, count:2048)
        var buflen:Int = 0;
        var certainly_der: Bool = false
        var certainly_not_der: Bool = false
        random_ber_signature(&buffer, &buflen, &certainly_der, &certainly_not_der);
        CHECK(buflen <= 2048);
        for j in 0 ..< 16 {
            if j > 0 {
                damage_array(&buffer, &buflen);
                /* We don't know anything anymore about the DERness of the result */
                certainly_der = false
                certainly_not_der = false
            }
            let ret: Int = test_ecdsa_der_parse(buffer, UInt(buflen), certainly_der, certainly_not_der);
            if ret != 0 {
                print(String(format:"Failure %x on ", ret))
                print(buffer[0..<Int(buflen)].hexDescription())
            }
            CHECK(ret == 0);
        }
    }
}

/* Tests several edge cases. */
func test_ecdsa_edge_cases() {
    //int t;
    var sig = secp256k1_ecdsa_signature()
    var dummy_sig = secp256k1_ecdsa_signature()
    dummy_sig.data.removeAll()
    
    guard var ctx = ctx else { fatalError() }

    /* Test the case where ECDSA recomputes a point that is infinity. */
    do {
        var keyj = secp256k1_gej()
        var key = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_negate(&ss, ss);
        secp256k1_scalar_inverse(&ss, ss);
        secp256k1_scalar_set_int(&sr, 1);
        secp256k1_ecmult_gen(ctx.ecmult_gen_ctx, &keyj, sr);
        secp256k1_ge_set_gej(&key, &keyj);
        msg = ss;
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
    }

    /* Verify signature with r of zero fails. */
    do {
        let pubkey_mods_zero:[UInt8] = [
            0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0,
            0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
            0x41
        ]
        var key = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 0);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey_mods_zero, 33));
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
    }

    /* Verify signature with s of zero fails. */
    do {
        let pubkey: [UInt8] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01
        ]
        var key = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 0);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 1);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
    }

    /* Verify signature with message 0 passes. */
    do {
        let pubkey: [UInt8] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02
        ]
        let pubkey2: [UInt8] = [
            0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0,
            0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
            0x43
        ]
        var key = secp256k1_ge()
        var key2 = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 2);
        secp256k1_scalar_set_int(&msg, 0);
        secp256k1_scalar_set_int(&sr, 2);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_eckey_pubkey_parse(&key2, pubkey2, 33));
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == true);
        secp256k1_scalar_negate(&ss, ss);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == true);
        secp256k1_scalar_set_int(&ss, 1);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == false);
    }

    /* Verify signature with message 1 passes. */
    do {
        let pubkey: [UInt8] = [
            0x02, 0x14, 0x4e, 0x5a, 0x58, 0xef, 0x5b, 0x22,
            0x6f, 0xd2, 0xe2, 0x07, 0x6a, 0x77, 0xcf, 0x05,
            0xb4, 0x1d, 0xe7, 0x4a, 0x30, 0x98, 0x27, 0x8c,
            0x93, 0xe6, 0xe6, 0x3c, 0x0b, 0xc4, 0x73, 0x76,
            0x25
        ]
        let pubkey2: [UInt8] = [
            0x02, 0x8a, 0xd5, 0x37, 0xed, 0x73, 0xd9, 0x40,
            0x1d, 0xa0, 0x33, 0xd2, 0xdc, 0xf0, 0xaf, 0xae,
            0x34, 0xcf, 0x5f, 0x96, 0x4c, 0x73, 0x28, 0x0f,
            0x92, 0xc0, 0xf6, 0x9d, 0xd9, 0xb2, 0x09, 0x10,
            0x62
        ]
        let csr: [UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
            0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xeb
        ]
        var key = secp256k1_ge()
        var key2 = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 1);
        var dummy_overflow = false
        secp256k1_scalar_set_b32(&sr, csr, &dummy_overflow)
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_eckey_pubkey_parse(&key2, pubkey2, 33));
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == true);
        secp256k1_scalar_negate(&ss, ss);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == true);
        secp256k1_scalar_set_int(&ss, 2);
        secp256k1_scalar_inverse_var(&ss, ss);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key2, msg) == false);
    }

    /* Verify signature with message -1 passes. */
    do {
        let pubkey: [UInt8] = [
            0x03, 0xaf, 0x97, 0xff, 0x7d, 0x3a, 0xf6, 0xa0,
            0x02, 0x94, 0xbd, 0x9f, 0x4b, 0x2e, 0xd7, 0x52,
            0x28, 0xdb, 0x49, 0x2a, 0x65, 0xcb, 0x1e, 0x27,
            0x57, 0x9c, 0xba, 0x74, 0x20, 0xd5, 0x1d, 0x20,
            0xf1
        ]
        let csr: [UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
            0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee
        ]
        var key = secp256k1_ge()
        var msg = secp256k1_scalar()
        var sr = secp256k1_scalar()
        var ss = secp256k1_scalar()
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_set_int(&msg, 1);
        secp256k1_scalar_negate(&msg, msg);
        var dummy: Bool = false
        secp256k1_scalar_set_b32(&sr, csr, &dummy);
        CHECK(secp256k1_eckey_pubkey_parse(&key, pubkey, 33));
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        secp256k1_scalar_negate(&ss, ss);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == true);
        secp256k1_scalar_set_int(&ss, 3);
        secp256k1_scalar_inverse_var(&ss, ss);
        CHECK(secp256k1_ecdsa_sig_verify(ctx.ecmult_ctx, sr, ss, key, msg) == false);
    }

    /* Signature where s would be zero. */
    do {
        var pubkey = secp256k1_pubkey()
        let dummy_pubkey = secp256k1_pubkey()
        var siglen:UInt
        var dummy_siglen: UInt = 0
        var ecount:Int32
        var signature = [UInt8](repeating: 0, count:72)
        var dummy_signature = [UInt8](repeating: 0, count: 0 /*72 */)
        let nonce:[UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]
        let nonce2: [UInt8] = [
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
        ]
        let key: [UInt8] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]
        var msg: [UInt8] = [
            0x86, 0x41, 0x99, 0x81, 0x06, 0x23, 0x44, 0x53,
            0xaa, 0x5f, 0x9d, 0x6a, 0x31, 0x78, 0xf4, 0xf7,
            0xb8, 0x12, 0xe0, 0x0b, 0x81, 0x7a, 0x77, 0x62,
            0x65, 0xdf, 0xdd, 0x31, 0xb9, 0x3e, 0x29, 0xa9,
        ]
        ecount = 0;
        secp256k1_context_set_illegal_callback(&ctx, counting_illegal_callback_fn, &ecount);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == false);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == false);
        msg[31] = 0xaa;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == true);
        CHECK(ecount == 0);
        var dummy_ecdsa_sig = secp256k1_ecdsa_signature()
        dummy_ecdsa_sig.data.removeAll()
        CHECK(secp256k1_ecdsa_sign(ctx, &dummy_ecdsa_sig,  msg, key, precomputed_nonce_function, nonce2) == false);
        CHECK(ecount == 1);
        let dummy_msg = [UInt8](repeating: 0, count: /* 32 */ 0)
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, dummy_msg, key, precomputed_nonce_function, nonce2) == false);
        CHECK(ecount == 2);
        let dummy_key = [UInt8](repeating: 0, count: 0 /*32 */)
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, dummy_key, precomputed_nonce_function, nonce2) == false);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == true);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, key) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, dummy_ecdsa_sig, msg, pubkey) == false);
        CHECK(ecount == 4);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, dummy_msg, pubkey) == false);
        CHECK(ecount == 5);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg, dummy_pubkey) == false);
        CHECK(ecount == 6);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg, pubkey) == true);
        CHECK(ecount == 6);
        let dummy_seckey = [UInt8](repeating: 0, count: 0 /*32 */)
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, dummy_seckey) == false);
        CHECK(ecount == 7);
        /* That pubkeyload fails via an ARGCHECK is a little odd but makes sense because pubkeys are an opaque data type. */
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg, pubkey) == false);
        CHECK(ecount == 8);
        siglen = 72;
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &dummy_signature, &siglen, sig) == false);
        CHECK(ecount == 9);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &signature, &dummy_siglen, sig) == false);
        CHECK(ecount == 10);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &signature, &siglen, dummy_sig) == false);
        CHECK(ecount == 11);
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &signature, &siglen, sig) == true);
        CHECK(ecount == 11);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &dummy_ecdsa_sig, signature, siglen) == false);
        CHECK(ecount == 12);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, dummy_signature, siglen) == false);
        CHECK(ecount == 13);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, signature, siglen) == true);
        CHECK(ecount == 13);
        siglen = 10;
        /* Too little room for a signature does not fail via ARGCHECK. */
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, &signature, &siglen, sig) == false);
        CHECK(ecount == 13);
        ecount = 0;
        var dummy_out_sig = secp256k1_ecdsa_signature()
        dummy_out_sig.data.removeAll()
        CHECK(secp256k1_ecdsa_signature_normalize(ctx, &dummy_ecdsa_sig, dummy_out_sig) == false);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, &dummy_signature, sig) == false);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, &signature, dummy_sig) == false);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, &signature, sig) == true);
        CHECK(ecount == 3);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &dummy_sig, signature) == false);
        CHECK(ecount == 4);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, dummy_signature) == false);
        CHECK(ecount == 5);
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature) == true);
        CHECK(ecount == 5);
        // memset(signature, 255, 64);
        for i in 0 ..< 64 {
            signature[i] = 255
        }
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature) == false);
        CHECK(ecount == 5);
        secp256k1_context_set_illegal_callback(&ctx, nil, nil);
    }

    /* Nonce function corner cases. */
    for t in 0 ..< 2 {
        let zero = [UInt8](repeating: 0, count:32)
        //int i;
        //unsigned char key[32];
        var key = [UInt8](repeating: 0xff, count: 32)
        var msg = [UInt8](repeating: 0, count: 32)
        var sig2 = secp256k1_ecdsa_signature()
        var sr = [secp256k1_scalar](repeating: secp256k1_scalar(), count: 512)
        var ss = secp256k1_scalar()
        //const unsigned char *extra;
        //extra = t == 0 ? NULL : zero;
        var extra: [UInt8]?
        if t == 0 {
            extra = nil
        } else {
            extra = zero
        }
        
        //memset(msg, 0, 32);
        msg[31] = 1;
        /* High key results in signature failure. */
        //memset(key, 0xFF, 32);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nil, extra) == false);
        CHECK(is_empty_signature(sig));
        /* Zero key results in signature failure. */
        //memset(key, 0, 32);
        for i in 0 ..< 32 {
            key[i] = 0
        }
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nil, extra) == false);
        CHECK(is_empty_signature(sig));
        /* Nonce function failure results in signature failure. */
        key[31] = 1;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_fail, extra) == false);
        CHECK(is_empty_signature(sig));
        /* The retry loop successfully makes its way to the first good value. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_retry, extra) == true);
        CHECK(!is_empty_signature(sig));
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nonce_function_rfc6979, extra) == true);
        CHECK(!is_empty_signature(sig2));
        CHECK(sig == sig2) //memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function is deterministic. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nil, extra) == true);
        CHECK(!is_empty_signature(sig2));
        CHECK(sig == sig2) // memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function changes output with different messages. */
        for i in 0 ..< 256 {
            msg[0] = UInt8(i)
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nil, extra) == true);
            CHECK(!is_empty_signature(sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, sig2);
            for j in 0 ..< i {
                CHECK(!secp256k1_scalar_eq(sr[i], sr[j]));
            }
        }
        msg[0] = 0;
        msg[31] = 2;
        /* The default nonce function changes output with different keys. */
        for i in 256 ..< 512 {
            key[0] = UInt8(i - 256)
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nil, extra) == true);
            CHECK(!is_empty_signature(sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, sig2);
            for j in 0 ..< i {
                CHECK(!secp256k1_scalar_eq(sr[i], sr[j]));
            }
        }
        key[0] = 0;
    }

    do {
        /* Check that optional nonce arguments do not have equivalent effect. */
        //const unsigned char zeros[32] = {0};
        let zeros = [UInt8](repeating: 0, count: 32)
        //unsigned char nonce[32];
        var nonce = [UInt8](repeating: 0, count:32)
        var nonce2 = [UInt8](repeating: 0, count:32)
        var nonce3 = [UInt8](repeating: 0, count:32)
        var nonce4 = [UInt8](repeating: 0, count:32)
        //unsigned char nonce2[32];
        //unsigned char nonce3[32];
        //unsigned char nonce4[32];
        //VG_UNDEF(nonce,32);
        //VG_UNDEF(nonce2,32);
        //VG_UNDEF(nonce3,32);
        //VG_UNDEF(nonce4,32);
        CHECK(nonce_function_rfc6979(&nonce, zeros, zeros, nil, nil, 0) == true);
        VG_CHECK(nonce,32);
        CHECK(nonce_function_rfc6979(&nonce2, zeros, zeros, zeros, nil, 0) == true);
        VG_CHECK(nonce2,32);
        CHECK(nonce_function_rfc6979(&nonce3, zeros, zeros, nil, zeros, 0) == true);
        VG_CHECK(nonce3,32);
        CHECK(nonce_function_rfc6979(&nonce4, zeros, zeros, zeros, zeros, 0) == true);
        VG_CHECK(nonce4,32);
        CHECK(memcmp(nonce, nonce2, 32) != 0);
        CHECK(memcmp(nonce, nonce3, 32) != 0);
        CHECK(memcmp(nonce, nonce4, 32) != 0);
        CHECK(memcmp(nonce2, nonce3, 32) != 0);
        CHECK(memcmp(nonce2, nonce4, 32) != 0);
        CHECK(memcmp(nonce3, nonce4, 32) != 0);
    }

    /* Privkey export where pubkey is the point at infinity. */
    do {
        //unsigned char privkey[300];
        var privkey = [UInt8](repeating: 0, count: 300)
        let seckey : [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ]
        var outlen: UInt = 300
        CHECK(!ec_privkey_export_der(ctx, &privkey, &outlen, seckey, false));
        outlen = 300
        CHECK(!ec_privkey_export_der(ctx, &privkey, &outlen, seckey, true));
    }
}

func run_ecdsa_edge_cases() {
    test_ecdsa_edge_cases()
}

/*
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
    //run_context_tests(); // fail
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
    
    /*
    /* scalar tests */
    run_scalar_tests(); // pass

    /* field tests */
    run_field_inv(); // pass
    run_field_inv_var(); // pass
    run_field_inv_all_var(); // pass
    run_field_misc(); // pass
    run_field_convert(); // pass
    run_sqr(); // pass
    run_sqrt(); // pass

    /* group tests */
    run_ge(); // pass
    run_group_decompress(); // pass
     */

    /* ecmult tests */
    /*
    run_wnaf(); // pass
    run_point_times_order(); // pass
     */
    //run_ecmult_chain();
    /*
    run_ecmult_constants(); // pass
    run_ecmult_gen_blind(); // pass
    run_ecmult_const_tests(); // pass

    run_ec_combine(); // pass
     */
    /*
    /* endomorphism tests */
    #if USE_ENDOMORPHISM
        run_endomorphism_tests();
    #endif
     */
    
    /*
    /* EC point parser test */
    run_ec_pubkey_parse_test(); // pass

    /* EC key edge cases */
    run_eckey_edge_case_test(); // pass
     */
    
    /*
    #if ENABLE_MODULE_ECDH
        /* ecdh tests */
        run_ecdh_tests();
    #endif
     */
    
    /* ecdsa tests */
    /*
    run_random_pubkeys(); // pass
    run_ecdsa_der_parse(); // pass
    run_ecdsa_sign_verify(); // pass
    run_ecdsa_end_to_end(); // wait
    run_ecdsa_edge_cases(); // pass
    #if ENABLE_OPENSSL_TESTS
        run_ecdsa_openssl()
    #endif
    
    #if ENABLE_MODULE_RECOVERY
        /* ECDSA pubkey recovery tests */
        run_recovery_tests();
    #endif
     */
    
    secp256k1_rand256(&run32);
    print("random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]);
    /* shutdown */
    secp256k1_context_destroy(&ctx);
}
