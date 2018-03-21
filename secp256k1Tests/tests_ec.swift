//
//  tests_ec.swift
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
@testable import secp256k1

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
        //memcpy(&pubkeyc[1], input, 64);
        for i in 0 ..< 64 {
            pubkeyc[1+i] = input[i]
        }
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
    assert(ctmp.count == 33)
    for i in 0 ..< 32 {
        ctmp[i] = orderc[i]
    }
    assert(ctmp.count == 33)
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
    assert(ctmp.count == 33)
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, ctmp2) == true);
    assert(ctmp.count == 33)
    CHECK(orderc.compare(ctmp, count:31) && ctmp[31] == 0x40) //memcmp(orderc, ctmp, 31) == 0 && ctmp[31] == 0x40);
    //memcpy(&pubkey2, &pubkey, sizeof(pubkey));
    pubkey2 = pubkey
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == true);
    CHECK(pubkey.equal(pubkey2)) // memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    /* Multiply tweak of zero zeroizes the output. */
    assert(ctmp.count == 33)
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, ctmp2) == false);
    assert(ctmp.count == 33)
    //CHECK(memcmp(zeros, ctmp, 32) == 0);
    for i in 0 ..< 32 {
        CHECK(ctmp[i] == 0)
    }
    CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, ctmp2) == false);
    CHECK(pubkey.is_zero()) // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    /* Overflowing key tweak zeroizes. */
    //memcpy(ctmp, orderc, 32);
    for i in 0 ..< 32 {
        ctmp[i] = orderc[i]
    }
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, orderc) == false);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    //memcpy(ctmp, orderc, 32);
    for i in 0 ..< 32 {
        ctmp[i] = orderc[i]
    }
    ctmp[31] = 0x40;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, orderc) == false);
    CHECK(memcmp(zeros, ctmp, 32) == 0);
    //memcpy(ctmp, orderc, 32);
    for i in 0 ..< 32 {
        ctmp[i] = orderc[i]
    }
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
    //CHECK( memcmp(zeros, ctmp2, 32) == 0);
    for i in 0 ..< 32 {
        CHECK(zeros[i] == ctmp2[i])
    }
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, ctmp2) == false);
    CHECK(pubkey.is_zero()) // // memcmp(&pubkey, zeros, sizeof(pubkey)) == 0);
    //memcpy(&pubkey, &pubkey2, sizeof(pubkey));
    pubkey = pubkey2
    /* Tweak computation wraps and results in a key of 1. */
    ctmp2[31] = 2;
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp2, ctmp) == true);
    //CHECK(memcmp(ctmp2, zeros, 31) == 0 && ctmp2[31] == 1);
    for i in 0 ..< 31 {
        CHECK(ctmp2[i] == 0)
    }
    CHECK(ctmp2[31] == 1)
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
    assert(ctmp.count == 33)
    CHECK(secp256k1_ec_privkey_tweak_add(ctx, &ctmp, dummy_seckey) == false);
    assert(ctmp.count == 33)
    CHECK(ecount == 2);
    ecount = 0;
    //memset(ctmp2, 0, 32);
    ctmp2.clear(count:32)
    ctmp2[31] = 1;
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &dummy_tmp, ctmp2) == false);
    CHECK(ecount == 1);
    assert(ctmp.count == 33)
    CHECK(secp256k1_ec_privkey_tweak_mul(ctx, &ctmp, dummy_tmp) == false);
    assert(ctmp.count == 33)
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
    CHECK(!pubkey.is_zero())
    CHECK(ecount == 3);
    len = 33;
    assert(ctmp.count == 33)
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
