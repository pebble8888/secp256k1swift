//
//  tests_recovery.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/19.
//  Copyright © 2018年 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation
@testable import secp256k1


func recovery_test_nonce_function(_ nonce32: inout [UInt8], _ msg32: [UInt8], _ key32: [UInt8], _ algo16: [UInt8]?, _ data: [UInt8]?, _ counter: UInt) -> Bool {

    /* On the first run, return 0 to force a second run */
    if (counter == 0) {
        for i in 0 ..< 32 {
            nonce32[i] = 0
        }
        return true
    }
    /* On the second run, return an overflow to force a third run */
    if (counter == 1) {
        for i in 0 ..< 32 {
            nonce32[i] = 0xff
        }
        return true
    }
    /* On the next run, return a valid nonce, but flip a coin as to whether or not to fail signing. */
    for i in 0 ..< 32 {
        nonce32[i] = 1;
    }
    return secp256k1_rand_bits(1) != 0
}

func test_ecdsa_recovery_api() {
    /* Setup contexts that just count errors */
    guard var none: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_NONE) else { fatalError() }
    guard var sign: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_SIGN) else { fatalError() }
    guard var vrfy: secp256k1_context = secp256k1_context_create(.SECP256K1_CONTEXT_VERIFY) else { fatalError() }
    guard var both: secp256k1_context =
        secp256k1_context_create([.SECP256K1_CONTEXT_SIGN, .SECP256K1_CONTEXT_VERIFY]) else { fatalError() }
    var pubkey = secp256k1_pubkey()
    var recpubkey = secp256k1_pubkey()
    var normal_sig = secp256k1_ecdsa_signature()
    var recsig = secp256k1_ecdsa_recoverable_signature()
    let privkey = [UInt8](repeating: 1, count:32)
    let message = [UInt8](repeating: 2, count:32)
    var ecount:Int32 = 0;
    var recid: Int = 0;
    var sig = [UInt8](repeating: 0, count:74)
    let zero_privkey = [UInt8](repeating: 0, count:32)
    var over_privkey: [UInt8] = /* [32] = */ [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    ]
    
    secp256k1_context_set_error_callback(&none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(&sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(&vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(&both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(&none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(&sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(&vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(&both, counting_illegal_callback_fn, &ecount);
    
    /* Construct and verify corresponding public key. */
    guard let ctx = ctx else { fatalError() }
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == true);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == true);
    
    /* Check bad contexts and NULLs for signing */
    ecount = 0;
    CHECK(secp256k1_ecdsa_sign_recoverable(none, &recsig, message, privkey, nil, nil) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_sign_recoverable(sign, &recsig, message, privkey, nil, nil) == true);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_sign_recoverable(vrfy, &recsig, message, privkey, nil, nil) == false);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, privkey, nil, nil) == true);
    CHECK(ecount == 2);
    var dummy_sig = secp256k1_ecdsa_recoverable_signature()
    dummy_sig.data = []
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &dummy_sig, message, privkey, nil, nil) == false);
    CHECK(ecount == 3);
    let dummy_msg32 = [UInt8](repeating:0, count: 0)
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, dummy_msg32, privkey, nil, nil) == false);
    CHECK(ecount == 4);
    let dummy_seckey = [UInt8](repeating:0, count: 0)
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, dummy_seckey, nil, nil) == false);
    CHECK(ecount == 5);
    /* This will fail or succeed randomly, and in either case will not ARG_CHECK failure */
    let _ = secp256k1_ecdsa_sign_recoverable(both, &recsig, message, privkey, recovery_test_nonce_function, nil);
    CHECK(ecount == 5);
    /* These will all fail, but not in ARG_CHECK way */
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, zero_privkey, nil, nil) == false);
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, over_privkey, nil, nil) == false);
    /* This one will succeed. */
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, privkey, nil, nil) == true);
    CHECK(ecount == 5);
    
    /* Check signing with a goofy nonce function */
    
    /* Check bad contexts and NULLs for recovery */
    ecount = 0;
    CHECK(secp256k1_ecdsa_recover(none, &recpubkey, recsig, message) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_recover(sign, &recpubkey, recsig, message) == false);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_recover(vrfy, &recpubkey, recsig, message) == true);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_recover(both, &recpubkey, recsig, message) == true);
    CHECK(ecount == 2);
    var dummy_pubkey = secp256k1_pubkey()
    dummy_pubkey.data = []
    CHECK(secp256k1_ecdsa_recover(both, &dummy_pubkey, recsig, message) == false);
    CHECK(ecount == 3);
    dummy_sig.data = []
    CHECK(secp256k1_ecdsa_recover(both, &recpubkey, dummy_sig, message) == false);
    CHECK(ecount == 4);
    let dummy_msg = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ecdsa_recover(both, &recpubkey, recsig, dummy_msg) == false);
    CHECK(ecount == 5);
    
    /* Check NULLs for conversion */
    CHECK(secp256k1_ecdsa_sign(both, &normal_sig, message, privkey, nil, nil) == true);
    ecount = 0;
    var dummy1_sig = secp256k1_ecdsa_signature()
    dummy1_sig.data = []
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(both, &dummy1_sig, recsig) == false);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(both, &normal_sig, dummy_sig) == false);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(both, &normal_sig, recsig) == true);
    
    /* Check NULLs for de/serialization */
    CHECK(secp256k1_ecdsa_sign_recoverable(both, &recsig, message, privkey, nil, nil) == true);
    ecount = 0;
    var output64_dummy = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(both, &output64_dummy, &recid, recsig) == false);
    CHECK(ecount == 1);
    /*
    var dummy_recid: Int = 0
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(both, &sig, &dummy_recid, recsig) == false);
     */
    ecount = 2;
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(both, &sig, &recid, dummy_sig) == false);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(both, &sig, &recid, recsig) == true);
   
    var dummy2_sig = secp256k1_ecdsa_recoverable_signature()
    dummy2_sig.data = []
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(both, &dummy2_sig, sig, recid) == false);
    CHECK(ecount == 4);
    let dummy_input64 = [UInt8](repeating: 0, count: 0)
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(both, &recsig, dummy_input64, recid) == false);
    CHECK(ecount == 5);
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(both, &recsig, sig, -1) == false);
    CHECK(ecount == 6);
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(both, &recsig, sig, 5) == false);
    CHECK(ecount == 7);
    /* overflow in signature will fail but not affect ecount */
    for i in 0 ..< 32 {
        sig[i] = over_privkey[i]
    }
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(both, &recsig, sig, recid) == false);
    CHECK(ecount == 7);
    
    /* cleanup */
    secp256k1_context_destroy(&none);
    secp256k1_context_destroy(&sign);
    secp256k1_context_destroy(&vrfy);
    secp256k1_context_destroy(&both);
}

func test_ecdsa_recovery_end_to_end() {
    var extra = [UInt8](repeating: 0, count: 32)
    var privkey = [UInt8](repeating: 0, count: 32)
    var message = [UInt8](repeating: 0, count: 32)
    var signature = [secp256k1_ecdsa_signature](repeating: secp256k1_ecdsa_signature(), count:5)
    var rsignature = [secp256k1_ecdsa_recoverable_signature](repeating: secp256k1_ecdsa_recoverable_signature(), count:5)
    var sig = [UInt8](repeating: 0, count:74)
    var pubkey = secp256k1_pubkey()
    var recpubkey = secp256k1_pubkey()
    var recid: Int = 0;
    
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
    
    /* Serialize/parse compact and verify/recover. */
    extra[0] = 0;
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &rsignature[0], message, privkey, nil, nil) == true);
    CHECK(secp256k1_ecdsa_sign(ctx, &signature[0], message, privkey, nil, nil) == true);
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &rsignature[4], message, privkey, nil, nil) == true);
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &rsignature[1], message, privkey, nil, extra) == true);
    extra[31] = 1;
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &rsignature[2], message, privkey, nil, extra) == true);
    extra[31] = 0;
    extra[0] = 1;
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &rsignature[3], message, privkey, nil, extra) == true);
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &sig, &recid, rsignature[4]) == true);
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature[4], rsignature[4]) == true);
    CHECK(signature[4] == signature[0]);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[4], message, pubkey) == true);
    rsignature[4].clear()
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsignature[4], sig, recid) == true);
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature[4], rsignature[4]) == true);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[4], message, pubkey) == true);
    /* Parse compact (with recovery id) and recover. */
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsignature[4], sig, recid) == true);
    CHECK(secp256k1_ecdsa_recover(ctx, &recpubkey, rsignature[4], message) == true);
    CHECK(pubkey == recpubkey)
    /* Serialize/destroy/parse signature and verify again. */
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &sig, &recid, rsignature[4]) == true);
    let idx = Int(secp256k1_rand_bits(6))
    sig[idx] = sig[idx] &+ UInt8(1) &+ UInt8(secp256k1_rand_int(255))
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsignature[4], sig, recid) == true);
    CHECK(secp256k1_ecdsa_recoverable_signature_convert(ctx, &signature[4], rsignature[4]) == true);
    CHECK(secp256k1_ecdsa_verify(ctx, signature[4], message, pubkey) == false);
    /* Recover again */
    CHECK(secp256k1_ecdsa_recover(ctx, &recpubkey, rsignature[4], message) == false ||
        pubkey != recpubkey)
}

/* Tests several edge cases. */
func test_ecdsa_recovery_edge_cases() {
    let msg32: [UInt8] = "This is a very secret message...".toUInt8
    let sig64: [UInt8] /* [64] */ = [
        /* Generated by signing the above message with nonce 'This is the nonce we will use...'
         * and secret key 0 (which is not valid), resulting in recid 0. */
        0x67, 0xCB, 0x28, 0x5F, 0x9C, 0xD1, 0x94, 0xE8,
        0x40, 0xD6, 0x29, 0x39, 0x7A, 0xF5, 0x56, 0x96,
        0x62, 0xFD, 0xE4, 0x46, 0x49, 0x99, 0x59, 0x63,
        0x17, 0x9A, 0x7D, 0xD1, 0x7B, 0xD2, 0x35, 0x32,
        0x4B, 0x1B, 0x7D, 0xF3, 0x4C, 0xE1, 0xF6, 0x8E,
        0x69, 0x4F, 0xF6, 0xF1, 0x1A, 0xC7, 0x51, 0xDD,
        0x7D, 0xD7, 0x3E, 0x38, 0x7E, 0xE4, 0xFC, 0x86,
        0x6E, 0x1B, 0xE8, 0xEC, 0xC7, 0xDD, 0x95, 0x57
    ]
    var pubkey = secp256k1_pubkey()
    /* signature (r,s) = (4,4), which can be recovered with all 4 recids. */
    let sigb64: [UInt8] /* [64] */ = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    ]
    var pubkeyb = secp256k1_pubkey()
    var rsig = secp256k1_ecdsa_recoverable_signature()
    var sig = secp256k1_ecdsa_signature()

    guard let ctx = ctx else { fatalError() }
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sig64, 0));
    CHECK(!secp256k1_ecdsa_recover(ctx, &pubkey, rsig, msg32));
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sig64, 1));
    CHECK(secp256k1_ecdsa_recover(ctx, &pubkey, rsig, msg32));
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sig64, 2));
    CHECK(!secp256k1_ecdsa_recover(ctx, &pubkey, rsig, msg32));
    CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sig64, 3));
    CHECK(!secp256k1_ecdsa_recover(ctx, &pubkey, rsig, msg32));
    
    for recid in 0 ..< 4 {
        /* (4,4) encoded in DER. */
        var sigbder : [UInt8] /*[8] */ = [0x30, 0x06, 0x02, 0x01, 0x04, 0x02, 0x01, 0x04]
        let sigcder_zr: [UInt8] /*[7] */ = [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]
        let sigcder_zs: [UInt8] /*[7] */ = [0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00]
        let sigbderalt1: [UInt8] /*[39] */ = [
            0x30, 0x25, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x04, 0x02, 0x01, 0x04,
        ]
        let sigbderalt2: [UInt8] /*[39] */ = [
            0x30, 0x25, 0x02, 0x01, 0x04, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        ]
        var sigbderalt3: [UInt8] /*[40] */ = [
            0x30, 0x26, 0x02, 0x21, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x01, 0x04,
        ]
        var sigbderalt4: [UInt8] /*[40] */ = [
            0x30, 0x26, 0x02, 0x01, 0x04, 0x02, 0x21, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        ]
        /* (order + r,4) encoded in DER. */
        let sigbderlong: [UInt8] /*[40] */ = [
            0x30, 0x26, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC,
            0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E,
            0x8C, 0xD0, 0x36, 0x41, 0x45, 0x02, 0x01, 0x04
        ]
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sigb64, recid) == true);
        CHECK(secp256k1_ecdsa_recover(ctx, &pubkeyb, rsig, msg32) == true);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, UInt(sigbder.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == true);
        for recid2 in 0 ..< 4 {
            var pubkey2b = secp256k1_pubkey()
            CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sigb64, recid2) == true);
            CHECK(secp256k1_ecdsa_recover(ctx, &pubkey2b, rsig, msg32) == true);
            /* Verifying with (order + r,4) should always fail. */
            CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderlong, UInt(sigbderlong.count)) == true);
            CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == false);
        }
        /* DER parsing tests. */
        /* Zero length r/s. */
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigcder_zr, UInt(sigcder_zr.count)) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigcder_zs, UInt(sigcder_zs.count)) == false);
        /* Leading zeros. */
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt1, UInt(sigbderalt1.count)) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt2, UInt(sigbderalt2.count)) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt3, UInt(sigbderalt3.count)) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt4, UInt(sigbderalt4.count)) == false);
        sigbderalt3[4] = 1;
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt3, UInt(sigbderalt3.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == false);
        sigbderalt4[7] = 1;
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbderalt4, UInt(sigbderalt4.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == false);
        /* Damage signature. */
        sigbder[7] += 1
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, UInt(sigbder.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == false);
        sigbder[7] -= 1
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, 6) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, UInt(sigbder.count - 1)) == false);
        for i in 0 ..< 8 {
            let orig:UInt8 = sigbder[i];
            /*Try every single-byte change.*/
            for c in 0 ..< 256 {
                if (c == orig) {
                    continue;
                }
                sigbder[i] = UInt8(c)
                CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbder, UInt(sigbder.count)) == false || secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyb) == false)
            }
            sigbder[i] = orig;
        }
    }
    
    /* Test r/s equal to zero */
    do {
        /* (1,1) encoded in DER. */
        var sigcder: [UInt8] /*[8] */ = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
        var sigc64: [UInt8] /*[64] */ = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]
        var pubkeyc = secp256k1_pubkey()
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sigc64, 0) == true);
        CHECK(secp256k1_ecdsa_recover(ctx, &pubkeyc, rsig, msg32) == true);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigcder, UInt(sigcder.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyc) == true);
        sigcder[4] = 0;
        sigc64[31] = 0;
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sigc64, 0) == true);
        CHECK(secp256k1_ecdsa_recover(ctx, &pubkeyb, rsig, msg32) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigcder, UInt(sigcder.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyc) == false);
        sigcder[4] = 1;
        sigcder[7] = 0;
        sigc64[31] = 1;
        sigc64[63] = 0;
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, sigc64, 0) == true);
        CHECK(secp256k1_ecdsa_recover(ctx, &pubkeyb, rsig, msg32) == false);
        CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigcder, UInt(sigcder.count)) == true);
        CHECK(secp256k1_ecdsa_verify(ctx, sig, msg32, pubkeyc) == false);
    }
}

func run_recovery_tests() {
    timelog("test_ecdsa_recovery_api")
    for i in 0 ..< g_count {
        print("\(i) ", terminator:"")
        test_ecdsa_recovery_api();
    }
    timelog("test_ecdsa_recovery_end_to_end")
    for i in 0 ..< 64*g_count {
        if i % 10 == 0 {
            print("\(i) ", terminator:"")
        }
        test_ecdsa_recovery_end_to_end();
    }
    test_ecdsa_recovery_edge_cases();
}
