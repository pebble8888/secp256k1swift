//
//  tests_context.swift
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
    CHECK(secp256k1_ec_pubkey_tweak_mul(vrfy, &pubkey, ctmp) == true);
    CHECK(ecount == 3);
    CHECK(secp256k1_context_randomize(&vrfy, ctmp) == false);
    CHECK(ecount == 4);
    CHECK(secp256k1_context_randomize(&sign, nil) == true)
    CHECK(ecount2 == 14)
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

