//
//  secp256k1AdditionalTests.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2018/03/17.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import XCTest
import secp256k1

class secp256k1AdditionalTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    func testExample1() {
        guard var ctx: secp256k1_context = secp256k1_context_create([.SECP256K1_CONTEXT_SIGN, .SECP256K1_CONTEXT_VERIFY]) else { fatalError() }
        let seckey: [UInt8] = [0,0,0,0,0,0,0,0,
                               0,0,0,0,0,0,0,0,
                               0,0,0,0,0,0,0,0,
                               0,0,0,0,0,0,0,3]
        var pubkey = secp256k1_pubkey()
        let result = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)
        XCTAssert(result)
        print("\(pubkey)")
        
        let msg32:[UInt8] = [0x9a, 0xf1, 0x5b, 0x33, 0x6e, 0x6a, 0x96, 0x19,
                             0x92, 0x85, 0x37, 0xdf, 0x30, 0xb2, 0xe6, 0xa2,
                             0x37, 0x65, 0x69, 0xfc, 0xf9, 0xd7, 0xe7, 0x73,
                             0xec, 0xce, 0xde, 0x65, 0x60, 0x65, 0x29, 0xa0]
        var sig = secp256k1_ecdsa_signature()
        
        let nonce_func: secp256k1_nonce_function = { (
            _ nonce32: inout [UInt8],
            _ msg32: [UInt8],
            _ key32:[UInt8],
            _ algo16:[UInt8]?,
            _ data: [UInt8]?,
            _ counter: UInt
            ) -> Bool in
            guard let data = data else { return false }
            nonce32 = data
            return true
        }
        // noncedata: BigEndian
        let noncedata: [UInt8] = [0,0,0,0,0,0,0,0,
                                  0,0,0,0,0,0,0,0,
                                  0,0,0,0,0,0,0,0,
                                  0,0,0,0,0,0,0,2]
        let ret2 = secp256k1_ecdsa_sign(ctx, &sig, msg32, seckey, nonce_func, noncedata)
        XCTAssert(ret2)
        print("\(sig)")
        
        let ret3 = secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey)
        XCTAssert(ret3)
        
        secp256k1_context_destroy(&ctx)
    }
    
}
