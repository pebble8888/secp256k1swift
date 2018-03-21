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

    func testExample() {
        guard var ctx = secp256k1_context_create(.SECP256K1_CONTEXT_NONE) else { fatalError() }
        defer { secp256k1_context_destroy(&ctx) }
        var seckey = [UInt8](repeating: 0, count: 32)
        seckey[31] = 1
        XCTAssert(secp256k1_ec_seckey_verify(ctx, seckey))
    }

}
