//
//  secp256k1refTests.swift
//  secp256k1refTests
//
//  Created by pebble8888 on 2017/10/16.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
@testable import secp256k1ref

class secp256k1refTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        print("q = \(secp256k1s.q.hexDescription())")
        print("Bx = \(secp256k1s.Bx.hexDescription())")
        print("By = \(secp256k1s.By.hexDescription())")
        print("L = \(secp256k1s.L.hexDescription())")
        XCTAssert(secp256k1s.isoncurve(secp256k1s.B), "B is not on curve")
        
        let T = secp256k1s.scalarmult(secp256k1s.B, secp256k1s.L)
        XCTAssert(T.infinity, "T is not infinity")
        print("T = \(T)")
        
    }
    
}
