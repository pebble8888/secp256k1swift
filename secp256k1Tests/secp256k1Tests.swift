//
//  secp256k1Tests.swift
//  secp256k1Tests
//
//  Created by pebble8888 on 2017/10/16.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import XCTest
@testable import secp256k1

class secp256k1Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testHash(){
        test_type(.hash)
    }
    
    // long time need
    func testScalar(){
        test_type(.scalar)
    }
    
    func testField(){
        test_type(.field)
    }
    
    // long time need
    func testGroup(){
        test_type(.group)
    }
    
    // long time need
    func testEcmult(){
        test_type(.ecmult)
    }
    
    // long time need
    func testEc(){
        test_type(.ec)
    }
    
    // long time need
    func testEcdsa(){
        test_type(.ecdsa)
    }

    func test_type(_ type: TestType){
        test_main(1, "00000000000000000000000000000000", type)
    }
}
   
