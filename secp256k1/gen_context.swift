//
//  gen_context.swift
//  secp256k1
//
//  Created by pebble8888 on 2018/02/17.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation

func default_error_callback_fn(str: [UInt8], data: UnsafeRawPointer?){
    print("[libsecp256k1] internal consistency check failed: \(str)\n")
    fatalError()
}

fileprivate let default_error_callback: secp256k1_callback = secp256k1_callback(
    fn: default_error_callback_fn,
    data: nil
)
