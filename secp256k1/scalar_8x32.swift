//
//  scalar_8x32.swift
//  secp256k1
//
//  Created by pebble8888 on 2018/02/17.
//  Copyright © 2018 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation

/** A scalar modulo the group order of the secp256k1 curve. */
struct secp256k1_scalar
{
    //uint32_t d[8];
    var d: [UInt32] // size: 8
    init(){
        d = [UInt32](repeating: 0, count: 8)
    }
}

//#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}
