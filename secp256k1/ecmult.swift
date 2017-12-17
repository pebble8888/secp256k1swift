/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
//
//  ecmult.swift
//  secp256k1
//
//  Created by pebble8888 on 2018/02/17.
//  Copyright © 2018年 pebble8888. All rights reserved.
//

import Foundation

//#include "num.h"
//#include "group.h"

//typealias Pre_G = () -> secp256k1_ge_storage

struct secp256k1_ecmult_context {
    /* For accelerating the computation of a*P + b*G: */
    var pre_g: [/*Pre_G*/ secp256k1_ge_storage]    /* odd multiples of the generator */
    init() {
        pre_g = [secp256k1_ge_storage](repeating: secp256k1_ge_storage(), count: 0)
    }
}
