//
//  secp256k1s.swift
//  secp256k1ref
//
//  Created by pebble8888 on 2017/12/02.
//  Copyright © 2017年 pebble8888. All rights reserved.
//

import Foundation
import BigInt

public struct secp256k1s {
    public struct Point : CustomDebugStringConvertible {
        public var x:BigInt
        public var y:BigInt
        public var infinity:Bool
        
        public init(_ x:BigInt, _ y:BigInt, _ infinity:Bool = false){
            self.x = x
            self.y = y
            self.infinity = infinity
        }
        public static func Infinity() -> Point {
            return Point(0, 0, true)
        }
        
        public var debugDescription: String {
            if infinity {
                return "infinity"
            }
            return "(\(x),\(y))"
        }
    }
    // modulo prime
    public static let q:BigInt = BigInt(2).power(256) - BigInt(2).power(32) - 977
    // order of base point (prime)
    public static let L:BigInt = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix:16)!
    // base point
    public static let Bx:BigInt = BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", radix:16)!
    public static let By:BigInt = BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", radix:16)!
    public static let B:Point = Point(Bx.modulo(q), By.modulo(q))
    
    public static func double_pt(_ P:Point) -> Point
    {
        if P.infinity { return P }
        let x = P.x
        let y = P.y
        let nu = 3 * BigInt.expmod(x,2,q) * BigInt.inv(2*y,q)
        let x3 = BigInt.expmod(nu,2,q) - 2*x
        let y3 = nu*(x-x3) - y
        return Point(x3.modulo(q), y3.modulo(q))
    }
    
    public static func add_pt(_ P:Point, _ Q:Point) -> Point {
        let x1 = P.x
        let y1 = P.y
        let x2 = Q.x
        let y2 = Q.y
        if P.infinity { return Q }
        if Q.infinity { return P }
        if x1 == x2 {
            if (y1 + y2).modulo(q) == 0 {
                return Point.Infinity()
            } else {
                return double_pt(P)
            }
        }
        let lm = (y1-y2)*BigInt.inv(x1-x2,q)
        let x3 = BigInt.expmod(lm,2,q)-(x1+x2)
        let y3 = lm*(x1-x3)-y1
        return Point(x3.modulo(q), y3.modulo(q))
    }
    
    public static func scalarmult(_ P:Point, _ e:BigInt) -> Point
    {
        if e == 0 { return Point.Infinity() }
        var Q = scalarmult(P, e/2)
        Q = add_pt(Q, Q)
        if e.parity() == 1 {
            Q = add_pt(Q, P)
        }
        return Q
    }
   
    public static func isoncurve(_ P:Point) -> Bool {
        if P.infinity { return true }
        return (P.y.power(2) - P.x.power(3) - BigInt(7)).modulo(q) == 0
    }
}
