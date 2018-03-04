//
//  util.swift
//  secp256k1
//
//  Created by pebble8888 on 2018/02/17.
//  Copyright © 2018 pebble8888. All rights reserved.
//
/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

import Foundation

//#if defined HAVE_CONFIG_H
//    #include "libsecp256k1-config.h"
//#endif

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
 */

struct secp256k1_callback {
    //void (*fn)(const char *text, void* data);
    var fn: (_ text: String, _ data: UnsafeMutableRawPointer? /*[UInt8] */) -> Void
    // const void* data;
    var data: UnsafeMutableRawPointer? // [UInt8]?
}

func secp256k1_callback_call(_ cb: secp256k1_callback, _ text: String) {
    cb.fn(text, cb.data)
}

 /*
#ifdef DETERMINISTIC
#define TEST_FAILURE(msg) do { \
    fprintf(stderr, "%s\n", msg); \
        abort(); \
} while(0);
#else
#define TEST_FAILURE(msg) do { \
fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
abort(); \
} while(0)
#endif

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#ifdef DETERMINISTIC
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed"); \
    } \
} while(0)
#else
#define CHECK(cond) do { \
if (EXPECT(!(cond), 0)) { \
TEST_FAILURE("test condition failed: " #cond); \
} \
} while(0)
#endif

/* Like assert(), but when VERIFY is defined, and side-effect safe. */
#if defined(COVERAGE)
    #define VERIFY_CHECK(check)
    #define VERIFY_SETUP(stmt)
    #elif defined(VERIFY)
    #define VERIFY_CHECK CHECK
    #define VERIFY_SETUP(stmt) do { stmt; } while(0)
    #else
    #define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
    #define VERIFY_SETUP(stmt)
    #endif
    
    static SECP256K1_INLINE void *checked_malloc(const secp256k1_callback* cb, size_t size) {
        void *ret = malloc(size);
        if (ret == NULL) {
            secp256k1_callback_call(cb, "Out of memory");
        }
        return ret;
}
    
    /* Macro for restrict, when available and not in a VERIFY build. */
#if defined(SECP256K1_BUILD) && defined(VERIFY)
    # define SECP256K1_RESTRICT
    #else
    # if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
    #  if SECP256K1_GNUC_PREREQ(3,0)
    #   define SECP256K1_RESTRICT __restrict__
    #  elif (defined(_MSC_VER) && _MSC_VER >= 1400)
    #   define SECP256K1_RESTRICT __restrict
    #  else
    #   define SECP256K1_RESTRICT
    #  endif
    # else
    #  define SECP256K1_RESTRICT restrict
    # endif
    #endif
    
#if defined(_WIN32)
    # define I64FORMAT "I64d"
    # define I64uFORMAT "I64u"
    #else
    # define I64FORMAT "lld"
    # define I64uFORMAT "llu"
    #endif
    
#if defined(HAVE___INT128)
    # if defined(__GNUC__)
    #  define SECP256K1_GNUC_EXT __extension__
    # else
    #  define SECP256K1_GNUC_EXT
    # endif
    SECP256K1_GNUC_EXT typedef unsigned __int128 uint128_t;
#endif

*/

func UInt8ToUInt32LE(_ dst: inout [UInt32],
                    _ dst_begin: Int,
                    _ src: [UInt8],
                    _ src_begin: Int,
                    _ size: UInt)
{
    //assert((size % 4) == 0)
    //let count = size / 4
    //var i = 0
    //for i in 0..<Int(count) {
    var dst_idx = dst_begin
    var src_idx = src_begin
    while dst_idx < dst.count {
        if src_idx >= size { break }
        dst[dst_idx] = UInt32(src[src_idx])
        src_idx += 1
        
        if src_idx >= size { break }
        dst[dst_idx] += UInt32(src[src_idx]) << 8
        src_idx += 1
        
        if src_idx >= size { break }
        dst[dst_idx] += UInt32(src[src_idx]) << 16
        src_idx += 1
        
        if src_idx >= size { break }
        dst[dst_idx] += UInt32(src[src_idx]) << 24
        src_idx += 1
        
        dst_idx += 1
    }
}

func UInt32LEToUInt8(_ dst: inout [UInt8], _ src: [UInt32] /* size: 2 */)
{
    assert(dst.count == src.count * 4)
    //assert(src.count == 2)
    for i in 0..<src.count {
        dst[i*4]     = UInt8(0xff & src[i])
        dst[i*4 + 1] = UInt8(0xff & (src[i] >> 8))
        dst[i*4 + 2] = UInt8(0xff & (src[i] >> 16))
        dst[i*4 + 3] = UInt8(0xff & (src[i] >> 24))
    }
}

func UInt32BEToUInt8(_ dst: inout [UInt8], _ dst_idx: Int, _ src: UInt32)
{
    assert(dst_idx >= 0)
    assert(dst_idx + 3 < dst.count)
    dst[dst_idx]     = UInt8(0xff & (src >> 24))
    dst[dst_idx + 1] = UInt8(0xff & (src >> 16))
    dst[dst_idx + 2] = UInt8(0xff & (src >> 8))
    dst[dst_idx + 3] = UInt8(0xff & src)
}

public extension UInt64
{
    var lo: UInt32 {
        return UInt32(self & UInt64(UInt32.max))
    }
    var hi: UInt32 {
        return UInt32((self >> 32) & UInt64(UInt32.max))
    }
}

public extension UInt32
{
    var lo: UInt16 {
        return UInt16(self & UInt32(UInt16.max))
    }
    var hi: UInt16 {
        return UInt16((self >> 16) & UInt32(UInt16.max))
    }
}

extension Collection where Iterator.Element == UInt8 {
    public func toLEUInt32() -> [UInt32]? {
        if self.count % 4 != 0 {
            return nil
        }
        let c = Int(self.count / 4)
        var v = [UInt32](repeating: 0, count: c)
        var it = self.makeIterator()
        for i in 0 ..< c {
            guard let a = it.next() else { break }
            v[i] += UInt32(a)
            guard let b = it.next() else { break }
            v[i] += (UInt32(b) << 8)
            guard let c = it.next() else { break }
            v[i] += (UInt32(c) << 16)
            guard let d = it.next() else { break }
            v[i] += (UInt32(d) << 24)
        }
        return v
    }
}

extension String {
    public func unhexlify() -> [UInt8] {
        var pos = startIndex
        return (0..<self.count/2).flatMap { _ in
            defer { pos = index(pos, offsetBy: 2) }
            return UInt8(self[pos...index(after: pos)], radix: 16)
        }
    }
}
