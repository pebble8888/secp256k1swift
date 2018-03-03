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
    var fn: (_ text: String, _ data: [UInt8]?) -> Void
    // const void* data;
    var data: [UInt8]?
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
    assert((size % 4) == 0)
    let count = size / 4
    for i in 0..<Int(count) {
        dst[i + dst_begin] = UInt32(src[i + src_begin])
        dst[i + dst_begin] += UInt32(src[i + src_begin + 1]) << 8
        dst[i + dst_begin] += UInt32(src[i + src_begin + 2]) << 16
        dst[i + dst_begin] += UInt32(src[i + src_begin + 3]) << 24
    }
}

func UInt32LEToUInt8(_ dst: inout [UInt8], _ src: [UInt32] /* size: 2 */)
{
    assert(dst.count == 8)
    assert(src.count == 2)
    for i in 0..<src.count {
        dst[i*4]     = UInt8(0xff & src[i])
        dst[i*4 + 1] = UInt8(0xff & (src[i] >> 8))
        dst[i*4 + 2] = UInt8(0xff & (src[i] >> 16))
        dst[i*4 + 3] = UInt8(0xff & (src[i] >> 24))
    }
}

extension UInt64
{
    var lo: UInt32 {
        return UInt32(self & UInt64(0xffffffff))
    }
    var hi: UInt32 {
        return UInt32((self >> 32) & UInt64(0xffffffff))
    }
}
