#!/usr/bin/env python

#import sympy

q = 2**256 - 2**32 - 977
l = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#print sympy.isprime(q)
#print sympy.isprime(l)

def expmod(b,e,m):
    if e == 0: return 1
    t = expmod(b,e/2,m)**2 % m
    if e & 1: t = (t*b) % m
    return t

def inv(x):
    return expmod(x,q-2,q)

def double_pt(P):
    x = P[0]
    y = P[1]
    if y == 0: return [0, 0]
    nu = 3*expmod(x,2,q)*inv(2*y)
    x3 = expmod(nu,2,q)-2*x
    y3 = nu*(x-x3)-y
    return [x3 % q, y3 % q]

def add_pt(P, Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    if y1 == 0: return Q
    if y2 == 0: return P
    if x1 == x2:
        if y1 == y2:
            return double_pt(P)
        else:
            return [0, 0]

    lm = (y1-y2)*inv(x1-x2)
    x3 = expmod(lm,2,q)-(x1+x2)
    y3 = lm*(x1-x3)-y1
    return [x3 % q, y3 % q]

def scalarmult(P, e):
    if e == 0: return [0, 0]
    Q = scalarmult(P, e/2)
    Q = add_pt(Q, Q)
    if e & 1: Q = add_pt(Q, P)
    return Q

def isoncurve(P):
    x = P[0]
    y = P[1]
    return (y**2 - x**3 - 7) % q == 0

Bx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
By = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B = [Bx, By]
B2 = double_pt(B)
print "q  = %x" % q
print "Bx = %x" % Bx
print "By = %x" % By
print "l  = %x" % l
if isoncurve(B):
    print "B is on curve"
else:
    assert False, "B is not on curve!"

#print "    2*G= %x,%x" % (B2[0], B2[1])
#C = add_pt(B, B2)
#print "  G+2*G= %x,%x" % (C[0], C[1])
#D = add_pt(B2, B2)
#print "2*G+2*G= %x,%x" % (D[0], D[1])

# 
#privkey= 0xf8ef380d6c05116dbed78bfdd6e6625e57426af9a082b81c2fa27b06984c11f3
#PUBKEY= scalarmult(B, privkey)
#print " -> pubkey= (%x,%x)" % (PUBKEY[0], PUBKEY[1]) 
#
#"""
#for reference, the numbers printed should be:
#2*G= (c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a)
#G+2*G= (f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672)
#2*G+2*G= (e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13,51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922)
#-> pubkey= (71ee918bc19bb566e3a5f12c0cd0de620bec1025da6e98951355ebbde8727be3,37b3650efad4190b7328b1156304f2e9e23dbb7f2da50999dde50ea73b4c2688)
#"""
T = scalarmult(B, l)
print "T  = (%x, %x)" % (T[0], T[1])

