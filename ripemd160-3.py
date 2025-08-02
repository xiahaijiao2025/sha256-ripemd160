"""
Implementing SHA-256 from scratch was fun, but for RIPEMD160 I am
taking an existing implementation and made some cleanups and api changes.
"""

## ripemd.py - pure Python implementation of the RIPEMD-160 algorithm.
## Bjorn Edstrom <be@bjrn.se> 16 december 2007.
##
## Copyrights
## ==========
##
## This code is a derived from an implementation by Markus Friedl which is
## subject to the following license. This Python implementation is not
## subject to any other license.
##
##/*
## * Copyright (c) 2001 Markus Friedl.  All rights reserved.
## *
## * Redistribution and use in source and binary forms, with or without
## * modification, are permitted provided that the following conditions
## * are met:
## * 1. Redistributions of source code must retain the above copyright
## *    notice, this list of conditions and the following disclaimer.
## * 2. Redistributions in binary form must reproduce the above copyright
## *    notice, this list of conditions and the following disclaimer in the
## *    documentation and/or other materials provided with the distribution.
## *
## * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
## * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
## * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
## * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
## * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
## * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES LOSS OF USE,
## * DATA, OR PROFITS OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
## * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
## * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
## */
##/*
## * Preneel, Bosselaers, Dobbertin, "The Cryptographic Hash Function RIPEMD-160",
## * RSA Laboratories, CryptoBytes, Volume 3, Number 2, Autumn 1997,
## * ftp://ftp.rsasecurity.com/pub/cryptobytes/crypto3n2.pdf
## */

import sys
import struct

# -----------------------------------------------------------------------------
# public interface

def ripemd160(b: bytes) -> bytes:
    """ simple wrapper for a simpler API to this hash function, just bytes to bytes """
    ctx = RMDContext()
    RMD160Update(ctx, b, len(b))
    digest = RMD160Final(ctx)
    return digest

# -----------------------------------------------------------------------------

class RMDContext:
    def __init__(self):
        self.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] # uint32
        # self.state = [0x51c683bc ,0xe9cd8258, 0x75924d6d ,0xb31d5b2b ,0x9f1418b8] # uint32
        self.count = 0 # uint64
        self.buffer = [0]*64 # uchar

def RMD160Update(ctx, inp, inplen):
    have = int((ctx.count // 8) % 64)
    inplen = int(inplen)
    need = 64 - have
    ctx.count += 8 * inplen
    off = 0
    if inplen >= need:
        if have:
            for i in range(need):
                ctx.buffer[have+i] = inp[i]
            RMD160Transform(ctx.state, ctx.buffer)
            off = need
            have = 0
        while off + 64 <= inplen:
            RMD160Transform(ctx.state, inp[off:]) #<---
            off += 64
    if off < inplen:
        for i in range(inplen - off):
            ctx.buffer[have+i] = inp[off+i]

    pass
    print(f"------- buffer {len(ctx.buffer)} ,{ctx.count } ,{ctx.buffer}  ")

def RMD160Final(ctx):
    size = struct.pack("<Q", ctx.count)
    padlen = 64 - ((ctx.count // 8) % 64)
    if padlen < 1 + 8:
        padlen += 64
    RMD160Update(ctx, PADDING, padlen-8)
    RMD160Update(ctx, size, 8)
    return struct.pack("<5L", *ctx.state)

# -----------------------------------------------------------------------------

K0 = 0x00000000
K1 = 0x5A827999
K2 = 0x6ED9EBA1
K3 = 0x8F1BBCDC
K4 = 0xA953FD4E
KK0 = 0x50A28BE6
KK1 = 0x5C4DD124
KK2 = 0x6D703EF3
KK3 = 0x7A6D76E9
KK4 = 0x00000000

PADDING = [0x80] + [0]*63

def ROL(n, x):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def F0(x, y, z):
    return x ^ y ^ z

def F1(x, y, z):
    return (x & y) | (((~x) % 0x100000000) & z)

def F2(x, y, z):
    return (x | ((~y) % 0x100000000)) ^ z

def F3(x, y, z):
    return (x & z) | (((~z) % 0x100000000) & y)

def F4(x, y, z):
    return x ^ (y | ((~z) % 0x100000000))

def R(a, b, c, d, e, Fj, Kj, sj, rj, X):
    global global_j  # 声明使用全局变量
    global global_j_slash  # 声明使用全局变量

    # t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e)]
    # t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e),hex(X[rj]),hex(Kj)]
    # if global_j_slash == 0:
    #     print(f"{f'j = {global_j-1} ':<5}" + " ".join(f"{v:>10}" for v in t0_values))
    #
    #     pass
    # else:
    #     print(f"{f'j_slash = {global_j-1} ':<5}" + " ".join(f"{v:>10}" for v in t0_values))
    #
    #     pass
    # if sj==rj and sj==0:
    #
    #     return

    # print(f"{f'j = {global_j} ':<5}" + " ".join(f"{v:>10}" for v in t0_values))

    # print(f"j={global_j} )
    a = ROL(sj, (a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000) + e
    c = ROL(10, c)

    global_j = global_j +1
    return a % 0x100000000, c

global_j = 0
global_j_slash = 0

xj_k_array = [
    # /* Round 1 */
    (F0, K0, 11, 0)
    , (F0, K0, 14, 1)
    , (F0, K0, 15, 2)
    , (F0, K0, 12, 3)
    , (F0, K0, 5, 4)
    , (F0, K0, 8, 5)
    , (F0, K0, 7, 6)
    , (F0, K0, 9, 7)
    , (F0, K0, 11, 8)
    , (F0, K0, 13, 9)
    , (F0, K0, 14, 10)
    , (F0, K0, 15, 11)
    , (F0, K0, 6, 12)
    , (F0, K0, 7, 13)
    , (F0, K0, 9, 14)
    , (F0, K0, 8, 15)

    # /* Round 2 */
    , (F1, K1, 7, 7)
    , (F1, K1, 6, 4)
    , (F1, K1, 8, 13)
    , (F1, K1, 13, 1)
    , (F1, K1, 11, 10)
    , (F1, K1, 9, 6)
    , (F1, K1, 7, 15)
    , (F1, K1, 15, 3)
    , (F1, K1, 7, 12)
    , (F1, K1, 12, 0)
    , (F1, K1, 15, 9)
    , (F1, K1, 9, 5)
    , (F1, K1, 11, 2)
    , (F1, K1, 7, 14)
    , (F1, K1, 13, 11)
    , (F1, K1, 12, 8)

    # /* Round 3 */
    , (F2, K2, 11, 3)
    , (F2, K2, 13, 10)
    , (F2, K2, 6, 14)
    , (F2, K2, 7, 4)
    , (F2, K2, 14, 9)
    , (F2, K2, 9, 15)
    , (F2, K2, 13, 8)
    , (F2, K2, 15, 1)
    , (F2, K2, 14, 2)
    , (F2, K2, 8, 7)
    , (F2, K2, 13, 0)
    , (F2, K2, 6, 6)
    , (F2, K2, 5, 13)
    , (F2, K2, 12, 11)
    , (F2, K2, 7, 5)
    , (F2, K2, 5, 12)

    # /* Round 4 */
    , (F3, K3, 11, 1)
    , (F3, K3, 12, 9)
    , (F3, K3, 14, 11)
    , (F3, K3, 15, 10)
    , (F3, K3, 14, 0)
    , (F3, K3, 15, 8)
    , (F3, K3, 9, 12)
    , (F3, K3, 8, 4)
    , (F3, K3, 9, 13)
    , (F3, K3, 14, 3)
    , (F3, K3, 5, 7)
    , (F3, K3, 6, 15)
    , (F3, K3, 8, 14)
    , (F3, K3, 6, 5)
    , (F3, K3, 5, 6)
    , (F3, K3, 12, 2)

    # /* Round 5 */
    , (F4, K4, 9, 4)
    , (F4, K4, 15, 0)
    , (F4, K4, 5, 5)
    , (F4, K4, 11, 9)
    , (F4, K4, 6, 7)
    , (F4, K4, 8, 12)
    , (F4, K4, 13, 2)
    , (F4, K4, 12, 10)
    , (F4, K4, 5, 14)
    , (F4, K4, 12, 1)
    , (F4, K4, 13, 3)
    , (F4, K4, 14, 8)
    , (F4, K4, 11, 11)
    , (F4, K4, 8, 6)
    , (F4, K4, 5, 15)
    , (F4, K4, 6, 13)

]

xj_k_slash_array = [
    # /* Parallel round 1 */
    (F4, KK0, 8, 5)
    , (F4, KK0, 9, 14)
    , (F4, KK0, 9, 7)
    , (F4, KK0, 11, 0)
    , (F4, KK0, 13, 9)
    , (F4, KK0, 15, 2)
    , (F4, KK0, 15, 11)
    , (F4, KK0, 5, 4)
    , (F4, KK0, 7, 13)
    , (F4, KK0, 7, 6)
    , (F4, KK0, 8, 15)
    , (F4, KK0, 11, 8)
    , (F4, KK0, 14, 1)
    , (F4, KK0, 14, 10)
    , (F4, KK0, 12, 3)
    , (F4, KK0, 6, 12)

    # /* Parallel round 2 */
    , (F3, KK1, 9, 6)
    , (F3, KK1, 13, 11)
    , (F3, KK1, 15, 3)
    , (F3, KK1, 7, 7)
    , (F3, KK1, 12, 0)
    , (F3, KK1, 8, 13)
    , (F3, KK1, 9, 5)
    , (F3, KK1, 11, 10)
    , (F3, KK1, 7, 14)
    , (F3, KK1, 7, 15)
    , (F3, KK1, 12, 8)
    , (F3, KK1, 7, 12)
    , (F3, KK1, 6, 4)
    , (F3, KK1, 15, 9)
    , (F3, KK1, 13, 1)
    , (F3, KK1, 11, 2)  # /* #31 */

    # /* Parallel round 3 */
    , (F2, KK2, 9, 15)
    , (F2, KK2, 7, 5)
    , (F2, KK2, 15, 1)
    , (F2, KK2, 11, 3)
    , (F2, KK2, 8, 7)
    , (F2, KK2, 6, 14)
    , (F2, KK2, 6, 6)
    , (F2, KK2, 14, 9)
    , (F2, KK2, 12, 11)
    , (F2, KK2, 13, 8)
    , (F2, KK2, 5, 12)
    , (F2, KK2, 14, 2)
    , (F2, KK2, 13, 10)
    , (F2, KK2, 13, 0)
    , (F2, KK2, 7, 4)
    , (F2, KK2, 5, 13)  # /* #47 */

    # /* Parallel round 4 */
    , (F1, KK3, 15, 8)
    , (F1, KK3, 5, 6)
    , (F1, KK3, 8, 4)
    , (F1, KK3, 11, 1)
    , (F1, KK3, 14, 3)
    , (F1, KK3, 14, 11)
    , (F1, KK3, 6, 15)
    , (F1, KK3, 14, 0)
    , (F1, KK3, 6, 5)
    , (F1, KK3, 9, 12)
    , (F1, KK3, 12, 2)
    , (F1, KK3, 9, 13)
    , (F1, KK3, 12, 9)
    , (F1, KK3, 5, 7)
    , (F1, KK3, 15, 10)
    , (F1, KK3, 8, 14)  # /* #63 */

    # /* Parallel round 5 */
    , (F0, KK4, 8, 12)
    , (F0, KK4, 5, 15)
    , (F0, KK4, 12, 10)
    , (F0, KK4, 9, 4)
    , (F0, KK4, 12, 1)
    , (F0, KK4, 5, 5)
    , (F0, KK4, 14, 8)
    , (F0, KK4, 6, 7)
    , (F0, KK4, 8, 6)
    , (F0, KK4, 13, 2)
    , (F0, KK4, 6, 13)
    , (F0, KK4, 5, 14)
    , (F0, KK4, 15, 0)
    , (F0, KK4, 13, 3)
    , (F0, KK4, 11, 9)
    , (F0, KK4, 11, 11)  # /* #79 */
]



def RMD160Transform(state, block): #uint32 state[5], uchar block[64]
    global global_j  # 声明使用全局变量
    global global_j_slash  # 声明使用全局变量

    global xj_k_array  # 声明使用全局变量
    global xj_k_slash_array  # 声明使用全局变量

    x = [0]*16
    assert sys.byteorder == 'little', "Only little endian is supported atm for RIPEMD160"
    x = struct.unpack('<16L', bytes(block[0:64]))

    print(f"--------- block = {block}")
    index=0
    for i in block:
        print(index,hex(i))
        index=index+1

    print(f"-------- x = {x} ")
    index=0
    for i in x:
        print(index,hex(i))
        index=index+1


    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    # print(f"a,b,c,d,e,X[rj],K[j]")
    # Kj, rj, x[rj]
    t0_values=["a","b","c","d","e","Kj","rj","x[rj]"  ,"a_slash","b_slash","c_slash","d_slash","e_slash",  "Kj`","rj`","x[rj`]" ]
    print(f"{f'j    ':<10}" + " ".join(f"{v:>10}" for v in t0_values))

    #/* Round 1 */
    # a, c = R(a, b, c, d, e, F0, K0, 11,  0, x)
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    e = state[4]

    a_slash = state[0]
    b_slash = state[1]
    c_slash = state[2]
    d_slash = state[3]
    e_slash = state[4]


    for i in range(0,80):
        xj_k_item=xj_k_array[i]
        xj_k_slash_item=xj_k_slash_array[i]
                                                             # Kj             ,rj           ,x[rj]                                                                                 Kj' ,rj',x[rj']
        t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e), hex(xj_k_item[1]),xj_k_item[3],hex(x[xj_k_item[3]]),hex(a_slash), hex(b_slash),hex(c_slash),hex(d_slash),hex(e_slash) ,hex(xj_k_slash_item[1]),xj_k_slash_item[3],hex(x[xj_k_slash_item[3]])  ]
        print(f"{f'j = {i } ':<10}" + " ".join(f"{v:>10}" for v in t0_values))


        temp_t, temp_d = R(a, b, c, d, e, xj_k_item[0], xj_k_item[1], xj_k_item[2], xj_k_item[3], x)
        a=e
        e=d
        d=temp_d
        c=b
        b=temp_t

        temp_t, temp_d = R(a_slash, b_slash, c_slash, d_slash, e_slash, xj_k_slash_item[0], xj_k_slash_item[1], xj_k_slash_item[2], xj_k_slash_item[3], x)
        a_slash=e_slash
        e_slash=d_slash
        d_slash=temp_d
        c_slash=b_slash
        b_slash=temp_t

        # a, c = R(a, b, c, d, e, F4, KK0, 8, 5, x)
        # def R(a, b, c, d, e, Fj, Kj, sj, rj, X):
        # a = ROL(sj, (a + Fj(b, c, d) + X[rj] + Kj) % 0x100000000) + e
                                                              #Kj             ,rj           ,x[rj]
        # t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e), hex(xj_k_item[1]),xj_k_item[3],hex(x[xj_k_item[3]]),hex(a_slash), hex(b_slash),hex(c_slash),hex(d_slash),hex(e_slash)]
        # print(f"{f'j = {i } ':<10}" + " ".join(f"{v:>10}" for v in t0_values))

        # if global_j_slash == 0:
        #     print(f"{f'j = {global_j - 1} ':<5}" + " ".join(f"{v:>10}" for v in t0_values))
        #
        #     pass
        # else:
        #     print(f"{f'j_slash = {global_j - 1} ':<5}" + " ".join(f"{v:>10}" for v in t0_values))
        #
        #     pass
        # if sj == rj and sj == 0:
        #     return
        pass

    aa = a
    bb = b
    cc = c
    dd = d
    ee = e

    a=a_slash
    b=b_slash
    c=c_slash
    d=d_slash
    e=e_slash


    t = (state[1] + cc + d) % 0x100000000
    state[1] = (state[2] + dd + e) % 0x100000000
    state[2] = (state[3] + ee + a) % 0x100000000
    state[3] = (state[4] + aa + b) % 0x100000000
    state[4] = (state[0] + bb + c) % 0x100000000
    state[0] = t % 0x100000000


    print(f"----------------- h0= {hex(state[0])} = {hex(state[1])} + {hex(cc)} + {hex(d)}")
    print(f"----------------- h1= {hex(state[1])} = {hex(state[2])} + {hex(dd)} + {hex(e)}")
    print(f"----------------- h2= {hex(state[2])} = {hex(state[3])} + {hex(ee)} + {hex(a)}")
    print(f"----------------- h3= {hex(state[3])} = {hex(state[4])} + {hex(aa)} + {hex(b)}")
    print(f"----------------- h4= {hex(state[4])} = {hex(state[0])} + {hex(bb)} + {hex(c)}")



    t0_values = [hex(aa), hex(bb), hex(cc), hex(dd), hex(ee),hex(a), hex(b), hex(c), hex(d), hex(e)]

    print(f"{f'j = final':<10}" + " ".join(f"{v:>10}" for v in t0_values))
    # t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e)]
    #
    # print(f"{f' slash a,b,c,d,e  ':<5}" + " ".join(f"{v:>10}" for v in t0_values))


    t0_values = [hex(state[0]), hex(state[1]), hex(state[2]), hex(state[3]), hex(state[4])]
    print(f"{f'final  ':<10}" + " ".join(f"{v:>10}" for v in t0_values))

    t0_values = [state[0].to_bytes(4, byteorder='little').hex(),state[1].to_bytes(4, byteorder='little').hex(),state[2].to_bytes(4, byteorder='little').hex(),state[3].to_bytes(4, byteorder='little').hex(), state[4].to_bytes(4, byteorder='little').hex()]
    print(f"{f'final小端':<10}" + " ".join(f"{v:>10}" for v in t0_values))

    print("")


data = b'abc'  # 注意数据要以字节形式传入    8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
# data = b'a'  # 注意数据要以字节形式传入
# data = b''  # 注意数据要以字节形式传入

# str="1fbb53168ad15821bf04a498b85ed58f4d2d28f6977b64cd8c7769dc961cce169d7a5bc6f6519d3837316e69206d4292f451be9e748e57f5c73a141e753c86"
# # str="1fbb53168ad15821bf04a498b85ed58f4d2d28f6977b64cd8c7769dc961cce169d7a5bc6f6519d3837316e69206d4292f449be9e748e57f5c73a141e753c86"
str = "0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554"
# str = "1fbb53168ad15821bf04a498b85ed58f4d2d28f6977b64cd8c7769dc961cce169d7a5bc6f6519d3837316e69206d4292f451be9e748e57f5c73a141e753c86"
# str = "1fbb53168ad15821bf04a498b85ed58f4d2d28f6977b64cd8c7769dc961cce169d7a5bc6f6519d3837316e69206d4292f449be9e748e57f5c73a141e753c86"
# str = "29f1ebfb4468041a1e6565b64cc17e754ea4f99333a77104864a828d1dcec3d2d33d7b02bcd4a2d73b10201d399535488e127f2b0304fc01e711857743b12ca7"

# data=bytes.fromhex(str)  #16进制


print(data.hex())
print("")
# 计算 RIPEMD-160 哈希值
hash_value = ripemd160(data)

# 输出结果（以十六进制形式表示）
print(hash_value.hex())
