import struct

# 定义常数 K
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


# 循环右移函数
def right_rotate(n, d):
    return (n >> d) | (n << (32 - d)) & 0xFFFFFFFF


# 将32位整数转换为字节
def i_to_b(i):
    return struct.pack(">I", i)


def wiki_sha256(message):
    # 初始化哈希值
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # 填充消息
    padded = message + b'\x80'  # 先加上 0x80
    while len(padded) % 64 != 56:  # 填充 0 直到满足 448 mod 512
        padded += b'\x00'
    print(padded.hex())
    msg_len = len(message) * 8  # 消息长度（以位为单位）
    padded += struct.pack(">Q", msg_len)  # 加上64位的长度
    print(hex(msg_len))
    print(padded.hex())
    # 将消息分块，每块64字节
    broken = [padded[i:i + 64] for i in range(0, len(padded), 64)]
    print(broken)
    # 主循环处理每个块
    for chunk in broken:
        w = list(struct.unpack(">16I", chunk))  # 解析为16个32位整数
        w.extend([0] * 48)  # 扩展到64个32位整数

        # 消息扩展
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        print("-----------   w   begin ----------------")
        for i in range(0,64):
            print(f"i={i} {hex(w[i])}")
            pass
        print("-----------   w   end ----------------")

        # 初始化工作变量
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        #
        t0_values = ["a", "b", "c", "d", "e", "f", "g", "h", "T1", "T2", "Kj", "Wj"]
        print(f"{f't    ':<10}" + " ".join(f"{v:>10}" for v in t0_values))

        # 压缩函数
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            # print(f"i={i , hex(a),hex(b),hex(c),hex(d),hex(e),hex(f),hex(g),hex(h)}")

            # t0_values = [a,b,c,d,e,f,g,h]
            #                                                                 T1,T2                  ,Kj,Wj
            t0_values=[ hex(a),hex(b),hex(c),hex(d),hex(e),hex(f),hex(g),hex(h),hex(temp1),hex(temp2),hex(K[i]),hex(w[i])]
            # print(f"{'t=0':<5}" + " ".join(f"{v:>10}" for v in t0_values))
            print(f"{f't={i}':<10}" + " ".join(f"{v:>10}" for v in t0_values))

            # 更新工作变量
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
            pass
        t0_values = [hex(a), hex(b), hex(c), hex(d), hex(e), hex(f), hex(g), hex(h)]
        print(f"{f't=final':<10}" + " ".join(f"{v:>10}" for v in t0_values))
        t0_values = [hex(h0), hex(h1), hex(h2), hex(h3), hex(h4), hex(h5), hex(h6), hex(h7)]
        print(f"{f'h before ':<5}" + " ".join(f"{v:>10}" for v in t0_values))

        # 更新哈希值
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
        t0_values = [hex(h0), hex(h1), hex(h2), hex(h3), hex(h4), hex(h5), hex(h6), hex(h7)]
        print(f"{f'h after ':<5}" + " ".join(f"{v:>10}" for v in t0_values))


    # 组合结果并返回哈希值
    hash_bytes = i_to_b(h0) + i_to_b(h1) + i_to_b(h2) + i_to_b(h3) + i_to_b(h4) + i_to_b(h5) + i_to_b(h6) + i_to_b(h7)
    return hash_bytes.hex()


# 示例
input_string = "abc"
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
# hash_value = wiki_sha256(input_string.encode('utf-8'))



#16进制数
input_string_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# input_string_hex = "29f1ebfb4468041a1e6565b64cc17e754ea4f99333a77104864a828d1dcec3d2d33d7b02bcd4a2d73b10201d399535488e127f2b0304fc01e711857743b12ca7"
# input_string_hex = "0187e08e865cedaf5b69e21ae0f7485e50b98993217e465051e3cf65c2997c682c267e1682ffa4e937b5af095b28721d1be355977ff22aa1e807a758c1519aaa"
#0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554
hash_value = wiki_sha256(bytes.fromhex(input_string_hex))


print(f"SHA-256 Hash: {hash_value}")
