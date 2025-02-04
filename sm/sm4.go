// Copyright 2025 BUAA BoYuan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    "bytes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"

    // 注意引入 scrypt 包
    "golang.org/x/crypto/scrypt"
)

// ========== 1. SM4 算法实现 ========== //

// SM4 块大小
const (
    SM4BlockSize = 16
    Round        = 32
)

// 固定参数
const (
    FK0 = 0xA3B1BAC6
    FK1 = 0x56AA3350
    FK2 = 0x677D9197
    FK3 = 0xB27022DC
)

// S盒
var sbox = [256]byte{
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
}

// CK 常量
var ck = [32]uint32{
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
}

// sm4Cipher 实现了 cipher.Block 接口
type sm4Cipher struct {
    rk [Round]uint32
}

// NewSM4Cipher 创建一个新的 SM4 Cipher
func NewSM4Cipher(key []byte) (cipher.Block, error) {
    if len(key) != 16 {
        return nil, errors.New("sm4: 密钥长度必须是 16 字节")
    }
    c := &sm4Cipher{}
    c.keyExpand(key)
    return c, nil
}

// BlockSize 返回 SM4 块大小 16 字节
func (c *sm4Cipher) BlockSize() int {
    return SM4BlockSize
}

// Encrypt 加密 16 字节数据
func (c *sm4Cipher) Encrypt(dst, src []byte) {
    var x [36]uint32

    // 输入转换
    for i := 0; i < 4; i++ {
        x[i] = binary.BigEndian.Uint32(src[i*4:])
    }

    for i := 0; i < 32; i++ {
        x[i+4] = x[i] ^ lFun(tFun(x[i+1]^x[i+2]^x[i+3]^c.rk[i]))
    }

    // 输出转换（反序）
    binary.BigEndian.PutUint32(dst[0:4], x[35])
    binary.BigEndian.PutUint32(dst[4:8], x[34])
    binary.BigEndian.PutUint32(dst[8:12], x[33])
    binary.BigEndian.PutUint32(dst[12:16], x[32])
}

// Decrypt 解密 16 字节数据
func (c *sm4Cipher) Decrypt(dst, src []byte) {
    // 为解密构造一个反向轮密钥的临时 cipher
    var reverseRK [Round]uint32
    for i := 0; i < 32; i++ {
        reverseRK[i] = c.rk[31-i]
    }
    revCipher := &sm4Cipher{rk: reverseRK}
    revCipher.Encrypt(dst, src)
}

func (c *sm4Cipher) keyExpand(key []byte) {
    var mk [4]uint32
    for i := 0; i < 4; i++ {
        mk[i] = binary.BigEndian.Uint32(key[i*4:])
    }

    var k [36]uint32
    k[0] = mk[0] ^ FK0
    k[1] = mk[1] ^ FK1
    k[2] = mk[2] ^ FK2
    k[3] = mk[3] ^ FK3

    for i := 0; i < 32; i++ {
        k[i+4] = k[i] ^ tPrime(k[i+1]^k[i+2]^k[i+3]^ck[i])
        c.rk[i] = k[i+4]
    }
}

// tFun S 盒变换
func tFun(n uint32) uint32 {
    var b [4]byte
    binary.BigEndian.PutUint32(b[:], n)
    for i := 0; i < 4; i++ {
        b[i] = sbox[b[i]]
    }
    return binary.BigEndian.Uint32(b[:])
}

// tPrime 用于生成轮密钥的变换
func tPrime(n uint32) uint32 {
    tn := tFun(n)
    return tn ^ rotl(tn, 13) ^ rotl(tn, 23)
}

// lFun 用于加密轮函数的线性变换
func lFun(n uint32) uint32 {
    return n ^ rotl(n, 2) ^ rotl(n, 10) ^ rotl(n, 18) ^ rotl(n, 24)
}

// rotl 左移位函数
func rotl(x uint32, n uint) uint32 {
    return (x << n) | (x >> (32 - n))
}

// ========== 2. 分组模式实现 ========== //

// ---------- ECB 模式 ----------
func SM4EncryptECB(block cipher.Block, data []byte, paddingType string) []byte {
    blockSize := block.BlockSize()
    data = Padding(data, blockSize, paddingType)
    encrypted := make([]byte, len(data))

    for i := 0; i < len(data); i += blockSize {
        block.Encrypt(encrypted[i:i+blockSize], data[i:i+blockSize])
    }
    return encrypted
}

func SM4DecryptECB(block cipher.Block, data []byte, paddingType string) []byte {
    blockSize := block.BlockSize()
    if len(data)%blockSize != 0 {
        panic("密文长度不是块大小的整数倍")
    }
    decrypted := make([]byte, len(data))

    for i := 0; i < len(data); i += blockSize {
        block.Decrypt(decrypted[i:i+blockSize], data[i:i+blockSize])
    }
    return UnPadding(decrypted, paddingType)
}

// ---------- CBC 模式 ----------
func SM4EncryptCBC(block cipher.Block, iv, data []byte, paddingType string) []byte {
    if len(iv) != block.BlockSize() {
        panic("CBC模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    data = Padding(data, blockSize, paddingType)

    encrypted := make([]byte, len(data))
    tmp := make([]byte, blockSize)
    copy(tmp, iv)

    for i := 0; i < len(data); i += blockSize {
        blockData := data[i : i+blockSize]
        for j := 0; j < blockSize; j++ {
            tmp[j] ^= blockData[j]
        }
        block.Encrypt(encrypted[i:i+blockSize], tmp)
        copy(tmp, encrypted[i:i+blockSize])
    }
    return encrypted
}

func SM4DecryptCBC(block cipher.Block, iv, data []byte, paddingType string) []byte {
    if len(iv) != block.BlockSize() {
        panic("CBC模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    if len(data)%blockSize != 0 {
        panic("CBC模式：密文长度不是块大小的整数倍")
    }

    decrypted := make([]byte, len(data))
    tmp := make([]byte, blockSize)
    copy(tmp, iv)

    for i := 0; i < len(data); i += blockSize {
        blockData := data[i : i+blockSize]
        blockDec := make([]byte, blockSize)
        block.Decrypt(blockDec, blockData)
        for j := 0; j < blockSize; j++ {
            decrypted[i+j] = blockDec[j] ^ tmp[j]
        }
        copy(tmp, blockData)
    }
    return UnPadding(decrypted, paddingType)
}

// ---------- CFB 模式 ----------
func SM4EncryptCFB(block cipher.Block, iv, data []byte) []byte {
    // CFB 一般无需填充
    if len(iv) != block.BlockSize() {
        panic("CFB模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    encrypted := make([]byte, len(data))
    tmp := make([]byte, blockSize)
    copy(tmp, iv)

    for i := 0; i < len(data); {
        // 先加密IV或者上一段密文
        block.Encrypt(tmp, tmp)
        blockLen := blockSize
        if i+blockLen > len(data) {
            blockLen = len(data) - i
        }
        for j := 0; j < blockLen; j++ {
            encrypted[i+j] = tmp[j] ^ data[i+j]
        }
        // 把真正的密文写入 tmp，以便下一次加密
        copy(tmp, tmp[blockLen:])
        copy(tmp[blockSize-blockLen:], encrypted[i:i+blockLen])
        i += blockLen
    }
    return encrypted
}

func SM4DecryptCFB(block cipher.Block, iv, data []byte) []byte {
    if len(iv) != block.BlockSize() {
        panic("CFB模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    decrypted := make([]byte, len(data))
    tmp := make([]byte, blockSize)
    copy(tmp, iv)

    for i := 0; i < len(data); {
        block.Encrypt(tmp, tmp)
        blockLen := blockSize
        if i+blockLen > len(data) {
            blockLen = len(data) - i
        }
        for j := 0; j < blockLen; j++ {
            decrypted[i+j] = tmp[j] ^ data[i+j]
        }
        // 与加密不同的是，此处需要把当前的密文写到 tmp 末尾
        copy(tmp, tmp[blockLen:])
        copy(tmp[blockSize-blockLen:], data[i:i+blockLen])
        i += blockLen
    }
    return decrypted
}

// ---------- OFB 模式 ----------
func SM4EncryptOFB(block cipher.Block, iv, data []byte) []byte {
    // OFB 一般也无需填充
    if len(iv) != block.BlockSize() {
        panic("OFB模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    encrypted := make([]byte, len(data))
    tmp := make([]byte, blockSize)
    copy(tmp, iv)

    for i := 0; i < len(data); {
        block.Encrypt(tmp, tmp)
        blockLen := blockSize
        if i+blockLen > len(data) {
            blockLen = len(data) - i
        }
        for j := 0; j < blockLen; j++ {
            encrypted[i+j] = data[i+j] ^ tmp[j]
        }
        i += blockLen
    }
    return encrypted
}

func SM4DecryptOFB(block cipher.Block, iv, data []byte) []byte {
    // OFB 加解密相同
    return SM4EncryptOFB(block, iv, data)
}

// ---------- CTR 模式 ----------
func SM4EncryptCTR(block cipher.Block, iv, data []byte) []byte {
    // CTR 不需要填充
    if len(iv) != block.BlockSize() {
        panic("CTR模式：IV长度必须等于块大小")
    }
    blockSize := block.BlockSize()
    encrypted := make([]byte, len(data))

    counter := make([]byte, blockSize)
    copy(counter, iv)

    keystreamBlock := make([]byte, blockSize)

    for i := 0; i < len(data); {
        block.Encrypt(keystreamBlock, counter)

        blockLen := blockSize
        if i+blockLen > len(data) {
            blockLen = len(data) - i
        }
        for j := 0; j < blockLen; j++ {
            encrypted[i+j] = data[i+j] ^ keystreamBlock[j]
        }

        // 递增 counter
        incCounter(counter)
        i += blockLen
    }
    return encrypted
}

func SM4DecryptCTR(block cipher.Block, iv, data []byte) []byte {
    // CTR 加解密相同
    return SM4EncryptCTR(block, iv, data)
}

// 递增计数器（最简单的实现：将16字节看作一个128位数 +1）
func incCounter(counter []byte) {
    for i := len(counter) - 1; i >= 0; i-- {
        counter[i]++
        if counter[i] != 0 {
            break
        }
    }
}

// ========== 3. GCM 模式（示例性实现，修正 gmul 避免 panic） ========== //

// GCM 结构
type SM4GCM struct {
    block cipher.Block
}

// NewSM4GCM 构造 GCM，需要自己实现 GHASH 等
func NewSM4GCM(block cipher.Block) *SM4GCM {
    return &SM4GCM{
        block: block,
    }
}

// Seal：给定 nonce(IV) + AAD(附加数据) + plaintext -> ciphertext + tag
// 仅演示流程，未严格遵循全部规范
func (g *SM4GCM) Seal(nonce, plaintext, aad []byte) (ciphertext, tag []byte) {
    // 1. 生成哈希子密钥 H = E(K, 0^128)
    H := make([]byte, SM4BlockSize)
    zeroBlock := make([]byte, SM4BlockSize)
    g.block.Encrypt(H, zeroBlock)

    // 2. 组装 CTR nonce，(此处仅演示：把 nonce[16] 最后一字节设置计数器+1)
    ctrNonce := make([]byte, SM4BlockSize)
    copy(ctrNonce, nonce)
    ctrNonce[SM4BlockSize-1] ^= 0x01

    // 3. 用 CTR 模式加密 plaintext
    ciphertext = SM4EncryptCTR(g.block, ctrNonce, plaintext)

    // 4. 计算 GHASH 来生成 tag
    //    tag = GHASH(H, AAD, ciphertext) XOR E(K, J0)
    //    其中 J0 通常是 12字节 nonce 拼上长度等，这里简化处理
    computedGH := ghash(H, aad, ciphertext)
    j0Enc := make([]byte, SM4BlockSize)
    g.block.Encrypt(j0Enc, nonce) // 简化：直接用 nonce 做一次加密

    tag = make([]byte, SM4BlockSize)
    for i := 0; i < SM4BlockSize; i++ {
        tag[i] = computedGH[i] ^ j0Enc[i]
    }

    // 只返回 16 字节的 tag
    return ciphertext, tag
}

// Open：给定 nonce(IV) + ciphertext + AAD + tag -> plaintext
func (g *SM4GCM) Open(nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error) {
    // 1. 生成哈希子密钥
    H := make([]byte, SM4BlockSize)
    zeroBlock := make([]byte, SM4BlockSize)
    g.block.Encrypt(H, zeroBlock)

    // 2. 验证 tag
    computedGH := ghash(H, aad, ciphertext)
    j0Enc := make([]byte, SM4BlockSize)
    g.block.Encrypt(j0Enc, nonce)
    computedTag := make([]byte, SM4BlockSize)
    for i := 0; i < SM4BlockSize; i++ {
        computedTag[i] = computedGH[i] ^ j0Enc[i]
    }

    if !bytes.Equal(tag, computedTag) {
        return nil, errors.New("GCM tag 校验失败")
    }

    // 3. tag 校验通过后再解密
    ctrNonce := make([]byte, SM4BlockSize)
    copy(ctrNonce, nonce)
    ctrNonce[SM4BlockSize-1] ^= 0x01

    plaintext = SM4EncryptCTR(g.block, ctrNonce, ciphertext) // CTR 同操作
    return plaintext, nil
}

// ghash：将 (AAD || ciphertext || 长度信息) 做多项式运算
func ghash(H, A, C []byte) []byte {
    // 符合 GCM 规范需：GHASH(H, A, C) = Xm，X0 = 0
    // 其中最后还要拼接 (len(A) * 8, len(C) * 8) 两个64位
    // 简化版示例
    x := make([]byte, SM4BlockSize) // X初值=0
    x = ghashBlocks(x, H, A)
    x = ghashBlocks(x, H, C)

    // 处理长度信息：len(A), len(C)
    lenBlock := make([]byte, SM4BlockSize)
    putUint64BE(lenBlock[0:8], uint64(len(A))*8)
    putUint64BE(lenBlock[8:16], uint64(len(C))*8)
    x = ghashBlocks(x, H, lenBlock)
    return x
}

// ghashBlocks：把 data 按 128 位分组，依次做 Xor -> gmul(H)
func ghashBlocks(X, H, data []byte) []byte {
    bs := SM4BlockSize
    out := make([]byte, bs)
    copy(out, X)
    for len(data) >= bs {
        for i := 0; i < bs; i++ {
            out[i] ^= data[i]
        }
        out = gmul(out, H) // GF(2^128) 乘法
        data = data[bs:]
    }
    if len(data) > 0 {
        tmp := make([]byte, bs)
        copy(tmp, data)
        for i := 0; i < bs; i++ {
            out[i] ^= tmp[i]
        }
        out = gmul(out, H)
    }
    return out
}

// gmul：在 GF(2^128) 上计算 X * Y，采用常见的 bit-by-bit 方式
func gmul(X, Y []byte) []byte {
    var Z [16]byte
    var V [16]byte
    copy(V[:], X)

    for i := 0; i < 128; i++ {
        // 如果 Y 的当前位是 1，则 Z = Z XOR V
        if (Y[i/8] & (1 << (7 - (i % 8)))) != 0 {
            for j := 0; j < 16; j++ {
                Z[j] ^= V[j]
            }
        }
        // V 左移 1 位
        var carry byte
        for j := 0; j < 16; j++ {
            hiBit := (V[j] & 0x80) >> 7
            tmp := (V[j] << 1) | carry
            V[j] = tmp
            carry = hiBit
        }
        // 如果最高位发生了进位，就折返异或 “0xe1”
        if carry == 1 {
            V[0] ^= 0xe1
        }
    }
    return Z[:]
}

// putUint64BE 大端写入 uint64
func putUint64BE(b []byte, v uint64) {
    _ = b[7]
    b[0] = byte(v >> 56)
    b[1] = byte(v >> 48)
    b[2] = byte(v >> 40)
    b[3] = byte(v >> 32)
    b[4] = byte(v >> 24)
    b[5] = byte(v >> 16)
    b[6] = byte(v >> 8)
    b[7] = byte(v)
}

// ========== 4. 填充方式 ========== //

func Padding(data []byte, blockSize int, paddingType string) []byte {
    switch strings.ToUpper(paddingType) {
    case "PKCS5", "PKCS7":
        return PKCS7Padding(data, blockSize)
    case "ZEROS":
        return ZerosPadding(data, blockSize)
    case "ISO10126":
        return ISO10126Padding(data, blockSize)
    case "ANSI X.923", "ANSIX923":
        return AnsiX923Padding(data, blockSize)
    case "ISO/IEC 7816-4", "ISO7816-4":
        return ISO78164Padding(data, blockSize)
    default:
        // 默认用 PKCS7
        return PKCS7Padding(data, blockSize)
    }
}

func UnPadding(data []byte, paddingType string) []byte {
    switch strings.ToUpper(paddingType) {
    case "PKCS5", "PKCS7":
        return PKCS7UnPadding(data)
    case "ZEROS":
        return ZerosUnPadding(data)
    case "ISO10126":
        return ISO10126UnPadding(data)
    case "ANSI X.923", "ANSIX923":
        return AnsiX923UnPadding(data)
    case "ISO/IEC 7816-4", "ISO7816-4":
        return ISO78164UnPadding(data)
    default:
        // 默认用 PKCS7
        return PKCS7UnPadding(data)
    }
}

// PKCS7 (PKCS5 为其子集)
func PKCS7Padding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padtext...)
}

func PKCS7UnPadding(data []byte) []byte {
    length := len(data)
    if length == 0 {
        return data
    }
    unpadding := int(data[length-1])
    if unpadding > length {
        return data
    }
    return data[:(length - unpadding)]
}

// Zeros 填充
func ZerosPadding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := bytes.Repeat([]byte{0}, padding)
    return append(data, padtext...)
}

func ZerosUnPadding(data []byte) []byte {
    return bytes.TrimRight(data, "\x00")
}

// ISO10126 填充：最后一字节是填充长度，前面随机（这里只用 0xFF 代替）
func ISO10126Padding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := make([]byte, padding)
    for i := 0; i < padding-1; i++ {
        padtext[i] = 0xFF
    }
    padtext[padding-1] = byte(padding)
    return append(data, padtext...)
}

func ISO10126UnPadding(data []byte) []byte {
    length := len(data)
    if length == 0 {
        return data
    }
    unpadding := int(data[length-1])
    if unpadding > length {
        return data
    }
    return data[:(length - unpadding)]
}

// ANSI X.923 填充：最后一字节是填充长度，前面补0
func AnsiX923Padding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := make([]byte, padding)
    padtext[padding-1] = byte(padding)
    return append(data, padtext...)
}

func AnsiX923UnPadding(data []byte) []byte {
    length := len(data)
    if length == 0 {
        return data
    }
    unpadding := int(data[length-1])
    if unpadding > length {
        return data
    }
    return data[:(length - unpadding)]
}

// ISO78164 填充：最后一字节为0x80，其余补0
func ISO78164Padding(data []byte, blockSize int) []byte {
    padding := blockSize - (len(data) % blockSize)
    padtext := make([]byte, padding)
    padtext[0] = 0x80
    return append(data, padtext...)
}

func ISO78164UnPadding(data []byte) []byte {
    idx := bytes.LastIndexByte(data, 0x80)
    if idx == -1 {
        return data
    }
    return data[:idx]
}

// ========== 5. 常见编码 ========== //

func EncodeToHex(data []byte) string {
    return hex.EncodeToString(data)
}

func DecodeHex(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

func EncodeToBase64(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

func EncodeToUTF8(data []byte) string {
    return string(data)
}

// ========== 6. 示例：加入 scrypt KDF ========== //

// scryptDeriveKey 演示使用 scrypt 从用户密码中派生 16 字节的 SM4 密钥
func scryptDeriveKey(password string, salt []byte, keyLen int) ([]byte, error) {
    // N, r, p 参数可根据安全需求和性能做调整
    // 以下参数只是示例。N=32768(2^15), r=8, p=1
    // 如果希望更慢/更安全，可再增大 N (如 1<<18 等)
    return scrypt.Key([]byte(password), salt, 32768, 8, 1, keyLen)
}

func demoSM4AllModes(key, iv []byte, plaintext string, paddingType string) {
    block, err := NewSM4Cipher(key)
    if err != nil {
        panic(err)
    }

    fmt.Printf("----- 测试模式: ECB ---- 原文: %s\n", plaintext)
    eECB := SM4EncryptECB(block, []byte(plaintext), paddingType)
    dECB := SM4DecryptECB(block, eECB, paddingType)
    fmt.Println("ECB 加密(hex):", EncodeToHex(eECB))
    fmt.Println("ECB 解密:", EncodeToUTF8(dECB))
    fmt.Println()

    fmt.Printf("----- 测试模式: CBC ---- 原文: %s\n", plaintext)
    eCBC := SM4EncryptCBC(block, iv, []byte(plaintext), paddingType)
    dCBC := SM4DecryptCBC(block, iv, eCBC, paddingType)
    fmt.Println("CBC 加密(hex):", EncodeToHex(eCBC))
    fmt.Println("CBC 解密:", EncodeToUTF8(dCBC))
    fmt.Println()

    fmt.Printf("----- 测试模式: CFB ---- 原文: %s\n", plaintext)
    eCFB := SM4EncryptCFB(block, iv, []byte(plaintext))
    dCFB := SM4DecryptCFB(block, iv, eCFB)
    fmt.Println("CFB 加密(hex):", EncodeToHex(eCFB))
    fmt.Println("CFB 解密:", EncodeToUTF8(dCFB))
    fmt.Println()

    fmt.Printf("----- 测试模式: OFB ---- 原文: %s\n", plaintext)
    eOFB := SM4EncryptOFB(block, iv, []byte(plaintext))
    dOFB := SM4DecryptOFB(block, iv, eOFB)
    fmt.Println("OFB 加密(hex):", EncodeToHex(eOFB))
    fmt.Println("OFB 解密:", EncodeToUTF8(dOFB))
    fmt.Println()

    fmt.Printf("----- 测试模式: CTR ---- 原文: %s\n", plaintext)
    eCTR := SM4EncryptCTR(block, iv, []byte(plaintext))
    dCTR := SM4DecryptCTR(block, iv, eCTR)
    fmt.Println("CTR 加密(hex):", EncodeToHex(eCTR))
    fmt.Println("CTR 解密:", EncodeToUTF8(dCTR))
    fmt.Println()

    // GCM 示例
    fmt.Printf("----- 测试模式: GCM ---- 原文: %s\n", plaintext)
    g := NewSM4GCM(block)
    aad := []byte("GCM附加数据") // 附加认证数据
    nonce := make([]byte, SM4BlockSize)
    copy(nonce, iv) // 仅作演示
    ciphGCM, tagGCM := g.Seal(nonce, []byte(plaintext), aad)
    plainGCM, err := g.Open(nonce, ciphGCM, aad, tagGCM)
    if err != nil {
        fmt.Println("GCM 解密失败:", err)
    } else {
        fmt.Println("GCM 加密(hex):", EncodeToHex(ciphGCM))
        fmt.Println("GCM tag(hex):", EncodeToHex(tagGCM))
        fmt.Println("GCM 解密:", EncodeToUTF8(plainGCM))
    }
    fmt.Println()
}

func main() {
    // ========== 1) 标准测试向量验证 ========== //
    keyStd := []byte{
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10,
    }
    plainStd := []byte{
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10,
    }
    expectedCipher := []byte{
        0x68, 0x1E, 0xDF, 0x34,
        0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F,
        0x53, 0x6E, 0x42, 0x46,
    }

    blockStd, _ := NewSM4Cipher(keyStd)
    encryptedStd := make([]byte, 16)
    blockStd.Encrypt(encryptedStd, plainStd)
    fmt.Printf("【标准测试向量】\n")
    fmt.Printf("Key:        %X\n", keyStd)
    fmt.Printf("Plaintext:  %X\n", plainStd)
    fmt.Printf("Ciphertext: %X\n", encryptedStd)
    fmt.Printf("Expected:   %X\n", expectedCipher)
    fmt.Printf("Match:      %t\n\n", bytes.Equal(encryptedStd, expectedCipher))

    // 解密验证
    decryptedStd := make([]byte, 16)
    blockStd.Decrypt(decryptedStd, encryptedStd)
    fmt.Printf("Decrypted:  %X\n", decryptedStd)
    fmt.Printf("Match:      %t\n\n", bytes.Equal(decryptedStd, plainStd))

    // ========== 2) 使用 scrypt KDF 派生 SM4 密钥 ========== //
    // 用户输入的简单口令
    pass := "passW0rd"
    // 示例盐，也可随机生成（建议至少 16 字节）。生产环境要保存盐并确保每次派生保持一致
    salt := []byte("SALT_scrypt")

    // 从口令派生 16 字节 SM4 密钥
    derivedKey, err := scryptDeriveKey(pass, salt, 16)
    if err != nil {
        panic(err)
    }
    fmt.Printf("使用 scrypt 派生后的 SM4 密钥: %X\n\n", derivedKey)

    // ========== 3) 准备 IV 及明文进行测试 ========== //
    ivCustom := bytes.Repeat([]byte{0}, 16) // 演示用全零 IV
    poem := "咏鹅，鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波。"
    paddingType := "PKCS7"

    fmt.Printf("【scrypt KDF：口令 %q -> SM4密钥(16字节), 演示模式加解密】\n", pass)
    demoSM4AllModes(derivedKey, ivCustom, poem, paddingType)
}
