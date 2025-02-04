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
    "crypto/rand"
    "errors"
    "fmt"
    "math/big"
)

// =======================
//   SM3 实现 (简化版)
// =======================

const (
    sm3BlockSize = 64
    sm3DigestLen = 32
)

type sm3Digest struct {
    h      [8]uint32
    length uint64
    block  [sm3BlockSize]byte
    offset int
}

func newSM3() *sm3Digest {
    d := &sm3Digest{}
    d.Reset()
    return d
}

// Initial values
func (d *sm3Digest) Reset() {
    d.h = [8]uint32{
        0x7380166F, 0x4914B2B9,
        0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA,
        0xE38DEE4D, 0xB0FB0E4E,
    }
    d.length = 0
    d.offset = 0
}

func (d *sm3Digest) Size() int      { return sm3DigestLen }
func (d *sm3Digest) BlockSize() int { return sm3BlockSize }

func (d *sm3Digest) Write(p []byte) (n int, err error) {
    n = len(p)
    d.length += uint64(n)
    for len(p) > 0 {
        r := copy(d.block[d.offset:], p)
        d.offset += r
        p = p[r:]
        if d.offset == sm3BlockSize {
            d.compress(d.block[:])
            d.offset = 0
        }
    }
    return
}

func (d *sm3Digest) Sum(in []byte) []byte {
    // Make a copy
    temp := *d
    h := temp.checkSum()
    return append(in, h[:]...)
}

func (d *sm3Digest) checkSum() [sm3DigestLen]byte {
    // padding
    lengthBits := d.length << 3
    d.Write([]byte{0x80})
    padLen := (56 - (d.offset)) % sm3BlockSize
    d.Write(make([]byte, padLen))
    // length
    var lenBlock [8]byte
    putUint64BE(lenBlock[:], lengthBits)
    d.Write(lenBlock[:])

    var digest [sm3DigestLen]byte
    for i := 0; i < 8; i++ {
        putUint32BE(digest[i*4:], d.h[i])
    }
    return digest
}

func (d *sm3Digest) compress(block []byte) {
    var w [68]uint32
    var w1 [64]uint32

    for i := 0; i < 16; i++ {
        w[i] = getUint32BE(block[i*4:])
    }
    for i := 16; i < 68; i++ {
        w[i] = p1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
    }
    for i := 0; i < 64; i++ {
        w1[i] = w[i] ^ w[i+4]
    }

    A, B, C, D, E, F, G, H := d.h[0], d.h[1], d.h[2], d.h[3],
        d.h[4], d.h[5], d.h[6], d.h[7]

    for j := 0; j < 64; j++ {
        ss1 := rotl(rotl(A, 12)+E+rotl(t(j), uint(j%32)), 7)
        ss2 := ss1 ^ rotl(A, 12)
        var tt1, tt2 uint32
        if j < 16 {
            tt1 = ff0(A, B, C) + D + ss2 + w1[j]
            tt2 = gg0(E, F, G) + H + ss1 + w[j]
        } else {
            tt1 = ff1(A, B, C) + D + ss2 + w1[j]
            tt2 = gg1(E, F, G) + H + ss1 + w[j]
        }
        D = C
        C = rotl(B, 9)
        B = A
        A = tt1
        H = G
        G = rotl(F, 19)
        F = E
        E = p0(tt2)
    }
    d.h[0] ^= A
    d.h[1] ^= B
    d.h[2] ^= C
    d.h[3] ^= D
    d.h[4] ^= E
    d.h[5] ^= F
    d.h[6] ^= G
    d.h[7] ^= H
}

// SM3 helper funcs
func ff0(x, y, z uint32) uint32 {
    return x ^ y ^ z
}
func ff1(x, y, z uint32) uint32 {
    return (x & y) | (x & z) | (y & z)
}
func gg0(x, y, z uint32) uint32 {
    return x ^ y ^ z
}
func gg1(x, y, z uint32) uint32 {
    return (x & y) | (^x & z)
}
func p0(x uint32) uint32 {
    return x ^ rotl(x, 9) ^ rotl(x, 17)
}
func p1(x uint32) uint32 {
    return x ^ rotl(x, 15) ^ rotl(x, 23)
}
func rotl(x uint32, n uint) uint32 {
    return (x << n) | (x >> (32 - n))
}
func t(j int) uint32 {
    if j < 16 {
        return 0x79cc4519
    }
    return 0x7a879d8a
}
func putUint64BE(b []byte, v uint64) {
    b[0] = byte(v >> 56)
    b[1] = byte(v >> 48)
    b[2] = byte(v >> 40)
    b[3] = byte(v >> 32)
    b[4] = byte(v >> 24)
    b[5] = byte(v >> 16)
    b[6] = byte(v >> 8)
    b[7] = byte(v)
}
func putUint32BE(b []byte, v uint32) {
    b[0] = byte(v >> 24)
    b[1] = byte(v >> 16)
    b[2] = byte(v >> 8)
    b[3] = byte(v)
}
func getUint32BE(b []byte) uint32 {
    return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) |
        (uint32(b[2]) << 8) | uint32(b[3])
}

// sm3Hash(data...) => 32字节哈希
func sm3Hash(data ...[]byte) []byte {
    d := newSM3()
    for _, dd := range data {
        d.Write(dd)
    }
    return d.Sum(nil)
}

// =======================
//  SM2 椭圆曲线
// =======================

type sm2Curve struct {
    P  *big.Int
    A  *big.Int
    B  *big.Int
    Gx *big.Int
    Gy *big.Int
    N  *big.Int
}

var sm2p256 *sm2Curve

func init() {
    sm2p256 = &sm2Curve{
        P:  new(big.Int),
        A:  new(big.Int),
        B:  new(big.Int),
        Gx: new(big.Int),
        Gy: new(big.Int),
        N:  new(big.Int),
    }
    // SM2参数（GM/T 0003.5-2012）
    sm2p256.P.SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    sm2p256.A.SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
    sm2p256.B.SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    sm2p256.Gx.SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    sm2p256.Gy.SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
    sm2p256.N.SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
}

// SM2私钥、公钥
type SM2PrivateKey struct {
    D *big.Int
}
type SM2PublicKey struct {
    X, Y *big.Int
}

// 生成密钥对
func GenerateKey() (*SM2PrivateKey, *SM2PublicKey, error) {
    n := sm2p256.N
    bitLen := n.BitLen()
    for {
        dBytes := make([]byte, (bitLen+7)/8)
        _, err := rand.Read(dBytes)
        if err != nil {
            return nil, nil, err
        }
        d := new(big.Int).SetBytes(dBytes)
        // 1 <= d < n
        if d.Sign() != 0 && d.Cmp(n) < 0 {
            // pub = dG
            x, y := scalarBaseMult(d)
            return &SM2PrivateKey{D: d}, &SM2PublicKey{X: x, Y: y}, nil
        }
    }
}

// =======================
//   椭圆曲线点运算 (简化实现)
//   产线中请使用更优化的 gmsm.
// =======================

// scalarBaseMult(k) = k * G
func scalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
    return scalarMult(sm2p256.Gx, sm2p256.Gy, k)
}

// scalarMult(px, py, k) = k*(px, py)
func scalarMult(px, py, k *big.Int) (rx, ry *big.Int) {
    // "double-and-add" naive version
    rx, ry = big.NewInt(0), big.NewInt(0) // 点O
    bx, by := new(big.Int).Set(px), new(big.Int).Set(py)
    kk := new(big.Int).Set(k)

    for kk.Sign() > 0 {
        if kk.Bit(0) == 1 {
            rx, ry = pointAdd(rx, ry, bx, by)
        }
        bx, by = pointDouble(bx, by)
        kk.Rsh(kk, 1)
    }
    return rx, ry
}

// pointAdd (x1, y1) + (x2, y2)
func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    // if (x1,y1)==O, return (x2,y2)
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return new(big.Int).Set(x2), new(big.Int).Set(y2)
    }
    // if (x2,y2)==O, return (x1,y1)
    if x2.Sign() == 0 && y2.Sign() == 0 {
        return new(big.Int).Set(x1), new(big.Int).Set(y1)
    }

    p := sm2p256.P

    dx := new(big.Int).Sub(x2, x1)
    dy := new(big.Int).Sub(y2, y1)
    dx.Mod(dx, p)
    dy.Mod(dy, p)
    if dx.Sign() == 0 {
        // if x1=x2
        if dy.Sign() == 0 {
            // same point => double
            return pointDouble(x1, y1)
        }
        // P + (-P)= O
        return big.NewInt(0), big.NewInt(0)
    }
    inv := new(big.Int).ModInverse(dx, p)
    lambda := new(big.Int).Mul(dy, inv)
    lambda.Mod(lambda, p)

    rx := new(big.Int).Mul(lambda, lambda)
    rx.Sub(rx, x1)
    rx.Sub(rx, x2)
    rx.Mod(rx, p)

    ry := new(big.Int).Sub(x1, rx)
    ry.Mul(ry, lambda)
    ry.Sub(ry, y1)
    ry.Mod(ry, p)

    return rx, ry
}

// pointDouble 2*(x,y)
func pointDouble(x, y *big.Int) (*big.Int, *big.Int) {
    if x.Sign() == 0 && y.Sign() == 0 {
        return big.NewInt(0), big.NewInt(0)
    }
    p := sm2p256.P
    a := sm2p256.A

    two := big.NewInt(2)
    three := big.NewInt(3)

    yy := new(big.Int).Mul(y, y) // y^2
    yy.Mod(yy, p)
    xx := new(big.Int).Mul(x, x) // x^2
    xx.Mod(xx, p)

    // lam = (3*x^2 + a) / (2*y)
    numerator := new(big.Int).Mul(three, xx)
    numerator.Add(numerator, a)
    numerator.Mod(numerator, p)

    denominator := new(big.Int).Mul(two, y)
    denominator.ModInverse(denominator, p)
    lambda := new(big.Int).Mul(numerator, denominator)
    lambda.Mod(lambda, p)

    rx := new(big.Int).Mul(lambda, lambda)
    rx.Sub(rx, new(big.Int).Mul(two, x))
    rx.Mod(rx, p)

    ry := new(big.Int).Sub(x, rx)
    ry.Mul(ry, lambda)
    ry.Sub(ry, y)
    ry.Mod(ry, p)

    return rx, ry
}

// =======================
//   计算 ZA
// =======================
// ZA = SM3( entl(ID) || ID || a || b || Gx || Gy || Px || Py )

func ZA(pub *SM2PublicKey, userID string) []byte {
    uidLen := len(userID)
    // entl = 16bit, big-endian, 表示 userID 的 bit 长度
    ent := []byte{byte((uidLen * 8) >> 8), byte(uidLen * 8)}
    return sm3Hash(
        ent,
        []byte(userID),
        sm2p256.A.Bytes(),
        sm2p256.B.Bytes(),
        sm2p256.Gx.Bytes(),
        sm2p256.Gy.Bytes(),
        pub.X.Bytes(),
        pub.Y.Bytes(),
    )
}

// =======================
//   SM2 签名/验签
// =======================

func SM2Sign(prv *SM2PrivateKey, pub *SM2PublicKey, userID string, msg []byte) (r, s *big.Int, err error) {
    // e = SM3(ZA || M)
    za := ZA(pub, userID)
    eBytes := sm3Hash(za, msg)
    e := new(big.Int).SetBytes(eBytes)

    n := sm2p256.N
    d := prv.D

    // 需要同时声明 k, x1, y1
    var k, x1  *big.Int



    for {
        // 1. 随机k in [1, n-1]
        k, x1, y1 = genRandK()
        // r = (e + x1) mod n
        r = new(big.Int).Add(e, x1)
        r.Mod(r, n)
        if r.Sign() == 0 {
            continue
        }
        // s = ((k - r*d) mod n) * (1+d)^-1 mod n
        rd := new(big.Int).Mul(r, d)
        rd.Mod(rd, n)
        left := new(big.Int).Sub(k, rd)
        left.Mod(left, n)

        d1 := new(big.Int).Add(d, big.NewInt(1))
        d1.Mod(d1, n)
        inv := new(big.Int).ModInverse(d1, n)
        if inv == nil {
            continue
        }
        s = new(big.Int).Mul(left, inv)
        s.Mod(s, n)
        if s.Sign() == 0 {
            continue
        }
        break
    }
    return r, s, nil
}

func SM2Verify(pub *SM2PublicKey, userID string, msg []byte, r, s *big.Int) bool {
    n := sm2p256.N
    if r.Sign() <= 0 || r.Cmp(n) >= 0 {
        return false
    }
    if s.Sign() <= 0 || s.Cmp(n) >= 0 {
        return false
    }
    // e
    za := ZA(pub, userID)
    eBytes := sm3Hash(za, msg)
    e := new(big.Int).SetBytes(eBytes)

    t := new(big.Int).Add(r, s)
    t.Mod(t, n)
    if t.Sign() == 0 {
        return false
    }
    // (x1, y1) = s*G + t*P
    sGx, sGy := scalarBaseMult(s)
    tPx, tPy := scalarMult(pub.X, pub.Y, t)
    // 我们只关心 x1, 用不到 y1 => 用下划线 _
    x1, _ := pointAdd(sGx, sGy, tPx, tPy)
    x1.Mod(x1, n) // mod n

    // R' = (e + x1) mod n
    Rdash := new(big.Int).Add(e, x1)
    Rdash.Mod(Rdash, n)
    return Rdash.Cmp(r) == 0
}

// 生成随机k并计算 k*G -> (x1,y1)
func genRandK() (*big.Int, *big.Int, *big.Int) {
    n := sm2p256.N
    bitLen := n.BitLen()
    for {
        b := make([]byte, (bitLen+7)/8)
        rand.Read(b)
        k := new(big.Int).SetBytes(b)
        k.Mod(k, n)
        if k.Sign() != 0 {
            x1, y1 := scalarBaseMult(k)
            return k, x1, y1
        }
    }
}

// =======================
//   SM2 加密/解密 (C1||C3||C2)
// =======================

func SM2Encrypt(pub *SM2PublicKey, msg []byte) ([]byte, error) {
    for {
        k, x1, y1 := genRandK()
        // x2,y2 = k*(Px, Py)
        x2, y2 := scalarMult(pub.X, pub.Y, k)
        // KDF => length(msg)
        key := sm2KDF(x2, y2, len(msg))
        if allZero(key) {
            // kdf全0, 重试
            continue
        }
        c2 := make([]byte, len(msg))
        for i:=0; i<len(msg); i++ {
            c2[i] = msg[i]^key[i]
        }
        c3 := sm3Hash(x2.Bytes(), msg, y2.Bytes())

        // c1 => 04||x1||y1
        c1Len := (sm2p256.N.BitLen()+7)/8
        c1 := make([]byte, 1+2*c1Len)
        c1[0] = 0x04
        fillBytes(c1[1:1+c1Len], x1, c1Len)
        fillBytes(c1[1+c1Len:], y1, c1Len)

        cipher := make([]byte, 0, len(c1)+len(c3)+len(c2))
        cipher = append(cipher, c1...)
        cipher = append(cipher, c3...)
        cipher = append(cipher, c2...)
        return cipher, nil
    }
}

func SM2Decrypt(prv *SM2PrivateKey, cipher []byte) ([]byte, error) {
    c1Len := (sm2p256.N.BitLen()+7)/8*2 + 1
    if len(cipher) < c1Len+32 {
        return nil, errors.New("invalid cipher")
    }
    c1 := cipher[:c1Len]
    c3 := cipher[c1Len:c1Len+32]
    c2 := cipher[c1Len+32:]
    if c1[0] != 0x04 {
        return nil, errors.New("only uncompressed format")
    }
    coordLen := (c1Len-1)/2
    x1 := new(big.Int).SetBytes(c1[1:1+coordLen])
    y1 := new(big.Int).SetBytes(c1[1+coordLen:1+2*coordLen])

    // (x2,y2)= d*(x1,y1)
    x2,y2 := scalarMult(x1, y1, prv.D)
    key := sm2KDF(x2, y2, len(c2))
    if allZero(key) {
        return nil, errors.New("kdf=0 => fail")
    }
    plain := make([]byte, len(c2))
    for i:=0; i<len(c2); i++ {
        plain[i] = c2[i]^key[i]
    }
    // check c3
    uhash := sm3Hash(x2.Bytes(), plain, y2.Bytes())
    if !equal(uhash, c3) {
        return nil, errors.New("c3 mismatch => tampered")
    }
    return plain, nil
}

// SM2 KDF
func sm2KDF(x2,y2 *big.Int, length int) []byte {
    var out []byte
    ct:=1
    for len(out)<length {
        ctx := newSM3()
        ctx.Write(x2.Bytes())
        ctx.Write(y2.Bytes())

        buf := []byte{byte(ct>>24), byte(ct>>16), byte(ct>>8), byte(ct)}
        ctx.Write(buf)
        hashv := ctx.Sum(nil)
        out = append(out, hashv...)
        ct++
    }
    return out[:length]
}

func allZero(b []byte) bool {
    for _,v := range b {
        if v!=0 {return false}
    }
    return true
}

func fillBytes(dst []byte, x *big.Int, length int) {
    tmp:=x.Bytes()
    offset := length-len(tmp)
    for i:=0;i<offset;i++{
        dst[i]=0
    }
    copy(dst[offset:], tmp)
}

func equal(a,b []byte) bool {
    if len(a)!=len(b) {return false}
    for i:=0;i<len(a);i++ {
        if a[i]!=b[i] {return false}
    }
    return true
}

// =======================
//      演示 main
// =======================

func main(){
    fmt.Println("========= SM2 + SM3 DEMO =========\n")
    // 1) 生成SM2密钥
    prv, pub, err := GenerateKey()
    if err!=nil { panic(err) }
    fmt.Println("私钥 d=", prv.D)
    fmt.Println("公钥 X=", pub.X, "\n    Y=", pub.Y)

    // 2) 签名/验签
    userID := "1234567812345678" // 国密推荐16字节或其他可行ID
    msgSig := []byte("Hello SM2 + SM3!")
    fmt.Println("\n--- [签名/验签] ---")
    r,s, err := SM2Sign(prv, pub, userID, msgSig)
    if err!=nil {
        fmt.Println("签名失败:",err)
        return
    }
    fmt.Printf("签名(r,s) = (%X, %X)\n", r,s)
    ok := SM2Verify(pub, userID, msgSig, r,s)
    fmt.Println("验签结果=", ok)

    // 3) 加密/解密
    msgEnc := []byte("你好，世界! This is SM2 encryption with SM3 KDF.")
    fmt.Println("\n--- [加密/解密] ---\n明文=", string(msgEnc))

    ctData, err := SM2Encrypt(pub, msgEnc)
    if err!=nil {
        fmt.Println("加密失败:", err)
        return
    }
    fmt.Println("密文(hex)=", fmt.Sprintf("%X", ctData))

    decData, err := SM2Decrypt(prv, ctData)
    if err!=nil {
        fmt.Println("解密失败:", err)
        return
    }
    fmt.Println("解密结果=", string(decData))
}
