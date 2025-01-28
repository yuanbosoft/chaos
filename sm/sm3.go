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
	"encoding/binary"
	"fmt"
	"hash"
    "strings"
)

const (
	BlockSize  = 64
	DigestSize = 32
)

type sm3 struct {
	state  [8]uint32
	buffer [BlockSize]byte
	offset int
	length uint64
}

func New() hash.Hash {
	s := &sm3{}
	s.Reset()
	return s
}

func (s *sm3) Reset() {
	s.state = [8]uint32{
		0x7380166f,
		0x4914b2b9,
		0x172442d7,
		0xda8a0600,
		0xa96f30bc,
		0x163138aa,
		0xe38dee4d,
		0xb0fb0e4e,
	}
	s.offset = 0
	s.length = 0
}

func (s *sm3) Size() int      { return DigestSize }
func (s *sm3) BlockSize() int { return BlockSize }

func (s *sm3) Write(data []byte) (int, error) {
	n := len(data)
	s.length += uint64(n)

	if s.offset > 0 {
		copied := copy(s.buffer[s.offset:], data)
		s.offset += copied
		data = data[copied:]

		if s.offset == BlockSize {
			s.compress(s.buffer[:])
			s.offset = 0
		}
	}

	for len(data) >= BlockSize {
		s.compress(data[:BlockSize])
		data = data[BlockSize:]
	}

	if len(data) > 0 {
		s.offset = copy(s.buffer[:], data)
	}

	return n, nil
}

func (s *sm3) Sum(in []byte) []byte {
	s0 := *s
	hash := s0.checkSum()
	return append(in, hash[:]...)
}

func (s *sm3) checkSum() [DigestSize]byte {
	totalBits := s.length << 3
	padding := []byte{0x80}

	used := (s.length + 1) % BlockSize
	needed := (56 + BlockSize - used) % BlockSize
	padding = append(padding, make([]byte, needed)...)

	s.Write(padding)

	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, totalBits)
	s.Write(lenBuf)

	var digest [DigestSize]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(digest[i*4:], s.state[i])
	}
	return digest
}

func (s *sm3) compress(data []byte) {
	var w [68]uint32
	var ww [64]uint32

	// 消息扩展
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(data[i*4:])
	}

	for i := 16; i < 68; i++ {
		w[i] = p1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
	}

	for i := 0; i < 64; i++ {
		ww[i] = w[i] ^ w[i+4]
	}

	a, b, c, d, e, f, g, h := s.state[0], s.state[1], s.state[2], s.state[3], s.state[4], s.state[5], s.state[6], s.state[7]

	for i := 0; i < 64; i++ {
		// 关键修正点：移除 T_j 的位移操作
		ss1 := rotl(rotl(a, 12)+e+rotl(t(i), uint(i%32)), 7) // 保留 T_j 位移但修正位移位数
		ss2 := ss1 ^ rotl(a, 12)
		tt1 := ff(a, b, c, i) + d + ss2 + ww[i]
		tt2 := gg(e, f, g, i) + h + ss1 + w[i]
		d = c
		c = rotl(b, 9)
		b = a
		a = tt1
		h = g
		g = rotl(f, 19)
		f = e
		e = p0(tt2)
	}

	s.state[0] ^= a
	s.state[1] ^= b
	s.state[2] ^= c
	s.state[3] ^= d
	s.state[4] ^= e
	s.state[5] ^= f
	s.state[6] ^= g
	s.state[7] ^= h
}

func rotl(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

func p0(x uint32) uint32 {
	return x ^ rotl(x, 9) ^ rotl(x, 17)
}

func p1(x uint32) uint32 {
	return x ^ rotl(x, 15) ^ rotl(x, 23)
}

func ff(x, y, z uint32, i int) uint32 {
	if i < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func gg(x, y, z uint32, i int) uint32 {
	if i < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

func t(i int) uint32 {
	if i < 16 {
		return 0x79cc4519
	}
	return 0x7a879d8a
}

/*
func main() {
	testCases := []struct {
		input  string
		expect string
	}{
		{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{"hello world", "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88"},
		{"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		{"abcdefghijklmnopqrstuvwxyz", "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595"},
	}

	for _, tc := range testCases {
		s := New()
		s.Write([]byte(tc.input))
		hash := s.Sum(nil)
		fmt.Printf("Input: %-30q\nHash: %x\nValid: %t\n\n",
			tc.input, hash, fmt.Sprintf("%x", hash) == tc.expect)
	}
}
    */

    func main() {
        // 标准测试向量
        testCases := []struct {
            input  string
            expect string
        }{
            // 空输入
            {"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
            
            // NIST 标准测试向量
            {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
            {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
            
            // 块边界测试
            { // 63字节 (刚好不满一个块)
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
                "bbd4283c1735f9419c2ff6ad7ec15a96e120c5636d8fc554d7956f982fc9faa9",
            },
            { // 64字节 (完整块)
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "4b4d6a96cd505afcfc069de88ef3ddc947cbd47e7a5161c9ddf9d637153ccda2",
            },
            { // 65字节 (跨块)
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
                "131c09b6717c436db17416d71ba6d57add75117a877802b4de2065decf0c56b2",
            },
            
            // 中文长消息测试
            { "成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希成 SM3 哈希使用 OpenSSL 生成 SM3 哈希", 
                "7dfedce0ce4cb632c0de9f2277aed9c0b521d3d148fa960ccc91036326948473",
            },
            { // 重复模式
                strings.Repeat("12345", 20000), // 100,000字节
                "b374d44dbc7ddbe3892555f7a554d0eae3322587df8f15424dbbf3fa60425d21",
            },
            
            // 特殊字符测试   
            {"中文汉字测试", "1f386575d25a4e1dd28a3aec31e88b4831d5088948a677242facbd0972e94b25"},
            {"🚀🌕✨", "d7fc692a429d8b71eca62d0f84d9ce8ca0c1c34a79e71f1ad60974b6b11230fa"},
        }
    
        // 运行测试
        for _, tc := range testCases {
            s := New()
            s.Write([]byte(tc.input))
            hash := s.Sum(nil)
            
            result := fmt.Sprintf("%x", hash)
            valid := result == tc.expect
            
            fmt.Printf("Input: %-30q\nLength: %d\nHash: %s\nValid: %t\n\n",
                abbreviate(tc.input, 20), len(tc.input), result, valid)


        }
    }
    
    // 辅助函数：长字符串缩写显示
    func abbreviate(s string, maxLen int) string {
        runes := []rune(s)
        if len(runes) <= maxLen {
            return s
        }
        return string(runes[:maxLen]) + fmt.Sprintf("...(%d more)", len(runes)-maxLen)
    }
