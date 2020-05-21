package paillier

import (
	"testing"
)

var (
	benchbit = 1024
	prv string
	pub string
	plain1 = 25
	plain2 = 12
	scal = 10
	cipher1 string
	cipher2 string
)

func BenchmarkKeyGen(b *testing.B) {
	for i:=0;i<b.N;i++ {
		testKeyGen()
	}
}
func BenchmarkEnc(b *testing.B) {
	for i:=0;i<b.N;i++ {
		testEnc()
	}
}
func BenchmarkDec(b *testing.B) {
	for i:=0;i<b.N;i++ {
		testDec()
	}
}
func BenchmarkAdd(b *testing.B) {
	for i:=0;i<b.N;i++ {
		testMul()
	}
}
func BenchmarkMul(b *testing.B) {
	for i:=0;i<b.N;i++ {
		testExp()
	}
}

func testKeyGen() {
	prv, pub = KeyGen(benchbit)
}
func testEnc() {
	cipher1 = PaillierEnc(uint64(plain1), pub)
	cipher2 = PaillierEnc(uint64(plain2), pub)
}
func testDec() {
	PaillierDec(cipher1, prv)
}
func testMul() {
	PaillierMul(pub, cipher1, cipher2)
}
func testExp() {
	PaillierExp(pub, cipher1, uint32(scal))
}
