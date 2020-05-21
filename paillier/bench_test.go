package paillier

import (
	"math/big"
	"testing"
)

var (
	benchbit = 1024
	prv string
	pub string
	plain1 = big.NewInt(25)
	plain2 = big.NewInt(12)
	scal = big.NewInt(10)
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
	prv, pub, _ = KeyGen(benchbit)
}
func testEnc() {
	cipher1,_ = PaillierEnc(plain1, pub)
	cipher2,_ = PaillierEnc(plain2, pub)
}
func testDec() {
	PaillierDec(cipher1, prv)
}
func testMul() {
	PaillierMul(pub, cipher1, cipher2)
}
func testExp() {
	PaillierExp(pub, cipher1, scal)
}
