package paillier

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"github.com/xuperdata/teesdk/paillier/xchain_plugin/pb"
)

type PaillierClient struct {}
var kInstance *PaillierClient
var once sync.Once
func NewPaillierClient() *PaillierClient {
	if kInstance != nil {
		return kInstance
	}
	once.Do(func() {
		kInstance = &PaillierClient{}
	})
	return kInstance
}

func (s *PaillierClient) Close() {
}

func (s *PaillierClient) Submit(method string, inputs string) (string, error) {
	if method != "paillier" {
		return "", errors.New("submit error, wrong method, supposed to be paillier")
	}

	var caller FuncCaller
	err := json.Unmarshal([]byte(inputs), &caller)
	if err != nil {
		return "", errors.New("submit error, unmarshal inputs error")
	}

	var resMapStr string
	switch caller.Method {
	case "PaillierKeyGen":
		resMapStr, err = KeyGenToMap(caller)
	case "PaillierEnc":
		resMapStr, err = PaillierEncToMap(caller)
	case "PaillierDec":
		resMapStr, err = PaillierDecToMap(caller)
	case "PaillierMul":
		resMapStr, err = PaillierMulToMap(caller)
	case "PaillierExp":
		resMapStr, err = PaillierExpToMap(caller)
	default:
		return "", errors.New("submit error, invalid paillier method")
	}

	if err != nil {
		return "", fmt.Errorf("submit error,  %v", err)
	}

	return resMapStr,nil
}

// wrap method outputs to map
func KeyGenToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("KeyGen errors, args nil")
	}
	var params pb.KeyGenParams
	json.Unmarshal([]byte(caller.Args), &params)
	prvkey, pubkey := KeyGen(int(params.Secbit))
	outputs := pb.KeyGenOutputs{
		PrivateKey: prvkey,
		PublicKey: pubkey,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("KeyGen errors, marshal result error")
	}
	return string(resStr), nil
}

func PaillierEncToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierEnc errors, args nil")
	}
	var params pb.PaillierEncParams
	json.Unmarshal([]byte(caller.Args), &params)
	msg,_  := strconv.Atoi(params.Message)
	cipher := PaillierEnc(uint64(msg), params.PublicKey)
	outputs := pb.PaillierEncOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierEnc errors, marshal result error")
	}
	return string(resStr), nil
}

func PaillierDecToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierDec errors, args nil")
	}
	var params pb.PaillierDecParams
	json.Unmarshal([]byte(caller.Args), &params)
	prvkey,err := ReadPrvKey(params.PrvkeyPath, params.Password)
	if err!=nil {
		return "", errors.New("PaillierDec errors, import private key failed")
	}

	plain := PaillierDec(params.Ciphertext, prvkey)
	outputs := pb.PaillierDecOutputs{
		Plaintext: plain,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierDec errors, marshal result error")
	}
	return string(resStr), nil
}

func PaillierMulToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierMul errors, args nil")
	}
	var params pb.PaillierMulParams
	json.Unmarshal([]byte(caller.Args), &params)

	// authorization check
	v := CheckCommitment(params.Ciphertext1, caller.Address, params.Commitment1)
	if v != true {
		return "", errors.New("not authorized to use ciphertext1")
	}
	v = CheckCommitment(params.Ciphertext2, caller.Address, params.Commitment2)
	if v != true {
		return "", errors.New("not authorized to use ciphertext2")
	}

	cipher := PaillierMul(params.PublicKey, params.Ciphertext1, params.Ciphertext2)
	outputs := pb.PaillierMulOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierMul errors, marshal result error")
	}
	return string(resStr), nil
}

func PaillierExpToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierExp errors, args nil")
	}
	var params pb.PaillierExpParams
	json.Unmarshal([]byte(caller.Args), &params)

	// authorization check
	v := CheckCommitment(params.Ciphertext, caller.Address, params.Commitment)
	if v != true {
		return "", errors.New("not authorized to use ciphertext")
	}

	scalarInput,_ := strconv.Atoi(params.Scalar)
	cipher := PaillierExp(params.PublicKey, params.Ciphertext, uint32(scalarInput))
	outputs := pb.PaillierExpOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierExp errors, marshal result error")
	}
	return string(resStr), nil
}

// paillier encryption method
func KeyGen(secbit int) (prv string, pub string){
	keylen := secbit/2
	p,_ := rand.Prime(rand.Reader, keylen)
	q,_ := rand.Prime(rand.Reader, keylen)
	n := new(big.Int).Mul(p,q)
	nn := new(big.Int).Mul(n,n)
	lambda := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	mu := new(big.Int).ModInverse(lambda, n)
	g := new(big.Int).Add(n, one)
	prvkey := &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			G:        g,
			NN:       nn,
		},
		P: p,
		Q: q,
		Lambda: lambda,
		Mu: mu,
	}
	return PrivateToString(prvkey), PublicToString(&prvkey.PublicKey)
}

// c=G^m*r^N (mod N^2)
func PaillierEnc(msg uint64, pubBase64 string) string{
	pubkey := PublicFromString(pubBase64)
	m := big.NewInt(int64(msg))
	r,_ := rand.Int(rand.Reader, pubkey.N)
	if new(big.Int).Mod(pubkey.N, r).Cmp(zero) == 0 {
		return ""
	}
	gm := new(big.Int).Exp(pubkey.G, m, pubkey.NN)
	rn := new(big.Int).Exp(r, pubkey.N, pubkey.NN)
	cipher := new(big.Int).Mod(new(big.Int).Mul(gm, rn),pubkey.NN)
	return CipherToString(cipher)
}

// m=L(c^Lambda mod N^2)*Mu (mod N)
func PaillierDec(cipherBase64, prvBase64 string) uint64{
	prvkey := PrivateFromString(prvBase64)
	c := CipherFromString(cipherBase64)
	nn := prvkey.PublicKey.NN
	clambda := new(big.Int).Exp(c, prvkey.Lambda, nn)
	lc := L(clambda, prvkey.PublicKey.N)
	lcn := new(big.Int).Mod(lc, prvkey.PublicKey.N)
	lmu := new(big.Int).Mul(lcn, prvkey.Mu)
	return new(big.Int).Mod(lmu, prvkey.PublicKey.N).Uint64()
}

func PaillierMul(pubBase64, cipher1Base64, cipher2Base64 string) string{
	cipher1 := CipherFromString(cipher1Base64)
	cipher2 := CipherFromString(cipher2Base64)
	pubkey := PublicFromString(pubBase64)
	cipherMul := new(big.Int).Mod(new(big.Int).Mul(cipher1,cipher2), pubkey.NN)
	return CipherToString(cipherMul)
}

func PaillierExp(pubBase64, cipherBase64 string, plain uint32) string{
	cipher := CipherFromString(cipherBase64)
	scalar := big.NewInt(int64(plain))
	pubkey := PublicFromString(pubBase64)
	cipherExp := new(big.Int).Exp(cipher, scalar, pubkey.NN)
	return CipherToString(cipherExp)
}

// L(x) = (x-1)/n
func L(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}
