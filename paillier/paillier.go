package paillier

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/xuperdata/teesdk/paillier/xchain_plugin/pb"
	"github.com/xuperdata/teesdk/utils"
)

type PaillierClient struct{}

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
		return "", fmt.Errorf("submit error: %v", err)
	}
	return resMapStr, nil
}

// wrap method outputs to map
func KeyGenToMap(caller FuncCaller) (string, error) {
	if caller.Args == "" {
		return "", errors.New("KeyGen errors, args nil")
	}
	var params pb.KeyGenParams
	err := json.Unmarshal([]byte(caller.Args), &params)
	if err != nil {
		return "", fmt.Errorf("unmarshal args error: %v", err)
	}
	prvkey, pubkey, err := KeyGen(int(params.Secbit))
	if err != nil {
		return "", fmt.Errorf("KeyGen error: %v", err)
	}
	outputs := pb.KeyGenOutputs{
		PrivateKey: prvkey,
		PublicKey:  pubkey,
	}

	resStr, err := json.Marshal(outputs)
	if err != nil {
		return "", errors.New("marshal KeyGen result error")
	}
	return string(resStr), nil
}

func PaillierEncToMap(caller FuncCaller) (string, error) {
	if caller.Args == "" {
		return "", errors.New("PaillierEnc errors, args nil")
	}
	var params pb.PaillierEncParams
	err := json.Unmarshal([]byte(caller.Args), &params)
	if err != nil {
		return "", fmt.Errorf("unmarshal args error: %v", err)
	}
	msg, v := new(big.Int).SetString(params.Message, 10)
	if v != true {
		return "", fmt.Errorf("set message to big int error")
	}
	cipher, err := PaillierEnc(msg, params.PublicKey)
	if err != nil {
		return "", fmt.Errorf("PaillierEnc error: %v", err)
	}
	outputs := pb.PaillierEncOutputs{
		Ciphertext: cipher,
	}

	resStr, err := json.Marshal(outputs)
	if err != nil {
		return "", errors.New("marshal PaillierEnc result error")
	}
	return string(resStr), nil
}

func PaillierDecToMap(caller FuncCaller) (string, error) {
	if caller.Args == "" {
		return "", errors.New("PaillierDec errors, args nil")
	}
	var params pb.PaillierDecParams
	err := json.Unmarshal([]byte(caller.Args), &params)
	if err != nil {
		return "", fmt.Errorf("unmarshal args error: %v", err)
	}
	prvkey, err := utils.ReadPrvKey(params.PrvkeyPath, params.Password)
	if err != nil {
		return "", fmt.Errorf("import private key error: %v", err)
	}

	plain, err := PaillierDec(params.Ciphertext, prvkey)
	if err != nil {
		return "", fmt.Errorf("PaillierDec error: %v", err)
	}
	outputs := pb.PaillierDecOutputs{
		Plaintext: plain.String(),
	}

	resStr, err := json.Marshal(outputs)
	if err != nil {
		return "", errors.New("marshal PaillierDec result error")
	}
	return string(resStr), nil
}

func PaillierMulToMap(caller FuncCaller) (string, error) {
	if caller.Args == "" {
		return "", errors.New("PaillierMul errors, args nil")
	}
	var params pb.PaillierMulParams
	err := json.Unmarshal([]byte(caller.Args), &params)
	if err != nil {
		return "", fmt.Errorf("unmarshal args error: %v", err)
	}
	// authorization check
	v, err := CheckCommitment(params.Ciphertext1, caller.Address, params.Commitment1)
	if err != nil {
		return "", fmt.Errorf("check commitment1 error: %v", err)
	}
	if v != true {
		return "", errors.New("not authorized to use ciphertext1")
	}
	v, err = CheckCommitment(params.Ciphertext2, caller.Address, params.Commitment2)
	if err != nil {
		return "", fmt.Errorf("check commitment2 error: %v", err)
	}
	if v != true {
		return "", errors.New("not authorized to use ciphertext2")
	}

	cipher, err := PaillierMul(params.PublicKey, params.Ciphertext1, params.Ciphertext2)
	if err != nil {
		return "", fmt.Errorf("PaillierMul error: %v", err)
	}
	outputs := pb.PaillierMulOutputs{
		Ciphertext: cipher,
	}

	resStr, err := json.Marshal(outputs)
	if err != nil {
		return "", errors.New("marshal PaillierMul result error")
	}
	return string(resStr), nil
}

func PaillierExpToMap(caller FuncCaller) (string, error) {
	if caller.Args == "" {
		return "", errors.New("PaillierExp errors, args nil")
	}
	var params pb.PaillierExpParams
	err := json.Unmarshal([]byte(caller.Args), &params)
	if err != nil {
		return "", fmt.Errorf("unmarshal args error: %v", err)
	}
	// authorization check
	v, err := CheckCommitment(params.Ciphertext, caller.Address, params.Commitment)
	if err != nil {
		return "", fmt.Errorf("check commitment error: %v", err)
	}
	if v != true {
		return "", errors.New("not authorized to use ciphertext")
	}

	scalarInput, v := new(big.Int).SetString(params.Scalar, 10)
	if v != true {
		return "", fmt.Errorf("set scalar to big int error")
	}
	cipher, err := PaillierExp(params.PublicKey, params.Ciphertext, scalarInput)
	if err != nil {
		return "", fmt.Errorf("PaillierExp error: %v", err)
	}
	outputs := pb.PaillierExpOutputs{
		Ciphertext: cipher,
	}

	resStr, err := json.Marshal(outputs)
	if err != nil {
		return "", errors.New("marshal PaillierExp result error")
	}
	return string(resStr), nil
}

// paillier key generation
func KeyGen(secbit int) (prv string, pub string, err error) {
	keylen := secbit / 2
	p, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return "", "", fmt.Errorf("generate random number error: %v", err)
	}
	q, err := rand.Prime(rand.Reader, keylen)
	if err != nil {
		return "", "", fmt.Errorf("generate random number error: %v", err)
	}
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)
	pinvq := new(big.Int).ModInverse(p, q)
	n := new(big.Int).Mul(p, q)
	nn := new(big.Int).Mul(n, n)
	lambda := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	mu := new(big.Int).ModInverse(lambda, n)
	g := new(big.Int).Add(n, one)
	prvkey := &PrivateKey{
		PublicKey: PublicKey{
			N:  n,
			G:  g,
			NN: nn,
		},
		P:      p,
		Q:      q,
		PP:     pp,
		QQ:     qq,
		PinvQ:  pinvq,
		Lambda: lambda,
		Mu:     mu,
	}
	return PrivateToString(prvkey), PublicToString(&prvkey.PublicKey), nil
}

// c = G^m*r^N (mod N^2)
func PaillierEnc(m *big.Int, pubBase64 string) (string, error) {
	pubkey, err := PublicFromString(pubBase64)
	if err != nil {
		return "", err
	}
	r, err := rand.Int(rand.Reader, pubkey.N)
	if err != nil {
		return "", fmt.Errorf("generate random number error: %v", err)
	}
	if new(big.Int).Mod(pubkey.N, r).Cmp(zero) == 0 {
		return "", errors.New("improper random number, please try again")
	}
	gm := new(big.Int).Exp(pubkey.G, m, pubkey.NN)
	rn := new(big.Int).Exp(r, pubkey.N, pubkey.NN)
	cipher := new(big.Int).Mod(new(big.Int).Mul(gm, rn), pubkey.NN)
	return CipherToString(cipher), nil
}

// m = L(c^Lambda mod N^2)*Mu (mod N)
// optimization using CRT [Paillier99, section 7](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
func PaillierDec(cipherBase64, prvBase64 string) (*big.Int, error) {
	prvkey, err := PrivateFromString(prvBase64)
	if err != nil {
		return nil, err
	}
	c, err := CipherFromString(cipherBase64)
	if err != nil {
		return nil, err
	}
	if c.Cmp(prvkey.NN) >= 0 {
		return nil, errors.New("ciphertext must be smaller than n square")
	}
	p1 := new(big.Int).Sub(prvkey.P, one)
	cp := new(big.Int).Exp(c, p1, prvkey.PP)
	lp := L(cp, prvkey.P)

	gp := new(big.Int).Mod(new(big.Int).Sub(one, prvkey.N), prvkey.PP)
	llp := L(gp, prvkey.P)
	hp := new(big.Int).ModInverse(llp, prvkey.P)
	a1 := new(big.Int).Mod(new(big.Int).Mul(lp, hp), prvkey.P)

	q1 := new(big.Int).Sub(prvkey.Q, one)
	cq := new(big.Int).Exp(c, q1, prvkey.QQ)
	lq := L(cq, prvkey.Q)

	gq := new(big.Int).Mod(new(big.Int).Sub(one, prvkey.N), prvkey.QQ)
	llq := L(gq, prvkey.Q)
	hq := new(big.Int).ModInverse(llq, prvkey.Q)
	a2 := new(big.Int).Mod(new(big.Int).Mul(lq, hq), prvkey.Q)
	return CRT(a1, a2, prvkey), nil
}

// cipherMul = cipher1*cipher2 (mod N^2)
func PaillierMul(pubBase64, cipher1Base64, cipher2Base64 string) (string, error) {
	cipher1, err := CipherFromString(cipher1Base64)
	if err != nil {
		return "", err
	}
	cipher2, err := CipherFromString(cipher2Base64)
	if err != nil {
		return "", err
	}
	pubkey, err := PublicFromString(pubBase64)
	if err != nil {
		return "", err
	}
	cipherMul := new(big.Int).Mod(new(big.Int).Mul(cipher1, cipher2), pubkey.NN)
	return CipherToString(cipherMul), nil
}

// cipherExp = cipher^scalar (mod N^2)
func PaillierExp(pubBase64, cipherBase64 string, scalar *big.Int) (string, error) {
	cipher, err := CipherFromString(cipherBase64)
	if err != nil {
		return "", err
	}
	pubkey, err := PublicFromString(pubBase64)
	if err != nil {
		return "", err
	}
	cipherExp := new(big.Int).Exp(cipher, scalar, pubkey.NN)
	return CipherToString(cipherExp), nil
}

// L(x) = (x-1)/n
func L(x *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// Chinese remainder theorem
// m = a_1 + (a_2 - a_1)P^{-1}modQ * P (mod N)
func CRT(a1, a2 *big.Int, prvkey *PrivateKey) *big.Int {
	dif := new(big.Int).Sub(a2, a1)
	difP := new(big.Int).Mod(new(big.Int).Mul(dif, prvkey.PinvQ), prvkey.Q)
	difPP := new(big.Int).Mul(difP, prvkey.P)
	return new(big.Int).Mod(new(big.Int).Add(a1, difPP), prvkey.N)
}
