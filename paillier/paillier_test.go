package paillier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/xuperchain/crypto/core/account"
	"strconv"
	"testing"

	"github.com/xuperdata/teesdk/utils"
)

var (
	testBit     = 1024
	prvkey      string
	pubkey      string
	plaintext1  = 25
	plaintext2  = 12
	scalar      = 10
	ciphertext1 string
	ciphertext2 string
	cipherMul   string
	cipherExp   string
	commitment1 string
	commitment2 string
	owner       = ""
	user        = "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	client      = NewPaillierClient()
	path        = "./paillierPrv.key"
	password    = "123456"
)

func getPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	prvkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubkey := ecdsa.PublicKey{elliptic.P256(), prvkey.X, prvkey.Y}
	owner, err = account.GetAddressFromPublicKey(&pubkey)
	if err != nil {
		t.Fatal(err)
	}
	return prvkey
}

// test paillier client method
func TestKeyGen(t *testing.T) {
	keyGenData := map[string]int{
		"secbit": testBit,
	}
	data, err := json.Marshal(keyGenData)
	if err != nil {
		t.Fatal(err)
	}
	caller := &FuncCaller{
		Method:  "PaillierKeyGen",
		Args:    string(data),
		Address: owner,
	}
	data, err = json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call paillier and encrypt testdata
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get two ciphertexts
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	prvkey = resMap["privateKey"]
	pubkey = resMap["publicKey"]
	utils.SavePrvKey(path, password, prvkey)
	t.Logf("private key: %s\n", prvkey)
	t.Logf("public key: %s\n", pubkey)
}

func TestEnc(t *testing.T) {
	encData1 := map[string]string{
		"message":   strconv.Itoa(plaintext1),
		"publicKey": pubkey,
	}
	data, err := json.Marshal(encData1)
	if err != nil {
		t.Fatal(err)
	}
	caller := &FuncCaller{
		Method:  "PaillierEnc",
		Args:    string(data),
		Address: owner,
	}
	data, err = json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call paillier and encrypt plaintext1
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphertext1
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext1 = resMap["ciphertext"]

	// encrypt plaintext2
	encData2 := map[string]string{
		"message":   strconv.Itoa(plaintext2),
		"publicKey": pubkey,
	}
	data, err = json.Marshal(encData2)
	if err != nil {
		t.Fatal(err)
	}
	caller2 := &FuncCaller{
		Method:  "PaillierEnc",
		Args:    string(data),
		Address: owner,
	}
	data, err = json.Marshal(caller2)
	if err != nil {
		t.Fatal(err)
	}
	// call paillier and encrypt plaintext2
	result, err = client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphertext2
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2 = resMap["ciphertext"]

	t.Logf("ciphertext1: %s\n", ciphertext1)
	t.Logf("ciphertext2: %s\n", ciphertext2)
}

func TestDec(t *testing.T) {
	decData := map[string]string{
		"ciphertext": ciphertext1,
		"publicKey":  pubkey,
		"prvkeyPath": path,
		"password":   password,
	}
	data, err := json.Marshal(decData)
	if err != nil {
		t.Fatal(err)
	}
	caller := &FuncCaller{
		Method:  "PaillierDec",
		Args:    string(data),
		Address: owner,
	}
	data, err = json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call paillier and decrypt testdata
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get plaintext
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	plain := resMap["plaintext"]
	t.Logf("decrypted ciphertext1: %s\n", plain)
}

func TestMul(t *testing.T) {
	ecdsaPrvkey := getPrivateKey(t)
	var err error
	commitment1, err = Commit(ecdsaPrvkey, ciphertext1, user)
	if err != nil {
		t.Fatal(err)
	}
	commitment2, err = Commit(ecdsaPrvkey, ciphertext2, user)
	if err != nil {
		t.Fatal(err)
	}
	mulData := map[string]string{
		"publicKey":   pubkey,
		"ciphertext1": ciphertext1,
		"commitment1": commitment1,
		"ciphertext2": ciphertext2,
		"commitment2": commitment2,
	}
	data, err := json.Marshal(mulData)
	if err != nil {
		t.Fatal(err)
	}
	caller := &FuncCaller{
		Method:  "PaillierMul",
		Args:    string(data),
		Address: user,
	}
	data, err = json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call paillier and multiply ciphertext
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphetext
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}

	cipherMul := resMap["ciphertext"]
	t.Logf("multiplication of two ciphertexts: %s\n", cipherMul)
	mulRes, err := PaillierDec(cipherMul, prvkey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decrypted cipherMul: %s\n", mulRes.String())
}

func TestExp(t *testing.T) {
	expData := map[string]string{
		"publicKey":  pubkey,
		"ciphertext": ciphertext1,
		"commitment": commitment1,
		"scalar":     strconv.Itoa(scalar),
	}
	data, err := json.Marshal(expData)
	if err != nil {
		t.Fatal(err)
	}
	caller := &FuncCaller{
		Method:  "PaillierExp",
		Args:    string(data),
		Address: user,
	}
	data, err = json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}

	// call paillier and multiply ciphertext
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphetext
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}

	cipherExp := resMap["ciphertext"]
	t.Logf("exponentiation of ciphertext1 and %d: %s\n", scalar, cipherExp)
	expRes, err := PaillierDec(cipherExp, prvkey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("decrypted cipherExp: %s\n", expRes.String())
}

func TestKeyDestroy(t *testing.T) {
	err, isRemoved := DestroyPrvKey(path, "654321", pubkey)
	if err == nil || isRemoved == true {
		t.Fatal("not supposed to destroy the private key")
	}

	err, isRemoved = DestroyPrvKey(path, password, pubkey)
	if err != nil {
		t.Fatal(err)
	}
	if isRemoved == false {
		t.Fatal("failed to destroy the private key")
	}
	t.Logf("private key destroyed")
}
