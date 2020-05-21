/*
  This is a test file for mesatee-core-standalone
*/
package mesatee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const basePath = "/root/mesatee-core-standalone/release"
const publicDer = basePath + "/services/auditors/godzilla/godzilla.public.der"
const signSha256 = basePath + "/services/auditors/godzilla/godzilla.sign.sha256"
const enclaveInfoConfig = basePath + "/services/enclave_info.toml"
const bds = "3132333435363738393031323334353637383930313233343536373839303132"

// kds_0 is the kds with maximum N, it is the first kds we use in practice
const kds_0 = "657a51afc67a979fceb8ec3ca71076d647d08a496d48613217bd3bdd8e8b3bef"

// 公私钥信息
const admin_pk = "040bf4ab3b2918fd62ac0f7a718c24f68e7f31c44d4f874580eab031619aeb0fe29471bf2a52ecf14cbcadc1d5d65188d25bb9a274f5dcf44e460e4e364c6b1c94"
const admin_sk_D = "ea07ded1156e152ef8615661581cf73495c33b431f3fbe372f57370dc80b375b"
const admin_sk_X = "0bf4ab3b2918fd62ac0f7a718c24f68e7f31c44d4f874580eab031619aeb0fe2"
const admin_sk_Y = "9471bf2a52ecf14cbcadc1d5d65188d25bb9a274f5dcf44e460e4e364c6b1c94"

func getPrivateKey() *ecdsa.PrivateKey {
	d, _ := big.NewInt(0).SetString(admin_sk_D, 16)
	x, _ := big.NewInt(0).SetString(admin_sk_X, 16)
	y, _ := big.NewInt(0).SetString(admin_sk_Y, 16)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}
}

var teeClient = NewTEEClient("uid1", "token1", publicDer, signSha256, enclaveInfoConfig, 8082)

var (
	owner = "Rx3Cihj8SJgrYaPgPj1XpodfHxUQXUxKi"
	user  = "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	// ciphertext=25, ciphertext2=12
	ciphertext  = ""
	ciphertext2 = ""
	commitment  = ""
	commitment2 = ""
	outputKey   = "111"

	// test data is used for encryption and decryption
	testdata = map[string]string{
		"duan": "25",
		"bing": "12",
	}
	sum = "37"
)

// test key derivation
func TestKeyMint(t *testing.T) {
	caller := &KMSCaller{Method: "init", Svn: 0, Kds: kds_0}
	caller, err := caller.Sign(getPrivateKey())
	must(t, err)
	data, err := json.Marshal(caller)
	must(t, err)
	t.Logf("%s", data)
	result, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log(result)

	current_svn64, err := strconv.ParseUint(result, 10, 32)
	must(t, err)
	current_svn := uint32(current_svn64)

	// get kds_0
	caller = &KMSCaller{Method: "mint", Svn: 0, Kds: bds}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	result, err = teeClient.Submit("xchainkms", string(data))
	must(t, err)
	if result != kds_0 {
		t.Fatal("kds_0 derivates error")
	}
	t.Log("mint: kds0 = " + result)

	current_svn += 1
	// get kds_1
	caller = &KMSCaller{Method: "mint", Svn: current_svn, Kds: bds}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	result2, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log("mint: kds1 = " + result2)

	// kds update kds_0 -> kds_1
	caller = &KMSCaller{Method: "inc", Svn: current_svn, Kds: result2}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	result2, err = teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log("inc svn: " + result2)

	// kds update kds_0 -> kds_1
	caller = &KMSCaller{Method: "dump", Svn: current_svn}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	result2, err = teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log("dump kds: " + result2)
}

// test trust computing, encrypt, decrypt, authorize and binary ops
func TestTF(t *testing.T) {
	t.Log("TestTF")
	testEncDec(t)
	testAuth(t)
	testBinaryOp(t)
}

// test TEE encryption and decryption
func testEncDec(t *testing.T) {
	data, err := json.Marshal(testdata)
	must(t, err)
	caller := &FuncCaller{
		Method:  "encrypt",
		Args:    string(data),
		Svn:     0,
		Address: owner,
	}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	// call tee and encrypt testdata
	result, err := teeClient.Submit("xchaintf", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get two ciphertexts
	var encMap map[string]string
	if err := json.Unmarshal([]byte(result), &encMap); err != nil {
		t.Fatal(err)
	}
	ciphertext = encMap["duan"]
	ciphertext2 = encMap["bing"]

	// check decryption
	check(t, result)
}

// check if decrypted msg is equal to the testdata plaintext
func check(t *testing.T, result string) {
	caller := &FuncCaller{
		Method:  "decrypt",
		Args:    result,
		Svn:     0,
		Address: owner,
	}
	caller , err := caller.Sign(getPrivateKey())
	must(t, err)
	data, err := json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call tee to decrypt the encrypted result
	newPlainRaw := wrap_call_function(t, "xchaintf", string(data))

	// decrypted data is in base64 format, decoding required
	newPlain := map[string]string{}
	for k, v := range newPlainRaw {
		byteData, _ := base64.StdEncoding.DecodeString(v)
		newPlain[k] = string(byteData)
	}
	// verify whether the decrypted msg is equal to the testdata plaintext
	if newPlain["duan"] != testdata["duan"] {
		t.Fatalf("wrong result, %s \n!= %s", newPlain["duan"], testdata["duan"])
	}
	if newPlain["bing"] != testdata["bing"] {
		t.Fatalf("wrong result, %s \n!= %s", newPlain["bing"], testdata["bing"])
	}
}

// wrap decryption method and return decrypted data
func wrap_call_function(t *testing.T, method string, args string) map[string]string {
	resultStr, err := teeClient.Submit(method, args)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(resultStr))

	var newPlain map[string]string
	if err := json.Unmarshal([]byte(resultStr), &newPlain); err != nil {
		t.Fatal(err)
	}
	return newPlain
}

// test authorize, get two commitments
func testAuth(t *testing.T) {
	// get first commitment
	authData := map[string]string{
		"ciphertext": ciphertext,
		"to":         user,
		"kind":       "commitment",
	}
	data, err := json.Marshal(authData)
	must(t, err)
	caller := &FuncCaller{
		Method:  "authorize",
		Args:    string(data),
		Svn:     0,
		Address: owner,
	}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller);
	must(t, err)
	// call tee and get commitment
	resultStr, err := teeClient.Submit("xchaintf", string(data))
	var authMap map[string]string
	if err := json.Unmarshal([]byte(resultStr), &authMap); err != nil {
		t.Fatal(err)
	}
	t.Log(resultStr)
	commitment = authMap["commitment"]

	// get commitment2
	authData2 := map[string]string{
		"ciphertext": ciphertext2,
		"to":         user,
		"kind":       "commitment",
	}
	data2, err := json.Marshal(authData2)
	must(t, err)
	caller = &FuncCaller{
		Method:  "authorize",
		Args:    string(data2),
		Svn:     0,
		Address: owner,
	}
	caller, err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	// call tee and get commitment2
	resultStr, err = teeClient.Submit("xchaintf", string(data))
	if err := json.Unmarshal([]byte(resultStr), &authMap); err != nil {
		t.Fatal(err)
	}
	t.Log(resultStr)
	commitment2 = authMap["commitment"]
}

// test binary operations, get addition of two ciphertexts
func testBinaryOp(t *testing.T) {
	opData := map[string]string{
		"l":           ciphertext,
		"r":           ciphertext2,
		"o":           outputKey,
		"commitment":  commitment,
		"commitment2": commitment2,
	}

	data, err := json.Marshal(opData)
	must(t, err)
	caller := &FuncCaller{
		Method:    "add",
		Args:      string(data),
		Svn:       0,
		Address:   user,
	}
	caller , err = caller.Sign(getPrivateKey())
	must(t, err)
	data, err = json.Marshal(caller)
	must(t, err)
	// call tee and add two ciphertexts
	// return {outputKey: enc(v)}, v="37"
	result, err := teeClient.Submit("xchaintf", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
	// check decryption
	checkAdd(t, result)
}

// check if result is equal to sum of two plain values
func checkAdd(t *testing.T, result string) {
	caller := &FuncCaller{
		Method:  "decrypt",
		Args:    result,
		Svn:     0,
		Address: user,
	}
	caller, err := caller.Sign(getPrivateKey())
	must(t, err)
	data, err := json.Marshal(caller)
	if err != nil {
		t.Fatal(err)
	}
	// call tee to decrypt the result
	newPlainRaw := wrap_call_function(t, "xchaintf", string(data))

	// decrypted data is in base64 format, decoding required
	byteData, _ := base64.StdEncoding.DecodeString(newPlainRaw[outputKey])
	// verify whether the decrypted value is equal to 25+12=37
	if string(byteData) != sum {
		t.Fatalf("wrong result, %s \n!= %s", string(byteData), sum)
	}
}

// handle error
func must(t *testing.T, err error) {
	pc, filename, line, ok := runtime.Caller(1)
	funcname := ""
	if ok {
		funcname = runtime.FuncForPC(pc).Name()      // main.(*MyStruct).foo
		funcname = filepath.Ext(funcname)            // .foo
		funcname = strings.TrimPrefix(funcname, ".") // foo

		filename = filepath.Base(filename) // /full/path/basename.go => basename.go
	}
	if err != nil {
		t.Fatal(fmt.Sprintf("%s:%d:%s: %s\n", filename, line, funcname, err.Error()))
	}
}

