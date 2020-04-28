/*
  This is a test file for mesatee-core-standalone
*/
package teesdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const basePath = "/root/mesatee-core-standalone/release"
const publicDer = basePath + "/services/auditors/godzilla/godzilla.public.der"
const signSha256 = basePath + "/services/auditors/godzilla/godzilla.sign.sha256"
const enclaveInfoConfig  = basePath + "/services/enclave_info.toml"
const bds = "3132333435363738393031323334353637383930313233343536373839303132"
// kds_0 is the kds with maximum N, it is the first kds we use in practice
const kds_0 = "657a51afc67a979fceb8ec3ca71076d647d08a496d48613217bd3bdd8e8b3bef"

var teeClient = NewTEEClient("uid1", "token1", publicDer, signSha256, enclaveInfoConfig, 8082)

var (
	owner 		= "Rx3Cihj8SJgrYaPgPj1XpodfHxUQXUxKi"
	user 		= "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	// ciphertext=25, ciphertext2=12
	ciphertext  = ""
	ciphertext2 = ""
	commitment	= ""
	commitment2 = ""
	outputKey = "111"

	// test data is used for encryption and decryption
	testdata = map[string]string{
		"duan": "25",
		"bing": "12",
	}
	sum = "37"
)

// test trust computing, encrypt, decrypt, authorize and binary ops
func TestTF(t *testing.T) {
	// init key
	t.Log("TestTF")
	data , err := json.Marshal(KMSCaller{Method: "init", Svn: 0, Kds: kds_0})
	must(t, err)
	result, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log(result)

	testEncDec(t)
	testAuth(t)
	testBinaryOp(t)
}

// test TEE encryption and decryption
func testEncDec(t *testing.T) {
	data, err := json.Marshal(testdata)
	must(t, err)
	data, err  = json.Marshal(FuncCaller{
		Method:"encrypt",
		Args: string(data),
		Svn: 0,
		Address: owner,
		// TODO: pubkey and signature should be consistent with address
		PublicKey:"04ff1e7e37deb3f253f27a57a794c0e9a6bfc75c16600f3ebe0b5c6d1aa30028be065f5c1874b9fdbf344aca601ed3e270d270946b6302caa4455266fdfd337890",
		Signature:"3045022100babd4b72aa666c33b5c7d931d8dbeb4b69af044a482eae541fc7ea7b61757336022003ca6398653ae5b68f2c0e191f57ece77cfe597dcd69194f91d2dc1943a9a154",
	})
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
	data, err := json.Marshal(FuncCaller{
		Method: "decrypt",
		Args: result,
		Svn: 0,
		Address: owner,
		// TODO: pubkey and signature should be consistent with address
		PublicKey:"049b443621162252ecacc15a0c32dc19364b8a6f08c183f8a8e940ab054bac9f8b6881451871338ed4d3810e8bc71197afc791f817d72d3fa144383c553adb5155",
		Signature:"30450221009d6ef984d8ba2da442034d42faad1923ad925958246553ae248e3ffddcfcc38802205de19a0d3dfcc595bc3be75d017cdf362ccf4ee60fea36fdf55e729008dc8536",
	})
	if err != nil {
		t.Fatal(err)
	}
	// call tee to decrypt the encrypted result
	newPlainRaw := wrap_call_function(t, "xchaintf", string(data))

	// decrypted data is in base64 format, decoding required
	newPlain := map[string]string {}
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
		"to": user,
		"kind": "commitment",
	}
	data, err := json.Marshal(authData)
	must(t, err)
	data, err  = json.Marshal(FuncCaller{
		Method:"authorize",
		Args: string(data),
		Svn: 0,
		Address: owner,
		// TODO: pubkey and signature should be consistent with address
		PublicKey:"0441b1c1ca4167cea79229fb2c0382c1bfde616d010eba419b8b55dbd095f74e44565c79ce91676b08b3ccb309575a1b649aff3ed45a141b54df01351144f94103",
		Signature:"3046022100870a62d6ef9d3e1f77f2739cc7c047dbc0e459a9dd9bad21cc3adaecc63b21e00221008e8492418bcbf1b5e7668b535a96b54ecf0974ac1dcd391bd04b64618573eb65",
	})
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
		"to": user,
		"kind": "commitment",
	}
	data2, err := json.Marshal(authData2)
	must(t, err)
	data, err  = json.Marshal(FuncCaller{
		Method:"authorize",
		Args: string(data2),
		Svn: 0,
		Address: owner,
		// TODO: pubkey and signature should be consistent with address
		PublicKey:"04c1571f4a4030e3c64854f2f3b9ac115d439eea29f32a720787b8762bad7a849c65862bf3ee1cb7d41e123baac5cb10546f540f3bd0e68a8283ab04ad20770076",
		Signature:"30450221008dfb83bdf43fe47eaa3214c6d58e186ab000799248f13cf2e64524cf19a58d020220392d9ace320bff94c503beed48f8675f6408b7e45a196e1df5e6f9878c03fd4d",
	})
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
		"l": ciphertext,
		"r": ciphertext2,
		"o": outputKey,
		"user": user,
		"commitment": commitment,
		"commitment2": commitment2,
	}

	data, err := json.Marshal(opData)
	must(t, err)
	data, err  = json.Marshal(FuncCaller{
		Method:"add",
		Args: string(data),
		Svn: 0,
		Address: user,
		PublicKey: "",
		Signature: "",
	})
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
	data, err := json.Marshal(FuncCaller{
		Method: "decrypt",
		Args: result,
		Svn: 0,
		Address: user,
		// TODO: pubkey and signature should be consistent with address
		PublicKey:"04839466a5b80fcdfac7428738faeda29c328f217593708ada050aef1580ea215a7f2007e3924ec4039bf6b4bf36cfb23fca119add07e2dde46bc84f892dca5c13",
		Signature:"3044022053a28f05834f0ce0cde2ac37832bc0e3068b473dc1c26d01cb40c613902c3d6b02205900414362d3c9aa99e9f9769e482130fb91a2570803623940a8ddb15b0affe7",
	})
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
		funcname = runtime.FuncForPC(pc).Name()       // main.(*MyStruct).foo
		funcname = filepath.Ext(funcname)             // .foo
		funcname = strings.TrimPrefix(funcname, ".")  // foo

		filename = filepath.Base(filename)  // /full/path/basename.go => basename.go
	}
	if err != nil {
		t.Fatal(fmt.Sprintf("%s:%d:%s: %s\n", filename, line, funcname, err.Error()))
	}
}

// test key derivation
func TestKeyMint(t *testing.T) {
	data , err := json.Marshal(KMSCaller{Method: "init", Svn: 0, Kds: kds_0})
	must(t, err)
	t.Log(data)
	result, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log(result)

	current_svn64, err := strconv.ParseUint(result, 10, 32)
	must(t, err)
	current_svn := uint32(current_svn64)

	// get kds_0
	data, err = json.Marshal(KMSCaller{Method: "mint", Svn: 0, Kds: bds})
	must(t, err)
	result, err = teeClient.Submit("xchainkms", string(data))
	must(t, err)
	if result != kds_0 {
		t.Fatal("kds_0 derivates error")
	}
	t.Log("mint: kds0 = " + result)

	current_svn += 1
	// get kds_1
	data, err = json.Marshal(KMSCaller{Method: "mint", Svn: current_svn, Kds: bds})
	result2, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log("mint: kds1 = " + result2)

	// kds update kds_0 -> kds_1
	data, err = json.Marshal(KMSCaller{Method: "inc", Svn: current_svn, Kds: result2})
	must(t, err)
	result2, err = teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log("inc svn: " + result2)
}
