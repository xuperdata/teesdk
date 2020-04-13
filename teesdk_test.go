/*
  This is a test file for mesatee-core-standalone
*/
package teesdk

import (
	"encoding/json"
	"encoding/base64"
	"strconv"
	"runtime"
	"strings"
	"path/filepath"
	"fmt"
	"time"
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

// init test data duan->time.now, bing->20
// test data is used for encryption and decryption
var testdata map[string]string
func init() {
	println("init data")
	testdata = map[string]string{
		"duan": fmt.Sprintf("%d",time.Now().Unix()),
		"bing": "20",
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

// test TEE encryption and decryption
func TestTF(t *testing.T) {
	// init key
	t.Log("TestTF")
	data , err := json.Marshal(KMSCaller{Method: "init", Svn: 0, Kds: kds_0})
	must(t, err)
	result, err := teeClient.Submit("xchainkms", string(data))
	must(t, err)
	t.Log(result)

	data, err = json.Marshal(testdata)
	must(t, err)
	data, err  = json.Marshal(FuncCaller{Method:"store", Args: string(data), Svn: 0, Address: "cccc"})
	must(t, err)

	// call tee and encrypt testdata
	result, err = teeClient.Submit("xchaintf", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)
	// check decryption
	check(t, result)
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

// check if decrypted msg is equal to the testdata plaintext
func check(t *testing.T, result string) {
	data, err := json.Marshal(FuncCaller{
		Method: "debug",
		Args: result,
		Svn: 0,
		Address: "cccc",
	})
	if err != nil {
		t.Fatal(err)
	}
	// call tee to decrypt the encrypted result
	newPlainRaw := wrap_call_function(t, "xchaintf", string(data)) //模拟基于账本已有的数据进行计算
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
