package paillier

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
)

var curve = elliptic.P256()

// ECDSASignature is the structure for marshall signature
type ECDSASignature struct {
	R, S *big.Int
}

func Commit(prvkey *ecdsa.PrivateKey, cipher, user string) (string, error) {
	msg := cipher + user
	hash := sha256.Sum256([]byte(msg))
	pk := prvkey.PublicKey
	pubkey := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	r, s, err := ecdsa.Sign(rand.Reader, prvkey, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign error: %v", err)
	}
	sigRS := ECDSASignature{r, s}
	sig, err := asn1.Marshal(sigRS)
	if err != nil {
		return "", fmt.Errorf("marshal signature error: %v", err)
	}

	commitment := make([]byte, 65+len(sig))
	copy(commitment[0:], pubkey)
	copy(commitment[65:], sig)
	return base64.RawStdEncoding.EncodeToString(commitment), nil
}

// authorization check
func CheckCommitment(cipher, user, commitment string) (bool, error) {
	commData,err := base64.RawStdEncoding.DecodeString(commitment)
	if err != nil {
		return false, fmt.Errorf("decode commitment error: %v", err)
	}
	hash := sha256.Sum256([]byte(cipher+user))

	x,y := elliptic.Unmarshal(curve, commData[:65])
	pub := &ecdsa.PublicKey{curve, x, y}
	sig := commData[65:]
	sigRS := new(ECDSASignature)
	_, err = asn1.Unmarshal(sig, sigRS)
	if err != nil {
		return false, fmt.Errorf("unmarshal signature error: %v", err)
	}
	return ecdsa.Verify(pub, hash[:], sigRS.R, sigRS.S), nil
}

// save private key to file
func ReadPrvKey(path string, password string) (string, error) {
	// read ciphertext from file
	ciphertext,err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("import private key error: %v", err)
	}

	realKey := sha256.Sum256([]byte(password))
	block,err := aes.NewCipher(realKey[:])
	if err != nil {
		return "", fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	blockModeD := cipher.NewCBCDecrypter(block, realKey[:blockSize])
	prvkey := make([]byte, len(ciphertext))
	blockModeD.CryptBlocks(prvkey, ciphertext)
	prvkey = BytesPKCS5UnPadding(prvkey)

	return string(prvkey), nil
}

func BytesPKCS5UnPadding(originalData []byte) []byte {
	dataLength := len(originalData)
	unpadLength := int(originalData[dataLength-1])
	return originalData[:(dataLength - unpadLength)]
}

// save private key to file
func SavePrvKey(path string, password string, prvkey string) error {
	// ciphertext = aesEnc(hash(pwd), prvkey)
	realKey := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(realKey[:])
	if err != nil {
		return fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	originalData := BytesPKCS5Padding([]byte(prvkey), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, realKey[:blockSize])
	ciphertext := make([]byte, len(originalData))
	blockMode.CryptBlocks(ciphertext, originalData)

	err = ioutil.WriteFile(path, ciphertext, 0666)
	if err != nil {
		return fmt.Errorf("Export private key file failed, the err is %v", err)
	}
	return nil
}

func BytesPKCS5Padding(cipherData []byte, blockSize int) []byte {
	padLength := blockSize - len(cipherData)%blockSize
	padData := bytes.Repeat([]byte{byte(padLength)}, padLength)
	return append(cipherData, padData...)
}
