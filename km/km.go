/*
  This file includes functions for key management.
  Specifically, it includes bds management using secret sharing.
*/
package km

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"

	"github.com/xuperchain/crypto/core/account"
)

// encrypt secret using password and save ciphertext and mac to file
func SaveSecretToFile(path string, password string, serect string) error {
	// ciphertext = aesEnc(hash(pwd), secret)
	realKey := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(realKey[:])
	if err != nil {
		return fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	originalData := BytesPKCS5Padding([]byte(serect), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, realKey[:blockSize])
	ciphertext := make([]byte, len(originalData))
	blockMode.CryptBlocks(ciphertext, originalData)

	// mac = sha256(realKey||cipher)
	mac := sha256.Sum256(append(realKey[:], ciphertext...))

	err = ioutil.WriteFile(path, append(ciphertext, mac[:]...), 0666)
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

// load ciphertext from file, verify mac and decrypt ciphertext using password
func LoadSecretFromFile(path string, password string) (string, error) {
	// read ciphertext and mac from file
	cipherMac, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("import private key error: %v", err)
	}
	cipherLen := len(cipherMac) - 32
	ciphertext := cipherMac[:cipherLen]
	macOrig := cipherMac[cipherLen:]

	// verify mac
	realKey := sha256.Sum256([]byte(password))
	mac := sha256.Sum256(append(realKey[:], ciphertext...))
	if !reflect.DeepEqual(mac[:], macOrig) {
		return "", fmt.Errorf("secret integrity check failed")
	}

	block, err := aes.NewCipher(realKey[:])
	if err != nil {
		return "", fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	blockModeD := cipher.NewCBCDecrypter(block, realKey[:blockSize])
	secret := make([]byte, len(ciphertext))
	blockModeD.CryptBlocks(secret, ciphertext)

	secret, err = BytesPKCS5UnPadding(secret)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

func BytesPKCS5UnPadding(originalData []byte) ([]byte, error) {
	dataLength := len(originalData)
	unpadLength := int(originalData[dataLength-1])
	if dataLength <= unpadLength {
		return nil, fmt.Errorf("wrong password")
	}
	return originalData[:(dataLength - unpadLength)], nil
}

// remove secret file from disk, only owner can destroy the bds
func DestroySecret(path string, password string) (error, bool) {
	cipherMac, err := ioutil.ReadFile(path)
	if err != nil {
		return err, false
	}
	cipherLen := len(cipherMac) - 32
	ciphertext := cipherMac[:cipherLen]
	macOrig := cipherMac[cipherLen:]

	// verify mac
	realKey := sha256.Sum256([]byte(password))
	mac := sha256.Sum256(append(realKey[:], ciphertext...))
	if !reflect.DeepEqual(mac[:], macOrig) {
		return fmt.Errorf("not authorized to destroy secret file"), false
	}

	// remove file from disk
	err = os.Remove(path)
	if err != nil {
		return err, false
	}
	return nil, true
}

/*****************   manage bds with single admin   *****************/
// randomly generate a bds between [0, 2^len]
func GenBds(len int64) string {
	max := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(len), nil)
	bds, err := rand.Int(rand.Reader, max)
	for {
		if err == nil {
			break
		}
		bds, err = rand.Int(rand.Reader, max)
	}
	return bds.String()
}

// encrypt bds with password and save it to file
func SaveBds(bds, path, password string) error {
	err := SaveSecretToFile(path, password, bds)
	if err != nil {
		return err
	}
	return nil
}

// load bds from file and decrypt bds using password
func LoadBdsFromFile(path, password string) (string, error) {
	bds, err := LoadSecretFromFile(path, password)
	if err != nil {
		return "", err
	}
	return bds, nil
}

/*******  manage bds with multiple admins using secret sharing  *******/
// given secret bds, generate bds shares
func GenBdsShares(bds string, sharesNum, threshold int) ([]string, error) {
	return account.SplitPrivateKey(bds, sharesNum, threshold)
}

// retrieve bds from enough shares
func LoadBdsFromShares(shares []string) (string, error) {
	return account.RetrievePrivateKeyByShares(shares)
}

// generate shares with hmac for integrity verification
// shares[i] = share_i || hmac(prvkey, share_i)
func GenBdsSharesWithHmac(prvkey *ecdsa.PrivateKey, bds string, sharesNum, threshold int) ([]string, error) {
	shares, err := account.SplitPrivateKey(bds, sharesNum, threshold)
	if err != nil {
		return nil, err
	}
	for i:=0;i<len(shares); i++ {
		mac := hmac.New(sha256.New, prvkey.D.Bytes())
		mac.Write([]byte(shares[i]))
		res := hex.EncodeToString(mac.Sum(nil))
		shares[i] = shares[i] + res
	}
	return shares, nil
}

// recover bds from shares with hmac
// we need to verify hmac first, collect correct shares and discard wrong share
func LoadBdsFromSharesHmac(prvkey *ecdsa.PrivateKey, shares []string) (string, error) {
	var sharesCorrect []string
	for i:=0;i<len(shares);i++ {
		if VerifyShareHmac(prvkey, shares[i]) {
			shareLen := len(shares[i]) - 64
			sharesCorrect = append(sharesCorrect, shares[i][:shareLen])
		}
	}
	return account.RetrievePrivateKeyByShares(sharesCorrect)
}

// verify hmac of a bds share, return true if the share is correct
func VerifyShareHmac(prvkey *ecdsa.PrivateKey, share string) bool {
	shareReceived := share[:len(share)-64]
	macReceived := share[len(share)-64:]
	mac := hmac.New(sha256.New, prvkey.D.Bytes())
	mac.Write([]byte(shareReceived))
	res := hex.EncodeToString(mac.Sum(nil))
	return macReceived == res
}
