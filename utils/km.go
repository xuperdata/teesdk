package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
)

// load secret from file and decrypt using password
func ReadPrvKey(path string, password string) (string, error) {
	// read ciphertext from file
	ciphertext, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("import private key error: %v", err)
	}

	realKey := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(realKey[:])
	if err != nil {
		return "", fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	blockModeD := cipher.NewCBCDecrypter(block, realKey[:blockSize])
	prvkey := make([]byte, len(ciphertext))
	blockModeD.CryptBlocks(prvkey, ciphertext)

	prvkey, err = BytesPKCS5UnPadding(prvkey)
	if err != nil {
		return "", err
	}
	return string(prvkey), nil
}

func BytesPKCS5UnPadding(originalData []byte) ([]byte, error) {
	dataLength := len(originalData)
	unpadLength := int(originalData[dataLength-1])
	if dataLength <= unpadLength {
		return nil, fmt.Errorf("wrong password")
	}
	return originalData[:(dataLength - unpadLength)], nil
}

// encrypt secret using password and save ciphertext to file
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

