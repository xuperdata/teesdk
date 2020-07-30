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

	"github.com/xuperchain/crypto/core/account"
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


/*****************   manage bds with single admin   *****************/
// encrypt bds with password and save it to file
func SaveBds(bds, path, password string) error {
	err := SavePrvKey(path, password, bds)
	if err != nil {
		return err
	}
	return nil
}

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

// load bds from file and decrypt bds using password
func LoadBdsFromFile(path, password string) (string, error) {
	bds, err := ReadPrvKey(path, password)
	if err != nil {
		return "", err
	}
	return bds, nil
}

/*******  manage bds with multiple admins using secret sharing  *******/
// given secret bds, generate bds pieces
func GenBdsPieces(bds string, piecesNum, threshold int) ([]string, error) {
	return account.SplitPrivateKey(bds, piecesNum, threshold)
}

// retrieve bds from enough pieces
func LoadBdsFromPieces(pieces []string) (string, error) {
	return account.RetrievePrivateKeyByShares(pieces)
}

// remove bds or bds piece from disk, only owner can destroy the bds
func DestroyBds(path string, r, s *big.Int, pubkey *ecdsa.PublicKey) (error, bool) {
	// check signature of admin
	hash := sha256.Sum256([]byte(path))
	isAuthorized := ecdsa.Verify(pubkey, hash[:], r, s)
	if isAuthorized != true {
		return fmt.Errorf("not authorized to destroy bds"), false
	}
	// remove bds file from disk
	err := os.Remove(path)
	if err != nil {
		return err, false
	}
	if _, err := os.Stat(path); os.IsExist(err) {
		return fmt.Errorf("failed to destroy bds"), false
	}
	return nil, true
}

// generate pieces with hmac for integrity verification
// pieces[i] = piece_i || hmac(prvkey, piece_i)
func GenBdsPiecesWithHmac(prvkey *ecdsa.PrivateKey, bds string, piecesNum, threshold int) ([]string, error) {
	pieces, err := account.SplitPrivateKey(bds, piecesNum, threshold)
	if err != nil {
		return nil, err
	}
	for i:=0;i<len(pieces); i++ {
		mac := hmac.New(sha256.New, prvkey.D.Bytes())
		mac.Write([]byte(pieces[i]))
		res := hex.EncodeToString(mac.Sum(nil))
		pieces[i] = pieces[i] + res
	}
	return pieces, nil
}

// recover bds from pieces with hmac
// we need to verify hmac first, collect correct pieces and discard wrong piece
func LoadBdsFromPiecesHmac(prvkey *ecdsa.PrivateKey, pieces []string) (string, error) {
	var piecesCorrect []string
	for i:=0;i<len(pieces);i++ {
		if VerifyPieceHmac(prvkey, pieces[i]) == true {
			pieceLen := len(pieces[i]) - 64
			piecesCorrect = append(piecesCorrect, pieces[i][:pieceLen])
		}
	}
	return account.RetrievePrivateKeyByShares(piecesCorrect)
}

// verify hmac of a bds piece, return true if the piece is correct
func VerifyPieceHmac(prvkey *ecdsa.PrivateKey, piece string) bool {
	pieceReceived := piece[:len(piece)-64]
	macReceived := piece[len(piece)-64:]
	mac := hmac.New(sha256.New, prvkey.D.Bytes())
	mac.Write([]byte(pieceReceived))
	res := hex.EncodeToString(mac.Sum(nil))
	return macReceived == res
}
