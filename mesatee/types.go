package mesatee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/xuperchain/crypto/core/account"
	"github.com/xuperdata/teesdk/utils"
)

type FuncCaller struct {
	Method    string `json:"method"`
	Args      string `json:"args"`
	Svn       uint32 `json:"svn"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func (k *FuncCaller) Sign(sk *ecdsa.PrivateKey) (*FuncCaller, error) {
	msg := k.Method + k.Args
	hash := sha256.Sum256([]byte(msg))
	sig, err := sk.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return k, err
	}
	pk := sk.PublicKey
	k.PublicKey = hex.EncodeToString(elliptic.Marshal(pk.Curve, pk.X, pk.Y))
	k.Signature = hex.EncodeToString(sig)
	return k, nil
}

type KMSCaller struct {
	Method    string `json:"method"`
	Kds       string `json:"kds"`
	Svn       uint32 `json:"svn"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func (k *KMSCaller) Sign(sk *ecdsa.PrivateKey) (*KMSCaller, error) {
	k.Timestamp = time.Now().Unix()
	msg := k.Method + k.Kds + fmt.Sprintf("%d%d", k.Svn, k.Timestamp)
	hash := sha256.Sum256([]byte(msg))
	sig, err := sk.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return k, err
	}
	k.Signature = hex.EncodeToString(sig)
	return k, nil
}

/*****************   manage bds with single admin   *****************/
// encrypt bds with password and save it to file
func SaveBds(bds, path, password string) error {
	err := utils.SavePrvKey(path, password, bds)
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
	bds, err := utils.ReadPrvKey(path, password)
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
		fmt.Printf("i: %d, res: %s\n", i, res)
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
