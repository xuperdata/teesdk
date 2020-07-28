package paillier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
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
	commData, err := base64.RawStdEncoding.DecodeString(commitment)
	if err != nil {
		return false, fmt.Errorf("decode commitment error: %v", err)
	}
	hash := sha256.Sum256([]byte(cipher + user))

	x, y := elliptic.Unmarshal(curve, commData[:65])
	pub := &ecdsa.PublicKey{curve, x, y}
	sig := commData[65:]
	sigRS := new(ECDSASignature)
	_, err = asn1.Unmarshal(sig, sigRS)
	if err != nil {
		return false, fmt.Errorf("unmarshal signature error: %v", err)
	}
	return ecdsa.Verify(pub, hash[:], sigRS.R, sigRS.S), nil
}
