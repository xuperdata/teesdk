package paillier

import (
    "encoding/base64"
    "math/big"
    "strings"
)

type FuncCaller struct {
    Method string  `json:"method"`
    Args string     `json:"args"`
    Svn uint32   `json:"svn"`
    Address string `json:"address"`
    PublicKey string `json:"public_key"`
    Signature string `json:"signature"`
}

var one = big.NewInt(1)
var zero = big.NewInt(0)

// PrivateKey represents a Paillier private key
type PrivateKey struct {
    PublicKey
    P			*big.Int	// P and Q have same length
    Q			*big.Int
    Lambda		*big.Int	// Lambda=(P-1)(Q-1)
    Mu			*big.Int	// Mu=lambda^-1 (mod N)
}

// PublicKey represents a Paillier public key
type PublicKey struct {
    N        *big.Int	// N=P*Q
    G        *big.Int	// G=N+1
    NN		 *big.Int	// NN=N*N
}

// publickey/privatekey/ciphertext import and export
func PrivateToString(key *PrivateKey) string {
    p := base64.RawStdEncoding.EncodeToString(key.P.Bytes())
    q := base64.RawStdEncoding.EncodeToString(key.Q.Bytes())
    return p + "," + q
}

func PrivateFromString(data64 string) (*PrivateKey) {
    pq64 := strings.Split(data64, ",")
    p64,_ := base64.RawStdEncoding.DecodeString(pq64[0])
    q64,_ := base64.RawStdEncoding.DecodeString(pq64[1])
    p := new(big.Int).SetBytes(p64)
    q := new(big.Int).SetBytes(q64)
    n := new(big.Int).Mul(p,q)
    nn := new(big.Int).Mul(n,n)
    lambda := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
    mu := new(big.Int).ModInverse(lambda, n)
    g := new(big.Int).Add(n, one)
    return &PrivateKey{
        PublicKey: PublicKey{
            N:        n,
            G:        g,
            NN:       nn,
        },
        P: p,
        Q: q,
        Lambda: lambda,
        Mu: mu,
    }
}

func PublicToString(key *PublicKey) string {
    return base64.RawStdEncoding.EncodeToString(key.N.Bytes())
}

func PublicFromString(data64 string) (*PublicKey) {
    data,_ := base64.RawStdEncoding.DecodeString(data64)
    n := new(big.Int).SetBytes(data)
    g := new(big.Int).Add(n, one)
    nn := new(big.Int).Mul(n, n)
    return &PublicKey{
        N:  n,
        G:  g,
        NN: nn,
    }
}

func CipherToString(cipher *big.Int) string {
    return base64.RawStdEncoding.EncodeToString(cipher.Bytes())
}

func CipherFromString(cipher64 string) *big.Int {
    data,_ := base64.RawStdEncoding.DecodeString(cipher64)
    return new(big.Int).SetBytes(data)

}
