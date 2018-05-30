package PairBFT

import (
	"crypto/sha256"
)

func getBlockHash(blockData []byte, prevHash []byte) []byte {
	if prevHash == nil { // first block
		h := sha256.Sum256(blockData)
		return h[:]
	}
	lenBlockData := len(blockData)
	l := lenBlockData + LenHash
	b := make([]byte, l)
	i := 0
	copy(b[i:], blockData)
	i += lenBlockData
	copy(b[i:], prevHash)
	h := sha256.Sum256(b)
	return h[:]
}

func getNoncedHash(hash []byte, nonce string) []byte {
	dataToSign := make([]byte, LenHash+len(nonce))
	copy(dataToSign, hash)
	copy(dataToSign[LenHash:], nonce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}
