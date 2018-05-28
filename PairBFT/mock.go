package PairBFT

import (
	"strconv"
	"crypto/sha256"
)

const (
	BlockData    = "Start BLS UDP BFT pair method test data block *********"
)

func getProposerID(blockID uint64, numVals int) int {
	return int(blockID % uint64(numVals))
}

func genValidatorAddresses(numVals int) []string {
	ret := make([]string, numVals)
	address := "127.0.0.1"
	startPort := 2000
	for i := 0; i < numVals; i++ {
		ret[i] = address + ":" + strconv.Itoa(int(startPort+i))
	}
	return ret
}

// Block hash is a hash digest over the concatenation of:
// - block data
// - hash of previous block, except for the first block, where prevHash = nil
func getBlockHash(prevHash []byte) []byte {
	if prevHash == nil { // first block
		h := sha256.Sum256([]byte(BlockData))
		return h[:]
	}
	lenBlockData := len([]byte(BlockData))
	l := lenBlockData + LenHash
	b := make([]byte, l)
	i := 0
	copy(b[i:], []byte(BlockData))
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
