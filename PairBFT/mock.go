package PairBFT

import (
	"strconv"
	"crypto/sha256"
)

const (
	BlockData    = "Start BLS UDP BFT pair method test data block *********"
)

func getProposerID(blockID uint64, numVals int) uint32 {
	return uint32(blockID % uint64(numVals))
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

func getBlockHash(blockID uint64) []byte {
	dataToSign := BlockData + strconv.Itoa(int(blockID))
	h := sha256.Sum256([]byte(dataToSign))
	return h[:]
}

func getNoncedHash(hash []byte, nonce string) []byte {
	dataToSign := make([]byte, LenHash+len(nonce))
	copy(dataToSign, hash)
	copy(dataToSign[LenHash:], nonce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}

func getPairedHash(blockID uint64) []byte{
	dataToSign := make([]byte, LenHash*2+len(NonceCommitPrepare))
	i := 0
	copy(dataToSign, getBlockHash(blockID))
	i += LenHash
	copy(dataToSign[i:], getBlockHash(blockID - 1))
	i += LenHash
	copy(dataToSign[i:], NonceCommitPrepare)
	h := sha256.Sum256(dataToSign)
	return h[:]
}
