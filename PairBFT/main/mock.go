package main

import (
	"strconv"
	"crypto/sha256"
)

const (
	BlockData    = "Gossip BLS UDP BFT pair method test data block *********"
)

func getProposerID(blockID uint32) uint32 {
	return blockID % numValidators
}

func getBlockHash(blockID uint32) []byte {
	dataToSign := BlockData + strconv.Itoa(int(blockID))
	h := sha256.Sum256([]byte(dataToSign))
	return h[:]
}

func genValidatorAddresses() []string {
	ret := make([]string, numValidators)
	address := "127.0.0.1"
	startPort := 2000
	for i := 0; i < numValidators; i++ {
		ret[i] = address + ":" + strconv.Itoa(int(startPort+i))
	}
	return ret
}

func getCommitedHash(hash []byte) []byte {
	dataToSign := make([]byte, LenHash+len(CommitNounce))
	copy(dataToSign, hash)
	copy(dataToSign[LenHash:], CommitNounce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}

func getPairedHash(blockID uint32) []byte{
	dataToSign := make([]byte, LenHash*2+len(CommitPrepareNounce))
	i := 0
	copy(dataToSign, getBlockHash(blockID))
	i += LenHash
	copy(dataToSign[i:], getBlockHash(blockID - 1))
	i += LenHash
	copy(dataToSign[i:], CommitPrepareNounce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}
