package main

import (
	"strconv"
	"crypto/sha256"
	"github.com/Nik-U/pbc"
)

const (
	BlockData    = "Start BLS UDP BFT pair method test data block *********"
)

func getProposerID(blockID uint32, numVals int) uint32 {
	return blockID % uint32(numVals)
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

func getBlockHash(blockID uint32) []byte {
	dataToSign := BlockData + strconv.Itoa(int(blockID))
	h := sha256.Sum256([]byte(dataToSign))
	return h[:]
}

func getNouncedHash(hash []byte, nounce string) []byte {
	dataToSign := make([]byte, LenHash+len(nounce))
	copy(dataToSign, hash)
	copy(dataToSign[LenHash:], nounce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}

func getPairedHash(blockID uint32) []byte{
	dataToSign := make([]byte, LenHash*2+len(NounceCommitPrepare))
	i := 0
	copy(dataToSign, getBlockHash(blockID))
	i += LenHash
	copy(dataToSign[i:], getBlockHash(blockID - 1))
	i += LenHash
	copy(dataToSign[i:], NounceCommitPrepare)
	h := sha256.Sum256(dataToSign)
	return h[:]
}

func genValidators(numVals int) []Validator {
	bls := &BLS{}
	bls.Init()

	validatorAddresses := genValidatorAddresses(numVals)

	vals := make([]Validator, numVals)
	for i := 0; i < numVals; i++ {
		vals[i].Init(uint32(i), bls)
	}

	pubKeys := make([]*pbc.Element, numVals)
	pubKeySigs := make([]*pbc.Element, numVals)
	for i := 0; i < numVals; i++ {
		pubKeys[i] = vals[i].PubKey
		pubKeySigs[i] = vals[i].PubKeySig
	}
	for i := 0; i < numVals; i++ {
		vals[i].SetValSet(validatorAddresses, pubKeys, pubKeySigs)
	}
	return vals
}
