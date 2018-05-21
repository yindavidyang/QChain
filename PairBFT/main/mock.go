package main

import (
	"strconv"
	"crypto/sha256"
)

const (
	BlockData    = "Gossip BLS UDP BFT pair method test data block *********"
	CommitNounce = "Commit Nounce"
)

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(vals []Validator) {
	for i := 0; i < numValidators; i++ {
		if !vals[i].VerifyPubKeySig() {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}
}

func getProposerID(blockID uint32) uint32 {
	return blockID % numValidators
}

func getBlockHash(blockID uint32) []byte {
	dataToSign := BlockData + strconv.Itoa(int(blockID))
	h := sha256.Sum256([]byte(dataToSign))
	return h[:]
}

func genValidatorAddresses() {
	for i := 0; i < numValidators; i++ {
		validatorAddresses[i] = address + ":" + strconv.Itoa(int(startPort+i))
	}
}

func getCommitedHash(hash []byte) []byte {
	dataToSign := make([]byte, LenHash+len(CommitNounce))
	copy(dataToSign, hash)
	copy(dataToSign[LenHash:], CommitNounce)
	h := sha256.Sum256(dataToSign)
	return h[:]
}
