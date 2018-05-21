package main

import (
	"strconv"
	"crypto/sha256"
)

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(peers []Validator) {
	for i := 0; i < numValidators; i++ {
		if !peers[i].VerifyPubKeySig() {
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
