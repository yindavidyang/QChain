package main

import (
	"strconv"
	"crypto/sha256"
	"log"
)

func getProposerID(blockID uint32) uint32 {
	return blockID % numPeers
}

func getBlockHash(blockID uint32) []byte {
	dataToSign := BlockData + strconv.Itoa(int(blockID))
	h := sha256.Sum256([]byte(dataToSign))
	return h[:]
}

func (self *Validator) finalizeBlock() {
	log.Print("Peer ", self.id, " has finalized block ", self.blockID, ".")
}
