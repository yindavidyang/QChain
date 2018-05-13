package main

import (
	"log"
)

func verifyFinalStates(peers []Peer) {
	for i := 0; i < numPeers; i++ {
		log.Print(peers[i])
		if ok := peers[i].VerifyState(); !ok {
			log.Panic("Aggregate signature verficiation failed for peer", i)
		}
	}
}

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(peers []Peer) {
	for i := 0; i < numPeers; i++ {
		if ok := peers[i].VerifyPubKeySig(); !ok {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}
}
