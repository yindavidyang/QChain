package main

import (
	"log"
	"github.com/Nik-U/pbc"
	"time"
	"crypto/sha256"
)

const (
	address   = "127.0.0.1"
	startPort = 2000

	numPeers  = 10
	numRounds = 10
	bf        = 2
	// increase epoch size if the program crashes or verification fails
	epoch      = time.Millisecond * 100
	dataToSign = "Gossip BLS UDP BFT test data"
)

var (
	finished         = make(chan bool)
	numSend, numRecv int64
	pubKeys          []*pbc.Element
)

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(peers []Peer) {
	for i := 0; i < numPeers; i++ {
		if ok := peers[i].VerifyPubKeySig(); !ok {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}
}

func main() {
	bls := &BLS{}
	bls.Init()

	peers := make([]Peer, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i].Init(uint32(i), bls)
	}
	verifyPubKeys(peers)

	pubKeys = make([]*pbc.Element, numPeers)
	for i := 0; i < numPeers; i++ {
		pubKeys[i] = peers[i].PubKey
	}

	finished = make(chan bool)

	proposerID := uint32(0)
	peers[proposerID].state = StatePreprepared
	h := sha256.Sum256([]byte(dataToSign))
	peers[proposerID].hash = h[:]
	peers[proposerID].proposerID = proposerID
	peers[proposerID].proposerSig = peers[proposerID].SignHash()

	for i := 0; i < numPeers; i++ {
		go peers[i].Gossip()
	}
	for i := 0; i < numPeers; i++ {
		<-finished
	}

	log.Print("Number of messages sent: ", numSend)
	log.Print("Number of messages received: ", numRecv)

	for i :=0; i < numPeers; i++ {
		log.Print(peers[i].state, " ", peers[i].aggSig.counters)
	}
}
