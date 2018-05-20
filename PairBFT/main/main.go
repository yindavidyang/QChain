package main

import (
	"log"
	"github.com/Nik-U/pbc"
	"time"
)

const (
	address   = "127.0.0.1"
	startPort = 2000

	numPeers  = 10
	numRounds = 100
	bf        = 2
	// increase epoch size if the program crashes or verification fails
	epoch = time.Millisecond * 100

	BlockData = "Gossip BLS UDP BFT pair method test data block *********"
)

var (
	finished         = make(chan bool)
	numSend, numRecv int64
	pubKeys          []*pbc.Element
)

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(peers []Validator) {
	for i := 0; i < numPeers; i++ {
		if !peers[i].VerifyPubKeySig() {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}
}

func main() {
	bls := &BLS{}
	bls.Init()

	peers := make([]Validator, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i].Init(uint32(i), bls)
	}
	verifyPubKeys(peers)

	pubKeys = make([]*pbc.Element, numPeers)
	for i := 0; i < numPeers; i++ {
		pubKeys[i] = peers[i].PubKey
	}

	finished = make(chan bool)

	proposerID := getProposerID(0)
	peers[proposerID].state = StatePrepared
	peers[proposerID].blockID = 0
	peers[proposerID].hash = getBlockHash(0)
	peers[proposerID].InitAggSig()

	for i := 0; i < numPeers; i++ {
		go peers[i].Gossip()
	}
	for i := 0; i < numPeers; i++ {
		<-finished
	}

	log.Print("Number of messages sent: ", numSend)
	log.Print("Number of messages received: ", numRecv)

	for i := 0; i < numPeers; i++ {
		log.Print(peers[i].blockID, " ", peers[i].state, " ", peers[i].aggSig.counters)
	}
}
