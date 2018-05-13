package main

import (
	"log"
	"github.com/NIk-U/pbc"
	"sync"
)

const (
	address   = "127.0.0.1"
	startPort = 2000

	numPeers   = 10
	numRounds  = 4
	bf         = 2
	textToSign = "Gossip BLS test message"
)

type (
	message struct {
		counters []int
		aggSig   *pbc.Element
	}

	Peer struct {
		num, id                            int
		state                              message
		PubKey, privKey, sig, PubKeySig, g *pbc.Element
		pairing                            *pbc.Pairing
		stateMutex                         sync.Mutex
	}
)

var (
	finished         = make(chan bool)
	numSend, numRecv int64
	pubKeys          []*pbc.Element
)

func main() {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	g := pairing.NewG2().Rand()

	peers := make([]Peer, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i].Init(i, pairing, g)
	}
	verifyPubKeys(peers)

	pubKeys = make([]*pbc.Element, numPeers)
	for i := 0; i < numPeers; i++ {
		pubKeys[i] = peers[i].PubKey
	}

	finished = make(chan bool)

	for i := 0; i < numPeers; i++ {
		go peers[i].Gossip()
	}
	for i := 0; i < numPeers; i++ {
		<-finished
	}

	log.Print("Number of messages sent: ", numSend)
	log.Print("Number of messages received: ", numRecv)
	verifyFinalStates(peers)
}
