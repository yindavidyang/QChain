package main

import (
	"log"
	"github.com/NIk-U/pbc"
	"sync"
	"crypto/sha256"
)

type (
	message struct {
		sum      int // for debugging
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

const (
	numPeers   = 10
	numRounds  = 4
	bf         = 2
	textToSign = "Gossip BLS test message"
)

var (
	numSend, numRecv int64
	chans            []chan *message
	finished         chan bool
)

func main() {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	g := pairing.NewG2().Rand()

	peers := make([]Peer, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i].Init(i, pairing, g)

		// Defend against "related key attack"
		if ok := peers[i].Verify(peers[i].PubKey.Bytes(), peers[i].PubKeySig); !ok {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}

	finished = make(chan bool)

	chans = make([]chan *message, numPeers)
	for i := 0; i < numPeers; i++ {
		chans[i] = make(chan *message)
	}

	for i := 0; i < numPeers; i++ {
		go peers[i].Gossip()
	}
	for i := 0; i < numPeers; i++ {
		<-finished
	}

	log.Print("Number of messages sent: ", numSend)
	log.Print("Number of messages received: ", numRecv)
	for i := 0; i < numPeers; i++ {
		log.Print(peers[i])

		vSum := 0
		for j := 0; j < numPeers; j++ {
			vSum += peers[i].state.counters[j] * peers[j].num
		}
		if (vSum != peers[i].state.sum) {
			log.Panic("Sum verification failed for peer", i)
		}

		vPubKey := pairing.NewG2()
		tempKey := pairing.NewG2()
		tempNum := pairing.NewZr()
		for j := 0; j < numPeers; j++ {
			tempNum.SetInt32(int32(peers[i].state.counters[j]))
			tempKey.PowZn(peers[j].PubKey, tempNum)
			if j == 0 {
				vPubKey.Set(tempKey)
			} else {
				vPubKey.ThenMul(tempKey)
			}
		}

		h := sha256.Sum256([]byte(textToSign))
		hash := pairing.NewG1().SetFromHash(h[:])
		temp1 := pairing.NewGT().Pair(hash, vPubKey)
		temp2 := pairing.NewGT().Pair(peers[i].state.aggSig, g)

		if !temp1.Equals(temp2) {
			log.Panic("Aggregate signature verficiation failed for peer", i)
		}
	}
}
