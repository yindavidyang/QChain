package main

import (
	"log"
)

type (
	message struct {
		sum      int
		counters []int
	}

	Peer struct {
		num, id int
		state   message
	}
)

const (
	numPeers  = 10
	numRounds = 4
	bf        = 2
)

var (
	numSend, numRecv int64
	chans            []chan message
)

func main() {
	peers := make([]Peer, numPeers)
	for i := 0; i < numPeers; i++ {
		peers[i].Init(i)
	}

	finished := make(chan bool)

	chans = make([]chan message, numPeers)
	for i := 0; i < numPeers; i++ {
		chans[i] = make(chan message)
	}

	for i := 0; i < numPeers; i++ {
		go peers[i].Main(finished)
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
	}
}
