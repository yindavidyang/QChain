package main

import (
	"sync/atomic"
	"time"
	"math/rand"
)

func (self *Peer) Send() {
	for i := 0; i < bf; i++ {
		rcpt := rand.Int() % (numPeers - 1)
		if rcpt >= self.id {
			rcpt ++
		}

		atomic.AddInt64(&numSend, 1)
		chans[rcpt] <- self.state
	}
}

func (self *Peer) Listen() {
	for {
		select {
		case msg := <-chans[self.id]:
			atomic.AddInt64(&numRecv, 1)
			self.updateState(&msg)
		default:
		}
	}
}

func (self *Peer) updateState(msg *message) {
	var i int
	for i = 0; i < numPeers; i++ {
		if self.state.counters[i] == 0 && msg.counters[i] != 0 {
			break
		}
	}
	if i == numPeers {
		return
	}
	self.state.sum += msg.sum
	for i = 0; i < numPeers; i++ {
		self.state.counters[i] += msg.counters[i]
	}
}

func (self *Peer) Main(finished chan bool) {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
	}

	time.Sleep(1000 * time.Millisecond)
	finished <- true
}

func (self *Peer) Init(id int) {
	self.id = id
	self.num = rand.Int() % 10000
	self.state.sum = self.num
	self.state.counters = make([]int, numPeers)
	self.state.counters[id] = 1
}
