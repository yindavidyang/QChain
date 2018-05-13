package main

import (
	"sync/atomic"
	"time"
	"math/rand"
	"github.com/NIk-U/pbc"
	"crypto/sha256"
	"log"
	"net"
	"strconv"
)

func (self *Peer) Send() {
	for i := 0; i < bf; i++ {
		rcpt := rand.Int() % (numPeers - 1)
		if rcpt >= self.id {
			rcpt ++
		}

		atomic.AddInt64(&numSend, 1)
		self.stateMutex.Lock()
		msg := self.state.copy()
		self.stateMutex.Unlock()


		conn, err := net.Dial("udp", address + ":" + strconv.Itoa(startPort + rcpt))
		if err != nil {
			log.Panic("Error connecting to server: ", err)
		}
		conn.Write(msg.toBytes())
		conn.Close()
	}
}

func (self *Peer) Listen() {
	pc, err := net.ListenPacket("udp", address + ":" + strconv.Itoa(startPort + self.id))
	if err != nil {
		log.Panic("Error listening to address: ", err)
	}
	defer pc.Close()

	for {
		buffer := make([]byte, 1024)
		n, _, err := pc.ReadFrom(buffer)
		if err != nil {
			log.Panic("Error reading from client", err)
		}
		atomic.AddInt64(&numRecv, 1)
		msg := &message{}
		msg.counters = make([]int, numPeers)
		msg.aggSig = self.pairing.NewG1()
		msg.fromBytes(buffer[:n])
		self.updateState(msg)
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

	if ok := msg.verifyMessage(self.pairing, self.g); !ok {
		log.Panic("Invalid Message: ", msg)
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	self.state.aggSig.ThenMul(msg.aggSig)
	for i = 0; i < numPeers; i++ {
		self.state.counters[i] += msg.counters[i]
	}
}

func (self *Peer) Gossip() {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
		time.Sleep(100 * time.Millisecond)
	}

	finished <- true
}

func (self *Peer) Init(id int, pairing *pbc.Pairing, g *pbc.Element) {
	self.id = id
	self.num = rand.Int() % 10000
	self.state.counters = make([]int, numPeers)
	self.state.counters[id] = 1

	self.pairing = pairing
	self.g = g
	self.privKey = pairing.NewZr().Rand()
	self.PubKey = pairing.NewG2().PowZn(g, self.privKey)
	self.PubKeySig = self.Sign(self.PubKey.Bytes())

	self.sig = self.Sign([]byte(textToSign))
	self.state.aggSig = self.pairing.NewG2().Set(self.sig)
}

func (self *Peer) Sign(data []byte) *pbc.Element {
	h := sha256.Sum256(data)
	hash := self.pairing.NewG1().SetFromHash(h[:])
	return self.pairing.NewG2().PowZn(hash, self.privKey)
}

func (self *Peer) Verify(data []byte, sig *pbc.Element) bool {
	h := sha256.Sum256(data)
	hash := self.pairing.NewG1().SetFromHash(h[:])

	temp1 := self.pairing.NewGT().Pair(hash, self.PubKey)
	temp2 := self.pairing.NewGT().Pair(sig, self.g)

	return temp1.Equals(temp2)
}

func (self *Peer) VerifyPubKeySig() bool {
	return self.Verify(self.PubKey.Bytes(), self.PubKeySig)
}

func (self *Peer) VerifyState() bool {
	return self.state.verifyMessage(self.pairing, self.g)
}
