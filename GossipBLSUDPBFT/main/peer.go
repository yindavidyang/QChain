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
	"sync"
)

type (
	Peer struct {
		id, state                          int
		aggSig                             AggSig
		PubKey, privKey, sig, PubKeySig, g *pbc.Element
		pairing                            *pbc.Pairing
		stateMutex                         sync.Mutex
	}
)

func (self *Peer) Send() {
	// Randomly choose bf peers to gossip

	for i := 0; i < bf; i++ {
		rcpt := rand.Int() % (numPeers - 1)
		if rcpt >= self.id {
			rcpt ++
		}

		atomic.AddInt64(&numSend, 1)
		self.stateMutex.Lock()
		msg := self.aggSig.Copy()
		self.stateMutex.Unlock()

		conn, err := net.Dial("udp", address + ":" + strconv.Itoa(startPort + rcpt))
		if err != nil {
			log.Panic("Error connecting to server: ", err)
		}
		conn.Write(msg.Bytes())
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
		msg := &AggSig{}
		msg.Init(self.pairing)
		msg.SetBytes(buffer[:n])
		self.updateState(msg)
	}
}

func (self *Peer) updateState(msg *AggSig) {
	var i int

	for i = 0; i < numPeers; i++ {
		if self.aggSig.counters[i] == 0 && msg.counters[i] != 0 {
			break
		}
	}
	if i == numPeers {
		return
	}

	h := sha256.Sum256([]byte(dataToSign))
	if ok := msg.Verify(self.pairing, self.g, h[:]); !ok {
		log.Panic("Invalid Message: ", msg)
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	self.aggSig.Aggregate(msg)
}

func (self *Peer) Gossip() {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
		time.Sleep(epoch)
	}

	finished <- true
}

func (self *Peer) Init(id int, pairing *pbc.Pairing, g *pbc.Element) {
	self.pairing = pairing
	self.g = g

	self.state = StateIdle

	self.id = id
	self.aggSig.Init(pairing)
	self.aggSig.counters[id] = 1

	self.privKey = pairing.NewZr().Rand()
	self.PubKey = pairing.NewG2().PowZn(g, self.privKey)
	self.PubKeySig = self.Sign(self.PubKey.Bytes())

	self.sig = self.Sign([]byte(dataToSign))
	self.aggSig.sig.Set(self.sig)
}

func (self *Peer) Sign(data []byte) *pbc.Element {
	h := sha256.Sum256(data)
	hash := self.pairing.NewG1().SetFromHash(h[:])
	return self.pairing.NewG1().PowZn(hash, self.privKey)
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
	h := sha256.Sum256([]byte(dataToSign))
	return self.aggSig.Verify(self.pairing, self.g, h[:])
}
