package main

import (
	"sync/atomic"
	"time"
	"math/rand"
	"github.com/Nik-U/pbc"
	"crypto/sha256"
	"log"
	"net"
	"strconv"
	"sync"
	"bytes"
)

type (
	Peer struct {
		id, proposerID         uint32
		state                  int
		hash                   []byte
		aggSig, prevAggSig     AggSig
		g                      *pbc.Element
		proposerSig, PubKeySig *pbc.Element
		PubKey, privKey        *pbc.Element
		pairing                *pbc.Pairing
		stateMutex             sync.Mutex
	}
)

const (
	StateIdle        = iota
	StatePreprepared
	StatePrepared
	StateCommitted
	StateFinal
)

const (
	MaxPacketSize = 4096
)

func (self *Peer) Send() {
	if self.state == StateIdle {
		return
	}
	for i := 0; i < bf; i++ {

		// Randomly choose another peer
		rcpt := rand.Uint32() % (numPeers - 1)
		if rcpt >= self.id {
			rcpt ++
		}

		atomic.AddInt64(&numSend, 1)
		self.stateMutex.Lock()
		var (
			data []byte
		)
		switch self.state {
		case StatePreprepared:
			ppMsg := &PreprepareMsg{}
			ppMsg.Init(self.pairing)
			copy(ppMsg.hash, self.hash)
			ppMsg.ProposerID = self.id
			ppMsg.sig.Set(self.proposerSig)

			data = ppMsg.Bytes()
		case StatePrepared:
			pMsg := &PrepareMsg{}
			pMsg.Init(self.pairing)
			copy(pMsg.hash, self.hash)
			pMsg.ProposerID = self.proposerID
			pMsg.sig.Set(self.proposerSig)
			pMsg.aggSig = self.aggSig.Copy()

			data = pMsg.Bytes()
		}
		self.stateMutex.Unlock()

		conn, err := net.Dial("udp", address+":"+strconv.Itoa(int(startPort+rcpt)))
		if err != nil {
			log.Panic("Error connecting to server: ", err)
		}
		conn.Write(data)
		conn.Close()
	}
}

func (self *Peer) Listen() {
	pc, err := net.ListenPacket("udp", address+":"+strconv.Itoa(int(startPort+self.id)))
	if err != nil {
		log.Panic("Error listening to address: ", err)
	}
	defer pc.Close()

	for {
		buffer := make([]byte, MaxPacketSize)
		n, _, err := pc.ReadFrom(buffer)
		if err != nil {
			log.Panic("Error reading from client", err)
		}
		atomic.AddInt64(&numRecv, 1)

		switch buffer[0] {
		case MessagePP:
			ppMsg := &PreprepareMsg{}
			ppMsg.Init(self.pairing)
			ppMsg.SetBytes(buffer[:n])
			self.updateStatePP(ppMsg)
		case MessageP:
			pMsg := &PrepareMsg{}
			pMsg.Init(self.pairing)
			pMsg.SetBytes(buffer[:n])
			self.updateStateP(pMsg)
		}
	}
}

func (self *Peer) updateStatePP(msg *PreprepareMsg) {
	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	switch self.state {
	case StateIdle:
		if (!msg.Verify(self.pairing, self.g)) {
			log.Panic("Message verification failed.", msg)
		}

		self.state = StatePrepared
		self.proposerID = msg.ProposerID
		self.proposerSig = self.pairing.NewG1().Set(msg.sig)
		self.hash = make([]byte, len(msg.hash))
		copy(self.hash, msg.hash)
		self.aggSig.Init(self.pairing)
		self.aggSig.counters[self.id] = 1
		self.aggSig.sig = self.SignHash()
		self.aggSig.counters[msg.ProposerID] = 1
		self.aggSig.sig.ThenMul(msg.sig)

	case StatePreprepared:
		log.Panic("Impossible: proposer receives a Preprepare message.")
	}
}

func (self *Peer) updateStateP(msg *PrepareMsg) {
	if self.state == StateFinal || self.state == StateCommitted {
		return
	}

	if !msg.Verify(self.pairing, self.g) {
		log.Panic("Message verification failed.", msg)
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	switch self.state {
	case StateIdle:
		self.state = StatePrepared
		self.proposerID = msg.ProposerID
		self.proposerSig = self.pairing.NewG1().Set(msg.sig)
		self.hash = make([]byte, len(msg.hash))
		copy(self.hash, msg.hash)
		self.aggSig.Init(self.pairing)
		self.aggSig.counters[self.id] = 1
		self.aggSig.sig = self.SignHash()
		self.aggSig.Aggregate(msg.aggSig)

	case StatePreprepared:
		self.state = StatePrepared
		if self.proposerID != msg.ProposerID {
			log.Panic("Incorrect proposer ID in message: ", msg)
		}
		if !self.proposerSig.Equals(msg.sig) {
			log.Panic("Incorrect proposer signature in message: ", msg)
		}
		if bytes.Compare(self.hash, msg.hash) != 0 {
			log.Panic("Incorrect hash in message:", msg)
		}
		self.aggSig.Init(self.pairing)
		self.aggSig.counters[self.id] = 1
		self.aggSig.sig.Set(self.proposerSig)
		self.aggSig.Aggregate(msg.aggSig)

	case StatePrepared:
		self.state = StatePrepared
		if self.proposerID != msg.ProposerID {
			log.Panic("Incorrect proposer ID in message: ", msg)
		}
		if !self.proposerSig.Equals(msg.sig) {
			log.Panic("Incorrect proposer signature in message: ", msg)
		}
		if bytes.Compare(self.hash, msg.hash) != 0 {
			log.Panic("Incorrect hash in message:", msg)
		}
		self.aggSig.Aggregate(msg.aggSig)
	}
}

func (self *Peer) updateStateC(msg *CommitMsg) {
	if self.state == StateFinal {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if self.state == StateCommitted {
		// do aggregation. if reaches quorum, set state to final
	}
	self.state = StateCommitted
}

func (self *Peer) updateStateF(msg *FinalMsg) {
	if self.state == StateFinal {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	self.state = StateFinal
}

func (self *Peer) Gossip() {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
		time.Sleep(epoch)
	}

	finished <- true
}

func (self *Peer) Init(id uint32, pairing *pbc.Pairing, g *pbc.Element) {
	self.pairing = pairing
	self.g = g

	self.state = StateIdle
	self.id = id

	self.privKey = pairing.NewZr().Rand()
	self.PubKey = pairing.NewG2().PowZn(g, self.privKey)
	self.PubKeySig = self.Sign(self.PubKey.Bytes())
}

func (self *Peer) Sign(data []byte) *pbc.Element {
	h := sha256.Sum256(data)
	hash := self.pairing.NewG1().SetFromHash(h[:])
	return self.pairing.NewG1().PowZn(hash, self.privKey)
}

func (self *Peer) SignHash() *pbc.Element {
	h := self.pairing.NewG1().SetFromHash(self.hash)
	return self.pairing.NewG1().PowZn(h, self.privKey)
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
