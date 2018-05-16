package main

import (
	"sync/atomic"
	"time"
	"math/rand"
	"github.com/Nik-U/pbc"
	"log"
	"net"
	"strconv"
	"sync"
	"crypto/sha256"
)

type (
	Peer struct {
		bls                    *BLS
		id, proposerID         uint32
		state                  int
		hash                   []byte
		aggSig, prevAggSig     *AggSig
		proposerSig, PubKeySig *pbc.Element
		PubKey, privKey        *pbc.Element
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
			ppMsg.Init(self.bls.pairing)
			copy(ppMsg.hash, self.hash)
			ppMsg.ProposerID = self.id
			ppMsg.ProposerSig.Set(self.proposerSig)
			data = ppMsg.Bytes()
		case StatePrepared:
			pMsg := &PrepareMsg{}
			pMsg.Init(self.bls.pairing)
			copy(pMsg.hash, self.hash)
			pMsg.ProposerID = self.proposerID
			pMsg.ProposerSig.Set(self.proposerSig)
			pMsg.aggSig = self.aggSig.Copy()
			data = pMsg.Bytes()
		case StateCommitted:
			cMsg := &CommitMsg{}
			cMsg.Init(self.bls.pairing)
			copy(cMsg.hash, self.hash)
			cMsg.CAggSig = self.aggSig.Copy()
			cMsg.PAggSig = self.prevAggSig.Copy()
			data = cMsg.Bytes()
		case StateFinal:
			fMsg := &FinalMsg{}
			fMsg.Init(self.bls.pairing)
			copy(fMsg.hash, self.hash)
			fMsg.CAggSig = self.aggSig.Copy()
			data = fMsg.Bytes()
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
		case MsgPreprepare:
			ppMsg := &PreprepareMsg{}
			ppMsg.Init(self.bls.pairing)
			ppMsg.SetBytes(buffer[:n])
			self.handlePreprepare(ppMsg)
		case MsgPrepare:
			pMsg := &PrepareMsg{}
			pMsg.Init(self.bls.pairing)
			pMsg.SetBytes(buffer[:n])
			self.handlePrepare(pMsg)
		case MsgCommit:
			cMsg := &CommitMsg{}
			cMsg.Init(self.bls.pairing)
			cMsg.SetBytes(buffer[:n])
			self.handleCommit(cMsg)
		case MsgFinal:
			fMsg := &FinalMsg{}
			fMsg.Init(self.bls.pairing)
			fMsg.SetBytes(buffer[:n])
			self.handleFinal(fMsg)
		}
	}
}

func (self *Peer) Gossip() {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
		time.Sleep(epoch)
	}

	finished <- true
}

func (self *Peer) Init(id uint32, bls *BLS) {
	self.bls = bls

	self.state = StateIdle
	self.id = id
	self.hash = make([]byte, sha256.Size)

	self.privKey, self.PubKey = bls.GenKey()
	self.PubKeySig = self.Sign(self.PubKey.Bytes())
}

func (self *Peer) InitAggSig() {
	self.aggSig = &AggSig{}
	self.aggSig.Init(self.bls.pairing)
	self.aggSig.counters[self.id] = 1
	if self.state == StateCommitted {
		self.aggSig.sig.Set(self.SignCommittedHash())
	} else {
		self.aggSig.sig.Set(self.SignHash())
	}
}

func (self *Peer) Sign(data []byte) *pbc.Element {
	return self.bls.SignBytes(data, self.privKey)
}

func (self *Peer) SignHash() *pbc.Element {
	return self.bls.SignHash(self.hash, self.privKey)
}

func (self *Peer) SignCommittedHash() *pbc.Element {
	text := string(self.hash) + TextC
	return self.bls.SignString(text, self.privKey)
}

func (self *Peer) Verify(data []byte, sig *pbc.Element) bool {
	return self.bls.VerifyBytes(data, sig, self.PubKey)
}

func (self *Peer) VerifyPubKeySig() bool {
	return self.Verify(self.PubKey.Bytes(), self.PubKeySig)
}
