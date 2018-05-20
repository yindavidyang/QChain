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
		id                     uint32
		state                  int
		hash                   []byte
		aggSig, prevAggSig     *AggSig
		PubKeySig              *pbc.Element
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
	if self.state == StatePreprepared {
		if self.id != ProposerID {
			log.Panic("Incorrect proposer: ", self.id)
		}
		h := sha256.Sum256([]byte(dataToSign))
		self.hash = h[:]
		self.InitAggSig()
		self.state = StatePrepared
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
		case StatePrepared:
			pMsg := &PrepareMsg{}
			data = pMsg.BytesFromData(self.hash, self.aggSig)
		case StateCommitted, StateFinal:
			cMsg := &CommitMsg{}
			data = cMsg.BytesFromData(self.hash, self.aggSig, self.prevAggSig)
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
		case MsgTypePrepare:
			pMsg := &PrepareMsg{}
			pMsg.Init(self.bls)
			pMsg.SetBytes(buffer[:n])
			self.handlePrepare(pMsg)
		case MsgTypeCommit:
			cMsg := &CommitMsg{}
			cMsg.Init(self.bls)
			cMsg.SetBytes(buffer[:n])
			self.handleCommit(cMsg)
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
	self.aggSig.Init(self.bls)
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
