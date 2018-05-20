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
	Validator struct {
		bls                    *BLS
		id                     uint32
		blockID                uint32
		state                  int
		hash, prevHash         []byte
		aggSig, prevAggSig     *AggSig
		PubKeySig              *pbc.Element
		PubKey, privKey        *pbc.Element
		stateMutex             sync.Mutex
	}
)

func (self *Validator) Send() {
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
		case StatePrepared:
			pMsg := &PrepareMsg{}
			if self.blockID == 0 {
				data = pMsg.BytesFromData(self.blockID, self.hash, self.aggSig, self.aggSig)
			} else {
				data = pMsg.BytesFromData(self.blockID, self.hash, self.prevAggSig, self.aggSig)
			}
		case StateCommitted, StateFinal:
			cMsg := &CommitMsg{}
			data = cMsg.BytesFromData(self.blockID, self.hash, self.aggSig, self.prevAggSig)
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

func (self *Validator) Listen() {
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

func (self *Validator) Gossip() {
	go self.Listen()

	for i := 0; i < numRounds; i++ {
		go self.Send()
		time.Sleep(epoch)
	}

	finished <- true
}

func (self *Validator) Init(id uint32, bls *BLS) {
	self.bls = bls

	self.state = StateIdle
	self.id = id
	self.hash = make([]byte, sha256.Size)
	self.blockID = 0

	self.privKey, self.PubKey = bls.GenKey()
	self.PubKeySig = self.Sign(self.PubKey.Bytes())
}

func (self *Validator) InitAggSig() {
	self.aggSig = &AggSig{}
	self.aggSig.Init(self.bls)
	self.aggSig.counters[self.id] = 1
	if self.state == StateCommitted {
		self.aggSig.sig.Set(self.SignCommittedHash())
	} else {
		self.aggSig.sig.Set(self.SignHash())
	}
}

func (self *Validator) Sign(data []byte) *pbc.Element {
	return self.bls.SignBytes(data, self.privKey)
}

func (self *Validator) SignHash() *pbc.Element {
	return self.bls.SignHash(self.hash, self.privKey)
}

func (self *Validator) SignCommittedHash() *pbc.Element {
	text := string(self.hash) + CommitNounce
	return self.bls.SignString(text, self.privKey)
}

func (self *Validator) Verify(data []byte, sig *pbc.Element) bool {
	return self.bls.VerifyBytes(data, sig, self.PubKey)
}

func (self *Validator) VerifyPubKeySig() bool {
	return self.Verify(self.PubKey.Bytes(), self.PubKeySig)
}
