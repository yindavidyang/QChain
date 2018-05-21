package main

import (
	"sync/atomic"
	"time"
	"math/rand"
	"github.com/Nik-U/pbc"
	"net"
	"strconv"
	"sync"
	"crypto/sha256"
	"github.com/sirupsen/logrus"
	"path/filepath"
	"os"
)

type (
	Validator struct {
		bls                *BLS
		id                 uint32
		blockID            uint32
		state              int
		hash, prevHash     []byte
		aggSig, prevAggSig *AggSig
		PubKeySig          *pbc.Element
		PubKey, privKey    *pbc.Element
		stateMutex         sync.Mutex
		log                *logrus.Logger
	}
)

func (self *Validator) Send() {
	if self.state == StateIdle {
		return
	}
	for i := 0; i < bf; i++ {

		// Randomly choose another peer
		rcpt := rand.Uint32() % (numValidators - 1)
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
			self.log.Debug("Prepare->", strconv.Itoa(int(rcpt)), "@", self.blockID, ":", self.aggSig.counters)
		case StateCommitted, StateFinal:
			cMsg := &CommitMsg{}
			data = cMsg.BytesFromData(self.blockID, self.hash, self.aggSig, self.prevAggSig)
			self.log.Debug("Commit->", strconv.Itoa(int(rcpt)), "@", self.blockID, ":", self.aggSig.counters)
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
		case MsgTypeCommitPrepare:
			cpMsg := &CommitPrepareMsg{}
			cpMsg.Init(self.bls)
			cpMsg.SetBytes(buffer[:n])
			self.handleCommitPrepare(cpMsg)
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
	self.log = logrus.New()
	self.log.SetLevel(logLevel)
	fileName, _ := filepath.Abs("log/validator" + strconv.Itoa(int(id)) + ".log")

	if _, err := os.Stat(fileName); err == nil {
		os.Remove(fileName)
	}

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		self.log.Out = file
	} else {
		self.log.Info("Failed to log to file, using default stdout")
	}

	self.bls = bls

	self.state = StateIdle
	self.id = id
	self.hash = make([]byte, sha256.Size)
	self.blockID = 0

	self.privKey, self.PubKey = bls.GenKey()
	self.log.Print("BLS params: ", bls.params)
	self.log.Print("BLS g: ", bls.g)
	self.log.Print("Public key: ", self.PubKey)
	self.log.Debug("Private key: ", self.privKey)

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

func (self *Validator) finalizeBlock() {
	self.state = StateFinal
	self.log.Print("Finalized@", self.blockID, ":", self.aggSig.counters)
	// Todo: verify the block. Slash the proposer if verification fails.
}

func (self *Validator) proposeBlock(blockID uint32) {
	self.state = StatePrepared
	self.blockID = blockID
	self.prevHash = self.hash
	self.hash = getBlockHash(self.blockID)
	self.prevAggSig = self.aggSig
	self.InitAggSig()
	self.log.Print("Propose@", self.blockID, "#", self.hash)
}

func (self *Validator) prepareBlock(blockID uint32, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	self.state = StatePrepared
	self.prevHash = self.hash
	self.hash = hash
	self.blockID = blockID
	self.InitAggSig()
	self.aggSig.Aggregate(aggSig)
	self.prevAggSig = prevAggSig
	self.log.Print("Prepared@", self.blockID, ":", self.aggSig.counters)
}

func (self *Validator) logMessageVerificationFailure(msg *Msg) {
	self.log.Print("Message verification failed.")
	self.log.Print("@", msg.blockID)
	self.log.Print("#", msg.hash)
	self.log.Print("Self#", self.hash)
	self.log.Print("Self prev#", self.prevHash)
	self.log.Print("PSig:", msg.PSig.counters, msg.PSig.sig)
	self.log.Print("CSig:", msg.CSig.counters, msg.CSig.sig)
}
