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

		pPairer, cPairer, prevCPairer *pbc.Pairer
		cHash, prevCHash              []byte
	}
)

func (val *Validator) Send() {
	if val.state == StateIdle {
		return
	}

	var (
		data      []byte
		dummyPMsg = &PrepareMsg{}
		dummyCMsg = &CommitMsg{}
	)

	for i := 0; i < bf; i++ {
		// Randomly choose another validator
		rcpt := rand.Uint32() % (numValidators - 1)
		if rcpt >= val.id {
			rcpt ++
		}

		atomic.AddInt64(&numSend, 1)

		val.stateMutex.Lock()
		switch val.state {
		case StatePrepared:
			if val.blockID == 0 {
				data = dummyPMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.aggSig)
			} else {
				data = dummyPMsg.BytesFromData(val.blockID, val.hash, val.prevAggSig, val.aggSig)
			}
			val.log.Debug("Prepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		case StateCommitted, StateFinal:
			data = dummyCMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.prevAggSig)
			val.log.Debug("Commit->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		}
		val.stateMutex.Unlock()

		conn, err := net.Dial("udp", validatorAddresses[rcpt])
		if err != nil {
			log.Panic("Error connecting to server: ", err)
		}
		conn.Write(data)
		conn.Close()
	}
}

func (val *Validator) Listen() {
	pc, err := net.ListenPacket("udp", validatorAddresses[val.id])
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
			pMsg.Init(val.bls)
			pMsg.SetBytes(buffer[:n])
			val.handlePrepare(pMsg)
		case MsgTypeCommit:
			cMsg := &CommitMsg{}
			cMsg.Init(val.bls)
			cMsg.SetBytes(buffer[:n])
			val.handleCommit(cMsg)
		case MsgTypeCommitPrepare:
			cpMsg := &CommitPrepareMsg{}
			cpMsg.Init(val.bls)
			cpMsg.SetBytes(buffer[:n])
			val.handleCommitPrepare(cpMsg)
		}
	}
}

func (val *Validator) Gossip() {
	go val.Listen()

	for i := 0; i < numRounds; i++ {
		go val.Send()
		time.Sleep(epoch)
	}

	finished <- true
}

func (val *Validator) Init(id uint32, bls *BLS) {
	val.log = logrus.New()
	val.log.SetLevel(logLevel)
	fileName, _ := filepath.Abs("log/validator" + strconv.Itoa(int(id)) + ".log")

	if _, err := os.Stat(fileName); err == nil {
		os.Remove(fileName)
	}

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		val.log.Out = file
	} else {
		val.log.Info("Failed to log to file, using default stdout")
	}

	val.bls = bls

	val.state = StateIdle
	val.id = id
	val.hash = make([]byte, sha256.Size)
	val.blockID = 0

	val.privKey, val.PubKey = bls.GenKey()
	val.log.Print("BLS params: ", bls.params)
	val.log.Print("BLS g: ", bls.g)
	val.log.Print("Public key: ", val.PubKey)
	val.log.Debug("Private key: ", val.privKey)

	val.PubKeySig = val.Sign(val.PubKey.Bytes())
}

func (val *Validator) InitAggSig() {
	val.aggSig = &AggSig{}
	val.aggSig.Init(val.bls)
	val.aggSig.counters[val.id] = 1
	if val.state == StateCommitted {
		val.aggSig.sig.Set(val.SignCommittedHash())
	} else {
		val.aggSig.sig.Set(val.SignHash())
	}
}

func (val *Validator) Sign(data []byte) *pbc.Element {
	return val.bls.SignBytes(data, val.privKey)
}

func (val *Validator) SignHash() *pbc.Element {
	return val.bls.SignHash(val.hash, val.privKey)
}

func (val *Validator) SignCommittedHash() *pbc.Element {
	h := getCommitedHash(val.hash)
	return val.bls.SignHash(h, val.privKey)
}

func (val *Validator) Verify(data []byte, sig *pbc.Element) bool {
	return val.bls.VerifyBytes(data, sig, val.PubKey)
}

func (val *Validator) VerifyPubKeySig() bool {
	return val.Verify(val.PubKey.Bytes(), val.PubKeySig)
}

func (val *Validator) updateHash(hash []byte) {
	val.prevHash = val.hash
	val.prevCHash = val.cHash
	val.prevCPairer = val.cPairer

	val.hash = hash
	val.cHash = getCommitedHash(val.hash)
	val.pPairer = val.bls.PreprocessHash(val.hash)
	val.cPairer = val.bls.PreprocessHash(val.cHash)
}

func (val *Validator) proposeBlock(blockID uint32) {
	val.state = StatePrepared
	val.blockID = blockID
	h := getBlockHash(val.blockID)
	val.updateHash(h)
	val.prevAggSig = val.aggSig
	val.InitAggSig()
	val.log.Print("Propose@", val.blockID, "#", val.hash)
}

func (val *Validator) prepareBlock(blockID uint32, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	val.state = StatePrepared
	val.blockID = blockID
	val.updateHash(hash)
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	val.aggSig.Aggregate(aggSig)
	val.log.Print("Prepared@", val.blockID, ":", val.aggSig.counters)
}

func (val *Validator) commitBlock(blockID uint32, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	if val.state == StateIdle || blockID != val.blockID {
		val.blockID = blockID
		val.updateHash(hash)
	}
	val.state = StateCommitted
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	if aggSig != nil {
		val.aggSig.Aggregate(aggSig)
	}
	val.log.Print("Committed@", val.blockID, ":", val.prevAggSig.counters)
}

func (val *Validator) finalizeBlock() {
	val.state = StateFinal
	val.log.Print("Finalized@", val.blockID, ":", val.aggSig.counters)
	// Todo: add block to local blockchain. Slash the proposer if that fails.
}

func (val *Validator) logMessageVerificationFailure(msg *Msg) {
	val.log.Print("Message verification failed.")
	val.log.Print("@", msg.blockID)
	val.log.Print("#", msg.hash)
	val.log.Print("Self#", val.hash)
	val.log.Print("Self prev#", val.prevHash)
	val.log.Print("PSig:", msg.PSig.counters, "(", msg.PSig.sig, ")")
	val.log.Print("CSig:", msg.CSig.counters, "(", msg.CSig.sig, ")")
}
