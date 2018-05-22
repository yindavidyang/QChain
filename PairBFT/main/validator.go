package main

import (
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
		bls                          *BLS
		id                           uint32
		blockID                      uint32
		state                        int
		hash                         []byte
		aggSig, prevAggSig           *AggSig
		PubKeySig                    *pbc.Element
		PubKey, privKey              *pbc.Element
		stateMutex                   sync.Mutex
		log                          *logrus.Logger
		pPairer, cPairer, prevPairer *pbc.Pairer
		valAddrSet                   []string
		valPubKeySet                 []*pbc.Element
	}
)

func (val *Validator) Send() {
	if val.state == StateIdle {
		return
	}

	var (
		data       []byte
		dummyPMsg  = &PrepareMsg{}
		dummyCMsg  = &CommitMsg{}
		dummyCPMsg = &CommitPrepareMsg{}
	)

	for i := 0; i < branchFactor; i++ {
		// Randomly choose another validator
		rcpt := rand.Uint32() % (numVals - 1)
		if rcpt >= val.id {
			rcpt ++
		}

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
		case StateCommitPrepared, StateFinalPrepared:
			if val.blockID == 0 {
				data = dummyCPMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.aggSig)
			} else {
				data = dummyCPMsg.BytesFromData(val.blockID, val.hash, val.prevAggSig, val.aggSig)
			}
			val.log.Debug("CommitPrepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		}
		val.stateMutex.Unlock()

		conn, err := net.Dial("udp", val.valAddrSet[rcpt])
		if err != nil {
			val.log.Panic("Error connecting to server: ", err)
		}
		conn.Write(data)
		conn.Close()
	}
}

func (val *Validator) Listen() {
	pc, err := net.ListenPacket("udp", val.valAddrSet[val.id])
	if err != nil {
		val.log.Panic("Error listening to address: ", err)
	}
	defer pc.Close()

	for {
		buffer := make([]byte, MaxPacketSize)
		n, _, err := pc.ReadFrom(buffer)
		if err != nil {
			val.log.Panic("Error reading from client", err)
		}

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

	for i := 0; i < numEpochs; i++ {
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

func (val *Validator) SetValSet(valAddrSet []string, valPubKeySet []*pbc.Element, valPubKeySig []*pbc.Element) {
	val.valAddrSet = valAddrSet
	val.valPubKeySet = valPubKeySet
	for i := 0; i < numVals; i++ {
		val.bls.VerifyBytes(valPubKeySet[i].Bytes(), valPubKeySig[i], valPubKeySet[i])
	}
}

func (val *Validator) updateHash(hash []byte) {
	val.hash = hash
	val.pPairer = val.bls.PreprocessHash(val.hash)
	if val.state == StateCommitPrepared {
		val.prevPairer = val.pPairer
	} else {
		val.prevPairer = val.cPairer
		cHash := getCommitedHash(val.hash)
		val.cPairer = val.bls.PreprocessHash(cHash)
	}
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

func (val *Validator) commitProposeBlock(blockID uint32) {
	val.state = StateCommitPrepared
	val.blockID = blockID
	h := getPairedHash(val.blockID)
	val.updateHash(h)
	val.prevAggSig = val.aggSig
	val.InitAggSig()
	val.log.Print("CommitPropose@", val.blockID, "#", val.hash)
}

func (val *Validator) commitPrepareBlock(blockID uint32, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	val.state = StateCommitPrepared
	val.blockID = blockID
	val.updateHash(hash)
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	val.aggSig.Aggregate(aggSig)
	val.log.Print("CommitPrepared@", val.blockID, ":", val.aggSig.counters)
}

func (val *Validator) finalizePrevBlock() {
	val.state = StateFinalPrepared
	if val.blockID == 0 {
		return
	}
	val.log.Print("Finalized@", val.blockID-1, ":", val.aggSig.counters)
	// Todo: add block to local blockchain. Slash the proposer if that fails.
}

func (val *Validator) logMessageVerificationFailure(msg *Msg) {
	val.log.Print("Message verification failed.")
	val.log.Print("@", msg.blockID)
	val.log.Print("#", msg.hash)
	val.log.Print("Self#", val.hash)
	val.log.Print("PSig:", msg.PSig.counters, "(", msg.PSig.sig, ")")
	val.log.Print("CSig:", msg.CSig.counters, "(", msg.CSig.sig, ")")
}
