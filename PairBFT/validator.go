package PairBFT

import (
	"time"
	"github.com/Nik-U/pbc"
	"net"
	"sync"
	"github.com/sirupsen/logrus"
	"path/filepath"
	"strconv"
	"os"
)

type (
	Validator struct {
		bls                          *BLS
		useCommitPrepare             bool
		id                           int
		blockHeight                  uint64
		state                        int
		branchFactor                 int
		epochLen                     time.Duration
		hash                         []byte
		aggSig, prevAggSig           *AggSig
		stateMutex                   sync.Mutex
		pPairer, cPairer, prevPairer *pbc.Pairer

		PubKey, privKey *pbc.Element
		PubKeySig       *pbc.Element

		log *logrus.Logger

		valAddrSet   []string
		valPubKeySet []*pbc.Element

		debugEpochLimit int
		debugTerminated chan bool
	}
)

func (val *Validator) initLog() { // requires val.id
	val.log = logrus.New()
	val.log.SetLevel(logLevel)
	fileName, _ := filepath.Abs("log/validator" + strconv.Itoa(val.id) + ".log")

	if _, err := os.Stat(fileName); err == nil {
		os.Remove(fileName)
	}

	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		val.log.Out = file
	} else {
		val.log.Info("Failed to log to file, using default stdout")
	}
}

func (val *Validator) Init(id int, bls *BLS, bf int, epochLen time.Duration, useCommitPrepare bool) {
	val.debugTerminated = make(chan bool)

	val.bls = bls
	val.useCommitPrepare = useCommitPrepare
	val.id = id
	val.blockHeight = 0
	val.state = StateIdle
	val.branchFactor = bf
	val.epochLen = epochLen

	val.privKey, val.PubKey = bls.GenKey()
	h := getNoncedHash(val.PubKey.Bytes(), NoncePubKey)
	val.PubKeySig = val.bls.SignHash(h, val.privKey)

	val.initLog()

	val.log.Print("BLS params: ", bls.params)
	val.log.Print("BLS g: ", bls.g)
	val.log.Print("Public key: ", val.PubKey)
	val.log.Debug("Private key: ", val.privKey)
}

func (val *Validator) SetValSet(valAddrSet []string, valPubKeySet []*pbc.Element, valPubKeySig []*pbc.Element) {
	val.valAddrSet = valAddrSet
	val.valPubKeySet = valPubKeySet
	numVals := len(val.valAddrSet)
	for i := 0; i < numVals; i++ {
		h := getNoncedHash(valPubKeySet[i].Bytes(), NoncePubKey)
		val.bls.VerifyHash(h, valPubKeySig[i], valPubKeySet[i])
	}
}

func (val *Validator) Listen() {
	pc, err := net.ListenPacket("udp", val.valAddrSet[val.id])
	if err != nil {
		val.log.Panic("Error listening to UDP address: ", err)
	}
	defer pc.Close()

	buffer := make([]byte, MaxPacketSize)
	for stop := false; !stop; {
		pc.SetDeadline(time.Now().Add(val.epochLen))
		n, _, err := pc.ReadFrom(buffer)
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				val.log.Panic("Error reading UDP packet: ", err)
			}
		} else {
			val.handleMsgData(buffer[:n])
		}
		select {
		case stop = <-val.debugTerminated:
		default:
		}
	}
}

func (val *Validator) Start() {
	go val.Listen()

	for epoch := 0; val.debugEpochLimit != 0 && epoch < val.debugEpochLimit; epoch++ {
		go val.Send()
		time.Sleep(val.epochLen)
	}
	val.debugTerminated <- true
}

func (val *Validator) InitAggSig() {
	numVals := len(val.valAddrSet)
	val.aggSig = &AggSig{}
	val.aggSig.Init(val.bls, numVals)
	val.aggSig.counters[val.id] = 1

	nounce := NoncePrepare
	if val.useCommitPrepare {
		nounce = NonceCommitPrepare
	}
	if val.state == StateCommitted {
		nounce = NonceCommit
	}
	h := getNoncedHash(val.hash, nounce)
	val.aggSig.sig = val.bls.SignHash(h, val.privKey)
}

func (val *Validator) updateHash(hash []byte) {
	val.hash = hash
	if val.useCommitPrepare {
		val.prevPairer = val.pPairer
		val.pPairer = val.bls.PreprocessHash(getNoncedHash(hash, NonceCommitPrepare))
	} else {
		val.pPairer = val.bls.PreprocessHash(getNoncedHash(hash, NoncePrepare))
		val.prevPairer = val.cPairer
		cHash := getNoncedHash(hash, NonceCommit)
		val.cPairer = val.bls.PreprocessHash(cHash)
	}
}

func (val *Validator) proposeBlock(blockID uint64) {
	val.state = StatePrepared
	val.blockHeight = blockID
	h := getBlockHash(val.hash)
	val.updateHash(h)
	val.prevAggSig = val.aggSig
	val.InitAggSig()
	val.log.Print("Propose@", val.blockHeight, "#", val.hash)
}

func (val *Validator) prepareBlock(blockID uint64, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	val.state = StatePrepared
	val.blockHeight = blockID
	val.updateHash(hash)
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	val.aggSig.Aggregate(aggSig)
	val.log.Print("Prepared@", val.blockHeight, ":", val.aggSig.counters)
}

func (val *Validator) commitBlock(blockID uint64, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	if val.state == StateIdle || blockID != val.blockHeight {
		val.blockHeight = blockID
		val.updateHash(hash)
	}
	val.state = StateCommitted
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	if aggSig != nil {
		val.aggSig.Aggregate(aggSig)
	}
	val.log.Print("Committed@", val.blockHeight, ":", val.prevAggSig.counters)
}

func (val *Validator) finalizeBlock() {
	val.state = StateFinal
	val.log.Print("Finalized@", val.blockHeight, ":", val.aggSig.counters)
	// Todo: add block to local blockchain. Slash the proposer if that fails.
}

func (val *Validator) commitProposeBlock(blockID uint64) {
	val.state = StateCommitPrepared
	val.blockHeight = blockID
	h := getBlockHash(val.hash)
	val.updateHash(h)
	val.prevAggSig = val.aggSig
	val.InitAggSig()
	val.log.Print("CommitPropose@", val.blockHeight, "#", val.hash)
}

func (val *Validator) commitPrepareBlock(blockID uint64, hash []byte, aggSig *AggSig, prevAggSig *AggSig) {
	val.state = StateCommitPrepared
	val.blockHeight = blockID
	val.updateHash(hash)
	val.prevAggSig = prevAggSig
	val.InitAggSig()
	val.aggSig.Aggregate(aggSig)
	val.log.Print("CommitPrepared@", val.blockHeight, ":", val.aggSig.counters)
}

func (val *Validator) finalizePrevBlock() {
	val.state = StateFinalPrepared
	if val.blockHeight == 0 {
		return
	}
	val.log.Print("Finalized@", val.blockHeight-1, ":", val.aggSig.counters)
	// Todo: add block to local blockchain. Slash the proposer if that fails.
}

func (val *Validator) logMessageVerificationFailure(msg *Msg) {
	val.log.Print("Message verification failed.")
	val.log.Print("@", msg.blockHeight)
	val.log.Print("#", msg.hash)
	val.log.Print("P#", getNoncedHash(msg.hash, NoncePrepare))
	val.log.Print("C#", getNoncedHash(msg.hash, NonceCommit))
	val.log.Print("Self#", val.hash)
	val.log.Print("PSig:", msg.PSig.counters, "(", msg.PSig.sig, ")")
	val.log.Print("PSig sig pairing:", val.bls.PairSig(msg.PSig.sig))
	val.log.Print("PSig agg pubkey:", msg.PSig.computeAggKey(val.bls, val.valPubKeySet))
	val.log.Print("CSig:", msg.CSig.counters, "(", msg.CSig.sig, ")")
	val.log.Print("CSig sig pairing:", val.bls.PairSig(msg.CSig.sig))
	val.log.Print("CSig agg pubkey:", msg.CSig.computeAggKey(val.bls, val.valPubKeySet))
}
