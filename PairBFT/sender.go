package PairBFT

import (
	"math/rand"
	"strconv"
	"net"
)

// Randomly choose another validator
func (val *Validator) chooseRcpt() uint32 {
	numVals := len(val.valAddrSet)
	rcpt := rand.Uint32() % uint32(numVals - 1)
	if rcpt >= val.id {
		rcpt ++
	}
	return rcpt
}

func (val *Validator) genMsgData(rcpt uint32) []byte {
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	var (
		data       []byte
		dummyPMsg  = &PrepareMsg{}
		dummyCMsg  = &CommitMsg{}
		dummyCPMsg = &CommitPrepareMsg{}
	)

	switch val.state {
	case StatePrepared:
		val.log.Debug("xPrepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		if val.blockID == 0 {
			data = dummyPMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.aggSig)
		} else {
			data = dummyPMsg.BytesFromData(val.blockID, val.hash, val.prevAggSig, val.aggSig)
		}
		val.log.Debug("Prepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
	case StateCommitted, StateFinal:
		val.log.Debug("xCommit->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		data = dummyCMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.prevAggSig)
		val.log.Debug("Commit->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
	case StateCommitPrepared, StateFinalPrepared:
		val.log.Debug("xCommitPrepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
		if val.blockID == 0 {
			data = dummyCPMsg.BytesFromData(val.blockID, val.hash, val.aggSig, val.aggSig)
		} else {
			data = dummyCPMsg.BytesFromData(val.blockID, val.hash, val.prevAggSig, val.aggSig)
		}
		val.log.Debug("CommitPrepare->", strconv.Itoa(int(rcpt)), "@", val.blockID, ":", val.aggSig.counters)
	}
	return data
}

func (val *Validator) sendData(rcpt uint32, data []byte) {
	conn, err := net.Dial("udp", val.valAddrSet[rcpt])
	if err != nil {
		val.log.Panic("Error connecting to server: ", err)
	}
	conn.Write(data)
	conn.Close()
}

func (val *Validator) Send() {
	val.stateMutex.Lock()
	state := val.state
	val.stateMutex.Unlock()

	if state == StateIdle {
		return
	}

	for i := 0; i < val.branchFactor; i++ {
		rcpt := val.chooseRcpt()
		data := val.genMsgData(rcpt)
		val.sendData(rcpt, data)
	}
}
