package PairBFT

import (
	"math/rand"
	"strconv"
	"net"
)

// Randomly choose another validator
func (val *Validator) chooseRcpt() int {
	numVals := len(val.valAddrSet)
	// todo: replace math.rand with a secure random function
	rcpt := int(rand.Uint32()) % (numVals - 1)
	if rcpt >= val.id {
		rcpt ++
	}
	return rcpt
}

func (val *Validator) genMsgData(rcpt int) []byte {
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	var (
		data []byte
	)

	switch val.state {
	case StatePrepared:
		data = MsgBytesFromData(MsgTypePrepare, val.blockHeight, val.hash, val.prevAggSig, val.aggSig)
		val.log.Debug("Prepare->", strconv.Itoa(rcpt), "@", val.blockHeight, ":", val.aggSig.counters)
	case StateCommitted, StateFinal:
		data = MsgBytesFromData(MsgTypeCommit, val.blockHeight, val.hash, val.aggSig, val.prevAggSig)
		val.log.Debug("Commit->", strconv.Itoa(rcpt), "@", val.blockHeight, ":", val.aggSig.counters)
	case StateCommitPrepared, StateFinalPrepared:
		data = MsgBytesFromData(MsgTypeCommitPrepare, val.blockHeight, val.hash, val.prevAggSig, val.aggSig)
		val.log.Debug("CommitPrepare->", strconv.Itoa(rcpt), "@", val.blockHeight, ":", val.aggSig.counters)
	}
	return data
}

func (val *Validator) sendData(rcpt int, data []byte) {
	conn, err := net.Dial("udp", val.valAddrSet[rcpt])
	if err != nil {
		val.log.Panic("Error connecting to validator: ", err)
	}
	conn.Write(data)
	conn.Close()
}

func (val *Validator) Send() {
	for i := 0; i < val.branchFactor; i++ {
		rcpt := val.chooseRcpt()
		data := val.genMsgData(rcpt)
		if data != nil {
			val.sendData(rcpt, data)
		}
	}
}
