package main

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

func (val Validator) genMsgData(rcpt uint32) []byte {
	var (
		data       []byte
		dummyPMsg  = &PrepareMsg{}
		dummyCMsg  = &CommitMsg{}
		dummyCPMsg = &CommitPrepareMsg{}
	)
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
	return data
}

func (val *Validator) Send() {
	if val.state == StateIdle {
		return
	}

	for i := 0; i < val.branchFactor; i++ {
		rcpt := val.chooseRcpt()
		data := val.genMsgData(rcpt)
		conn, err := net.Dial("udp", val.valAddrSet[rcpt])
		if err != nil {
			val.log.Panic("Error connecting to server: ", err)
		}
		conn.Write(data)
		conn.Close()
	}
}
