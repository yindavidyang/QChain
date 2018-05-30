package PairBFT

import (
	"bytes"
)

func (val *Validator) handleMsgData(data []byte) {
	numVals := len(val.valAddrSet)
	msg := &Msg{}
	msg.Init(val.bls, numVals, MsgTypeUnknown)
	msg.SetBytes(data)

	switch msg.msgType {
	case MsgTypePrepare:
		val.handlePrepare(msg)
	case MsgTypeCommit:
		val.handleCommit(msg)
	case MsgTypeCommitPrepare:
		val.handleCommitPrepare(msg)
	}
}

func (val *Validator) checkHashMismatch(msg *Msg) bool {
	return val.state != StateIdle && val.blockHeight == msg.blockHeight && bytes.Compare(val.hash, msg.hash) != 0
}

func (val *Validator) handlePrepare(msg *Msg) {
	// It is possible to lock this mutex later, when we start to modify the validator states
	// We lock it here for simplicity
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockHeight > msg.blockHeight {
		msgObsolete = true
	}
	if val.blockHeight == msg.blockHeight && (val.state == StateFinal || val.state == StateCommitted) {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockHeight > val.blockHeight+1 {
		val.log.Panic("Not implemented: ", msg.blockHeight, " ", val.blockHeight)
		// Todo: send sync request to the message sender
		return
	}

	if val.checkHashMismatch(msg) {
		val.log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle {
		// If the validator is not idle, msg.cPairer is always given a value
		// if the validator is idle, then the message must be about block 0 (otherwise not implemented).
		// For block 0, we don't check CSig, so we don't need cPairer anyway.
		if msg.blockHeight == val.blockHeight {
			msg.pPairer = val.pPairer
			msg.cPairer = val.prevPairer
		} else { // msg.blockHeight = val.blockHeight+1, otherwise not implemented
			msg.cPairer = val.cPairer
		}
	}
	if msg.pPairer == nil {
		msg.pPairer = val.bls.PreprocessHash(getNoncedHash(msg.hash, NoncePrepare))
	}

	if !msg.Verify(val.bls, val.valPubKeySet) {
		val.logMessageVerificationFailure(msg)
		val.log.Panic("Message verification failed.")
		return
	}

	if msg.blockHeight > 1 && msg.blockHeight > val.blockHeight && val.state != StateFinal {
		val.aggSig = msg.CSig
		val.finalizeBlock()
	}

	if val.state == StateIdle || msg.blockHeight > val.blockHeight {
		val.prepareBlock(msg.blockHeight, msg.hash, msg.PSig, msg.CSig)
	} else { // StatePrepared
		val.aggSig.Aggregate(msg.PSig)
	}

	if val.aggSig.ReachQuorum() {
		val.commitBlock(val.blockHeight, nil, nil, val.aggSig)
	}
}

func (val *Validator) handleCommit(msg *Msg) {
	// It is possible to lock this mutex later, when we start to modify the validator states
	// We lock it here for simplicity
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockHeight > msg.blockHeight {
		msgObsolete = true
	}
	if val.blockHeight == msg.blockHeight && val.state == StateFinal {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockHeight > val.blockHeight+1 {
		val.log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	if msg.blockHeight > 1 && msg.blockHeight > val.blockHeight && val.state != StateFinal {
		val.log.Panic("Not implemented.")
		// Todo: send sync request to the message sender, to retrieve the aggregate signature
	}

	if val.checkHashMismatch(msg) {
		val.log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle && msg.blockHeight == val.blockHeight {
		msg.pPairer = val.pPairer
		msg.cPairer = val.cPairer
	}
	msg.Preprocess(val.bls, val.useCommitPrepare)

	if !msg.Verify(val.bls, val.valPubKeySet) {
		val.logMessageVerificationFailure(msg)
		val.log.Panic("Message verification failed.", msg)
		return
	}

	if val.state == StateIdle || msg.blockHeight > val.blockHeight {
		val.commitBlock(msg.blockHeight, msg.hash, msg.CSig, msg.PSig)
	} else if val.state == StatePrepared {
		val.commitBlock(val.blockHeight, nil, msg.CSig, msg.PSig)
	} else { // StateCommit
		val.aggSig.Aggregate(msg.CSig)
	}

	if val.aggSig.ReachQuorum() {
		val.finalizeBlock()
		numVals := len(val.valAddrSet)
		if getProposerID(val.blockHeight+1, numVals) == val.id {
			val.proposeBlock(val.blockHeight + 1)
		}
	}
}

func (val *Validator) handleCommitPrepare(msg *Msg) {
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockHeight > msg.blockHeight {
		msgObsolete = true
	}
	if val.blockHeight == msg.blockHeight && val.state == StateFinalPrepared {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockHeight > val.blockHeight+1 {
		val.peerHeight = msg.blockHeight
		val.log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	if val.checkHashMismatch(msg) {
		val.log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle {
		if msg.blockHeight == val.blockHeight {
			msg.pPairer = val.pPairer
			msg.cPairer = val.prevPairer
		} else { // msg.blockHeight = val.blockHeight+1
			msg.cPairer = val.pPairer
		}
	}
	if msg.pPairer == nil {
		msg.pPairer = val.bls.PreprocessHash(getNoncedHash(msg.hash, NonceCommitPrepare))
	}

	if !msg.Verify(val.bls, val.valPubKeySet) {
		val.logMessageVerificationFailure(msg)
		val.log.Panic("Message verification failed.")
		return
	}

	if msg.blockHeight > val.blockHeight && val.state != StateFinalPrepared {
		val.aggSig = msg.CSig
		val.finalizePrevBlock()
	}

	if val.state == StateIdle || msg.blockHeight > val.blockHeight {
		val.commitPrepareBlock(msg.blockHeight, msg.hash, msg.PSig, msg.CSig)
	} else { // StatePrepared
		val.aggSig.Aggregate(msg.PSig)
	}

	if val.aggSig.ReachQuorum() {
		val.finalizePrevBlock()
		numVals := len(val.valAddrSet)
		if getProposerID(val.blockHeight+1, numVals) == val.id {
			val.commitProposeBlock(val.blockHeight + 1)
		}
	}
}
