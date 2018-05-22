package main

import (
	"bytes"
)

func (val *Validator) checkHashMismatch(msg *Msg) bool {
	return val.state != StateIdle && val.blockID == msg.blockID && bytes.Compare(val.hash, msg.hash) != 0
}

func (val *Validator) handlePrepare(msg *PrepareMsg) {
	// It is possible to lock this mutex later, when we start to modify the validator states
	// We lock it here for simplicity
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockID > msg.blockID {
		msgObsolete = true
	}
	if val.blockID == msg.blockID && (val.state == StateFinal || val.state == StateCommitted) {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockID > val.blockID+1 || (val.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented: ", msg.blockID, " ", val.blockID)
		// Todo: send sync request to the message sender
	}

	if val.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle {
		// If the validator is not idle, msg.cPairer is always given a value
		// if the validator is idle, then the message must be about block 0 (otherwise not implemented).
		// For block 0, we don't check CSig, so we don't need cPairer anyway.
		if msg.blockID == val.blockID {
			msg.pPairer = val.pPairer
			msg.cPairer = val.prevPairer
		} else { // msg.blockID = val.blockID+1, otherwise not implemented
			msg.cPairer = val.cPairer
		}
	}
	if msg.pPairer == nil {
		msg.pPairer = val.bls.PreprocessHash(msg.hash)
	}

	if !msg.Verify(val.bls) {
		val.logMessageVerificationFailure(&msg.Msg)
		log.Panic("Message verification failed.")
		return
	}

	if msg.blockID > val.blockID && val.state != StateFinal {
		val.aggSig = msg.CSig
		val.finalizeBlock()
	}

	if val.state == StateIdle || msg.blockID > val.blockID {
		val.prepareBlock(msg.blockID, msg.hash, msg.PSig, msg.CSig)
	} else { // StatePrepared
		val.aggSig.Aggregate(msg.PSig)
	}

	if val.aggSig.ReachQuorum() {
		val.commitBlock(val.blockID, nil, nil, val.aggSig)
	}
}

func (val *Validator) handleCommit(msg *CommitMsg) {
	// It is possible to lock this mutex later, when we start to modify the validator states
	// We lock it here for simplicity
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockID > msg.blockID {
		msgObsolete = true
	}
	if val.blockID == msg.blockID && val.state == StateFinal {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockID > val.blockID+1 || (val.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	if msg.blockID > val.blockID && val.state != StateFinal {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender, to retrieve the aggregate signature
	}

	if val.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle && msg.blockID == val.blockID {
		msg.pPairer = val.pPairer
		msg.cPairer = val.cPairer
	}
	msg.Preprocess(val.bls)

	if !msg.Verify(val.bls) {
		val.logMessageVerificationFailure(&msg.Msg)
		log.Panic("Message verification failed.", msg)
		return
	}

	if val.state == StateIdle || msg.blockID > val.blockID {
		val.commitBlock(msg.blockID, msg.hash, msg.CSig, msg.PSig)
	} else if val.state == StatePrepared {
		val.commitBlock(val.blockID, nil, msg.CSig, msg.PSig)
	} else { // StateCommit
		val.aggSig.Aggregate(msg.CSig)
	}

	if val.aggSig.ReachQuorum() {
		val.finalizeBlock()
		if getProposerID(val.blockID+1) == val.id {
			val.proposeBlock(val.blockID + 1)
		}
	}
}

func (val *Validator) handleCommitPrepare(msg *CommitPrepareMsg) {
	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	msgObsolete := false
	if val.blockID > msg.blockID {
		msgObsolete = true
	}
	if val.blockID == msg.blockID && val.state == StateFinalPrepared {
		msgObsolete = true
	}
	if msgObsolete {
		return
	}

	if msg.blockID > val.blockID+1 || (val.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	if val.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if val.state != StateIdle {
		if msg.blockID == val.blockID {
			msg.pPairer = val.pPairer
			msg.cPairer = val.prevPairer
		} else { // msg.blockID = val.blockID+1
			msg.cPairer = val.pPairer
		}
	}
	msg.pPairer = val.bls.PreprocessHash(msg.hash)

	if !msg.Verify(val.bls) {
		val.logMessageVerificationFailure(&msg.Msg)
		log.Panic("Message verification failed.")
		return
	}

	if msg.blockID > val.blockID && val.state != StateFinalPrepared {
		val.aggSig = msg.CSig
		val.finalizePrevBlock()
	}

	if val.state == StateIdle || msg.blockID > val.blockID {
		val.commitPrepareBlock(msg.blockID, msg.hash, msg.PSig, msg.CSig)
	} else { // StatePrepared
		val.aggSig.Aggregate(msg.PSig)
	}

	if val.aggSig.ReachQuorum() {
		val.finalizePrevBlock()
		if getProposerID(val.blockID+1) == val.id {
			val.commitProposeBlock(val.blockID + 1)
		}
	}
}
