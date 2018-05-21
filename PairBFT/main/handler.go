package main

import (
	"bytes"
	"crypto/sha256"
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
		if msg.blockID == val.blockID {
			msg.pPairer = val.pPairer
			msg.cPairer = val.prevCPairer
		} else { // msg.blockID = val.blockID+1
			msg.cPairer = val.cPairer
		}
	}
	msg.Preprocess(val.bls)

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
	if val.blockID > msg.blockID || (val.blockID == msg.blockID && val.state == StateFinalPrepared) {
		return
	}

	if val.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if msg.blockID > val.blockID+1 || (val.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	prevHash := val.prevHash
	if msg.blockID > val.blockID { // msg.blockID = val.blockID+1
		prevHash = val.hash
	}
	if !msg.Verify(val.bls, prevHash) {
		log.Panic("Message verification failed.", msg)
		return
	}

	val.stateMutex.Lock()
	defer val.stateMutex.Unlock()

	if msg.blockID > val.blockID && val.state != StateFinal {
		val.finalizeBlock()
	}

	if val.state == StateIdle || msg.blockID > val.blockID {
		val.state = StateCommitted
		val.prevHash = val.hash
		val.hash = msg.hash
		val.blockID = msg.blockID
		val.InitAggSig()
		val.aggSig.Aggregate(msg.CSig)
		val.prevAggSig = msg.PSig
	} else if val.state == StatePrepared {
		val.state = StateCommitted
		val.InitAggSig()
		val.aggSig.Aggregate(msg.CSig)
		val.prevAggSig = msg.PSig
	} else { // StateCommit
		val.aggSig.Aggregate(msg.CSig)
	}

	if val.aggSig.ReachQuorum() {
		val.finalizeBlock()
		val.state = StateFinalPrepared
		if getProposerID(val.blockID+1) == val.id {
			val.state = StateCommittedPrepared
			val.blockID ++
			val.prevHash = val.hash
			dataToSign := make([]byte, LenHash*2)
			copy(dataToSign, val.hash)
			copy(dataToSign[LenHash:], getBlockHash(val.blockID))
			h := sha256.Sum256(dataToSign)
			val.hash = h[:]
			val.prevAggSig = val.aggSig
			val.InitAggSig()
		}
	}
}
