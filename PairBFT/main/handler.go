package main

import (
	"bytes"
	"crypto/sha256"
)

func (self *Validator) checkHashMismatch(msg *Msg) bool {
	return self.state != StateIdle && self.blockID == msg.blockID && bytes.Compare(self.hash, msg.hash) != 0
}

func (self *Validator) handlePrepare(msg *PrepareMsg) {
	msgObsolete := false
	if self.blockID > msg.blockID {
		msgObsolete = true
	}

	if self.blockID == msg.blockID && (self.state == StateFinal || self.state == StateCommitted) {
		msgObsolete = true
	}

	if msgObsolete {
		return
	}

	if msg.blockID > self.blockID+1 || (self.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented: ", msg.blockID, " ", self.blockID)
		// Todo: send sync request to the message sender
	}

	if self.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	prevHash := self.prevHash
	if msg.blockID > self.blockID { // msg.blockID = self.blockID+1
		prevHash = self.hash
	}
	if !msg.Verify(self.bls, prevHash) {
		self.logMessageVerificationFailure(&msg.Msg)
		log.Panic("Message verification failed.")
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if msg.blockID > self.blockID && self.state != StateFinal {
		self.aggSig = msg.CSig
		self.finalizeBlock()
	}

	if self.state == StateIdle || msg.blockID > self.blockID {
		self.prepareBlock(msg.blockID, msg.hash, msg.PSig, msg.CSig)
	} else { // StatePrepared
		self.aggSig.Aggregate(msg.PSig)
	}

	if self.aggSig.ReachQuorum() {
		self.state = StateCommitted
		self.prevAggSig = self.aggSig
		self.InitAggSig()
		self.log.Print("Committed@", self.blockID, ":", self.prevAggSig.counters)
	}

}

func (self *Validator) handleCommit(msg *CommitMsg) {
	if self.blockID > msg.blockID {
		return
	}

	if self.blockID == msg.blockID && self.state == StateFinal {
		return
	}

	if !msg.Verify(self.bls) {
		self.logMessageVerificationFailure(&msg.Msg)
		log.Panic("Message verification failed.", msg)
		return
	}

	if self.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if msg.blockID > self.blockID+1 || (self.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	if msg.blockID > self.blockID && self.state != StateFinal {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender, to retrieve the aggregate signature
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if self.state == StateIdle || msg.blockID > self.blockID {
		self.state = StateCommitted
		self.prevHash = self.hash
		self.hash = msg.hash
		self.blockID = msg.blockID
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig
	} else if self.state == StatePrepared {
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig
	} else { // StateCommit
		self.aggSig.Aggregate(msg.CSig)
	}

	if self.aggSig.ReachQuorum() {
		self.finalizeBlock()
		if getProposerID(self.blockID+1) == self.id {
			self.proposeBlock(self.blockID + 1)
		}
	}
}

func (self *Validator) handleCommitPrepare(msg *CommitPrepareMsg) {
	if self.blockID > msg.blockID || (self.blockID == msg.blockID && self.state == StateFinalPrepared) {
		return
	}

	if self.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if msg.blockID > self.blockID+1 || (self.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented.")
		// Todo: send sync request to the message sender
	}

	prevHash := self.prevHash
	if msg.blockID > self.blockID { // msg.blockID = self.blockID+1
		prevHash = self.hash
	}
	if !msg.Verify(self.bls, prevHash) {
		log.Panic("Message verification failed.", msg)
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if msg.blockID > self.blockID && self.state != StateFinal {
		self.finalizeBlock()
	}

	if self.state == StateIdle || msg.blockID > self.blockID {
		self.state = StateCommitted
		self.prevHash = self.hash
		self.hash = msg.hash
		self.blockID = msg.blockID
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig
	} else if self.state == StatePrepared {
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig
	} else { // StateCommit
		self.aggSig.Aggregate(msg.CSig)
	}

	if self.aggSig.ReachQuorum() {
		self.finalizeBlock()
		self.state = StateFinalPrepared
		if getProposerID(self.blockID+1) == self.id {
			self.state = StateCommittedPrepared
			self.blockID ++
			self.prevHash = self.hash
			dataToSign := make([]byte, LenHash*2)
			copy(dataToSign, self.hash)
			copy(dataToSign[LenHash:], getBlockHash(self.blockID))
			h := sha256.Sum256(dataToSign)
			self.hash = h[:]
			self.prevAggSig = self.aggSig
			self.InitAggSig()
		}
	}
}
