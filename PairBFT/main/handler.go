package main

import (
	"log"
	"bytes"
)

func (self *Validator) checkHashMismatch(msg *Msg) bool {
	return self.state != StateIdle && self.blockID == msg.blockID && bytes.Compare(self.hash, msg.hash) != 0
}

func (self *Validator) checkMsgObsolete(msg *Msg, isPrepareMsg bool) bool {
	if self.blockID > msg.blockID {
		return true
	}
	if self.blockID < msg.blockID {
		return false
	}
	if isPrepareMsg {
		return self.state == StateFinal || self.state == StateCommitted
	} else {
		return self.state == StateFinal
	}
}

func (self *Validator) handlePrepare(msg *PrepareMsg) {
	if self.checkMsgObsolete(&msg.Msg, true) {
		return
	}

	if self.checkHashMismatch(&msg.Msg) {
		log.Panic("Hash mismatch: ", msg)
		// Todo: slash all validators contained in the message
		return
	}

	if msg.blockID > self.blockID+1 || (self.state == StateIdle && msg.blockID > 0) {
		log.Panic("Not implemented: ", msg.blockID, " ", self.blockID)
		// Todo: send sync request to the message sender
	}

	if msg.blockID == self.blockID {
		if !msg.Verify(self.bls, self.prevHash) {
			log.Panic("Message verification failed.", msg)
			return
		}
	} else { // msg.blockID = self.blockID+1
		if !msg.Verify(self.bls, self.hash) {
			log.Panic("Message verification failed.", msg)
			return
		}
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if self.state == StateIdle || msg.blockID > self.blockID {
		if msg.blockID > self.blockID && self.state != StateFinal{
			self.finalizeBlock()
		}
		self.state = StatePrepared
		self.prevHash = self.hash
		self.hash = msg.hash
		self.blockID = msg.blockID
		self.InitAggSig()
		self.aggSig.Aggregate(msg.PSig)
		self.prevAggSig = msg.CSig
	} else { // StatePrepared
		self.aggSig.Aggregate(msg.PSig)
	}

	if self.aggSig.ReachQuorum() {
		self.state = StateCommitted
		self.prevAggSig = self.aggSig
		self.InitAggSig()
	}

}

func (self *Validator) handleCommit(msg *CommitMsg) {
	if self.checkMsgObsolete(&msg.Msg, false) {
		return
	}

	if !msg.Verify(self.bls) {
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

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if self.state == StateIdle || msg.blockID > self.blockID {
		if msg.blockID > self.blockID && self.state != StateFinal {
			self.finalizeBlock()
		}
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
		self.state = StateFinal
		self.finalizeBlock()
		if getProposerID(self.blockID+1) == self.id {
			self.state = StatePrepared
			self.blockID ++
			self.prevHash = self.hash
			self.hash = getBlockHash(self.blockID)
			self.prevAggSig = self.aggSig
			self.InitAggSig()
		}
	}
}
