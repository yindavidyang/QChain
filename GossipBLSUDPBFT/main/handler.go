package main

import (
	"log"
	"bytes"
)

func (self *Peer) handlePreprepare(msg *PreprepareMsg) {
	if (!msg.Verify(self.bls)) {
		log.Panic("Message verification failed: ", msg)
		return
	}

	if self.state != StateIdle {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	self.state = StatePrepared
	self.proposerID = msg.ProposerID
	self.proposerSig = self.bls.cloneSig(msg.ProposerSig)
	copy(self.hash, msg.hash)

	self.InitAggSig()
	self.aggSig.AggregateOne(msg.ProposerID, msg.ProposerSig)
}

func (self *Peer) handlePrepare(msg *PrepareMsg) {
	if !msg.Verify(self.bls) {
		log.Panic("Message verification failed.", msg)
		return
	}

	if self.state != StateIdle && !msg.VerifyMatch(self.proposerID, self.proposerSig, self.hash) {
		log.Panic("Message mismatch: ", msg, "\n", self.id, " ", self.proposerSig, " ", self.hash)
		return
	}

	if self.state == StateFinal || self.state == StateCommitted {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	switch self.state {
	case StateIdle:
		self.state = StatePrepared
		self.proposerID = msg.ProposerID
		self.proposerSig = self.bls.cloneSig(msg.ProposerSig)
		copy(self.hash, msg.hash)

		self.InitAggSig()
		self.aggSig.Aggregate(msg.aggSig)

	case StatePreprepared:
		self.state = StatePrepared
		self.aggSig = msg.aggSig.Copy()

	case StatePrepared:
		self.aggSig.Aggregate(msg.aggSig)
		if self.aggSig.reachQuorum() {
			self.state = StateCommitted
			self.prevAggSig = self.aggSig
			self.InitAggSig()
		}
	}
}

func (self *Peer) handleCommit(msg *CommitMsg) {
	if !msg.Verify(self.bls) {
		log.Panic("Message verification failed.", msg)
		return
	}

	if self.state != StateIdle && bytes.Compare(self.hash, msg.hash) != 0 {
		log.Panic("Message mismatch: ", msg)
		return
	}

	if self.state == StateFinal {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	switch self.state {
	case StateIdle:
		self.state = StateCommitted
		copy(self.hash, msg.hash)

		self.InitAggSig()
		self.aggSig.Aggregate(msg.CAggSig)
		self.prevAggSig = msg.PAggSig

	case StatePreprepared:
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CAggSig)
		self.prevAggSig = msg.PAggSig

	case StatePrepared:
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CAggSig)
		self.prevAggSig = msg.PAggSig

	case StateCommitted:
		self.aggSig.Aggregate(msg.CAggSig)
		if self.aggSig.reachQuorum() {
			self.state = StateFinal
		}
	}
}

func (self *Peer) handleFinal(msg *FinalMsg) {
	if !msg.Verify(self.bls) {
		log.Panic("Message verification failed.", msg)
		return
	}

	if self.state != StateIdle && bytes.Compare(self.hash, msg.hash) != 0 {
		log.Panic("Message mismatch: ", msg)
		return
	}

	if self.state == StateFinal {
		return
	}

	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()

	if self.state == StateIdle {
		copy(self.hash, msg.hash)
	}

	self.state = StateFinal
	self.aggSig = msg.CAggSig
}
