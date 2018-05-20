package main

import (
	"log"
	"bytes"
)

func (self *Peer) handlePrepare(msg *PrepareMsg) {
	if !msg.Verify(self.bls) {
		log.Panic("Message verification failed.", msg)
		return
	}

	if self.state != StateIdle && bytes.Compare(self.hash, msg.hash) != 0 {
		log.Panic("Message mismatch: ", msg)
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
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig

	case StatePreprepared:
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig

	case StatePrepared:
		self.state = StateCommitted
		self.InitAggSig()
		self.aggSig.Aggregate(msg.CSig)
		self.prevAggSig = msg.PSig

	case StateCommitted:
		self.aggSig.Aggregate(msg.CSig)
		if self.aggSig.reachQuorum() {
			self.state = StateFinal
		}
	}
}
