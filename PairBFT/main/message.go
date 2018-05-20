package main

import (
	"crypto/sha256"
	"log"
)

const (
	MsgTypePrepare byte = iota
	MsgTypeCommit
)

const (
	TextC = "Commit"
)

type (
	Message struct {
		hash []byte
	}

	PrepareMsg struct {
		Message
		aggSig *AggSig
	}

	CommitMsg struct {
		Message
		CSig, PSig *AggSig
	}
)

func (self *Message) Len() int {
	return LenHash
}

func (self *Message) Init() {
	self.hash = make([]byte, LenHash)
}

func (self *PrepareMsg) Init(bls *BLS) {
	self.Message.Init()
	self.aggSig = &AggSig{}
	self.aggSig.Init(bls)
}

func (self *PrepareMsg) Len() int {
	return LenMsgType + LenHash + LenAggSig
}

func (self *PrepareMsg) Bytes() []byte {
	return self.BytesFromData(self.hash, self.aggSig)
}

func (self *PrepareMsg) BytesFromData(hash []byte, aggSig *AggSig) []byte {
	b := make([]byte, self.Len())
	i := 0
	b[i] = MsgTypePrepare
	i += LenMsgType
	copy(b[i:], hash)
	i += LenHash
	copy(b[i:], aggSig.Bytes())
	return b
}

func (self *PrepareMsg) SetBytes(b []byte) {
	i := LenMsgType
	copy(self.hash, b[i:])
	i += LenHash
	self.aggSig.SetBytes(b[i:])
}

func (self *PrepareMsg) Verify(bls *BLS) bool {
	if self.aggSig.counters[ProposerID] == 0 {
		log.Panic("Verification failed: ", self)
		return false
	}
	if !self.aggSig.Verify(bls, self.hash) {
		log.Panic("Verification failed: ", self)
		return false
	}
	return true
}

func (self *CommitMsg) Init(bls *BLS) {
	self.Message.Init()
	self.CSig = &AggSig{}
	self.CSig.Init(bls)
	self.PSig = &AggSig{}
	self.PSig.Init(bls)
}

func (self *CommitMsg) Len() int {
	return LenMsgType + self.Message.Len() + LenAggSig * 2
}

func (self *CommitMsg) Bytes() []byte {
	return self.BytesFromData(self.hash, self.CSig, self.PSig)
}

func (self *CommitMsg) BytesFromData(hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	i := 0
	b := make([]byte, self.Len())
	b[i] = MsgTypeCommit
	i += LenMsgType
	copy(b[i:], hash)
	i += LenHash
	copy(b[i:], cSig.Bytes())
	i += LenAggSig
	copy(b[i:], pSig.Bytes())
	return b
}

func (self *CommitMsg) SetBytes(b []byte) {
	i := LenMsgType
	copy(self.hash, b[i:])
	i += LenHash
	self.CSig.SetBytes(b[i:])
	i += LenAggSig
	self.PSig.SetBytes(b[i:])
}

func (self *CommitMsg) Verify(bls *BLS) bool {
	text := string(self.hash) + TextC
	h := sha256.Sum256([]byte(text))
	if !self.CSig.Verify(bls, h[:]) {
		return false
	}
	if !self.PSig.Verify(bls, self.hash) {
		return false
	}
	return self.PSig.reachQuorum()
}
