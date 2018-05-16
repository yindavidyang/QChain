package main

import (
	"github.com/Nik-U/pbc"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"bytes"
)

const (
	MsgPreprepare byte = iota
	MsgPrepare
	MsgCommit
	MsgFinal
)

const (
	TextC = "Commit"
)

type (
	Message struct {
		hash []byte
	}

	PreprepareMsg struct {
		Message
		ProposerID  uint32
		ProposerSig *pbc.Element
	}

	PrepareMsg struct {
		PreprepareMsg
		aggSig *AggSig
	}

	FinalMsg struct {
		Message
		CAggSig *AggSig
	}

	CommitMsg struct {
		FinalMsg
		PAggSig *AggSig
	}
)

func (self *Message) Len() int {
	return sha256.Size
}

func (self *Message) Init() {
	self.hash = make([]byte, self.Len())
}

func (self *PreprepareMsg) Init(pairing *pbc.Pairing) {
	self.Message.Init()
	self.ProposerSig = pairing.NewG1()
}

func (self *PreprepareMsg) Len() int {
	// 1 byte for message type, 4 bytes for proposer ID
	return 1 + self.Message.Len() + 4 + self.ProposerSig.BytesLen()
}

func (self *PreprepareMsg) Bytes() []byte {
	bytes := make([]byte, self.Len())
	bytes[0] = MsgPreprepare
	copy(bytes[1:], self.hash)
	binary.LittleEndian.PutUint32(bytes[1+self.Message.Len():], self.ProposerID)
	copy(bytes[1+self.Message.Len()+4:], self.ProposerSig.Bytes())
	return bytes
}

func (self *PreprepareMsg) SetBytes(bytes []byte) {
	copy(self.hash, bytes[1:])
	self.ProposerID = binary.LittleEndian.Uint32(bytes[1+self.Message.Len() : 1+self.Message.Len()+4])
	self.ProposerSig.SetBytes(bytes[1+self.Message.Len()+4:])
}

func (self *PreprepareMsg) Verify(bls *BLS) bool {
	return bls.VerifyHash(self.hash, self.ProposerSig, pubKeys[self.ProposerID])
}

func (self *PrepareMsg) Init(pairing *pbc.Pairing) {
	self.PreprepareMsg.Init(pairing)
	self.aggSig = &AggSig{}
	self.aggSig.Init(pairing)
}

func (self *PrepareMsg) Len() int {
	return self.PreprepareMsg.Len() + self.aggSig.Len()
}

func (self *PrepareMsg) Bytes() []byte {
	bytes := make([]byte, self.Len())
	copy(bytes[:], self.PreprepareMsg.Bytes())
	copy(bytes[self.PreprepareMsg.Len():], self.aggSig.Bytes())
	bytes[0] = MsgPrepare
	return bytes
}

func (self *PrepareMsg) SetBytes(bytes []byte) {
	self.PreprepareMsg.SetBytes(bytes[:self.PreprepareMsg.Len()])
	self.aggSig.SetBytes(bytes[self.PreprepareMsg.Len():])
}

func (self *PrepareMsg) Verify(bls *BLS) bool {
	if !self.PreprepareMsg.Verify(bls) {
		log.Panic("Verification failed: ", self)
		return false
	}
	if !self.aggSig.Verify(bls, self.hash) {
		log.Panic("Verification failed: ", self)
		return false
	}
	return true
}

func (self *PrepareMsg) VerifyMatch(id uint32, sig *pbc.Element, hash []byte) bool {
	return id == self.ProposerID && sig.Equals(self.ProposerSig) && bytes.Compare(hash, self.hash) == 0
}

func (self *FinalMsg) Init(pairing *pbc.Pairing) {
	self.Message.Init()
	self.CAggSig = &AggSig{}
	self.CAggSig.Init(pairing)
}

func (self *FinalMsg) Len() int {
	return 1 + self.Message.Len() + self.CAggSig.Len()
}

func (self *FinalMsg) Bytes() []byte {
	bytes := make([]byte, self.Len())
	bytes[0] = MsgFinal
	copy(bytes[1:], self.hash)
	copy(bytes[1+self.Message.Len():], self.CAggSig.Bytes())
	return bytes
}

func (self *FinalMsg) SetBytes(bytes []byte) {
	copy(self.hash, bytes[1:])
	self.CAggSig.SetBytes(bytes[1+self.Message.Len():])
}

func (self *FinalMsg) Verify(bls *BLS) bool {
	text := string(self.hash) + TextC
	h := sha256.Sum256([]byte(text))
	if !self.CAggSig.Verify(bls, h[:]) {
		return false
	}
	return self.CAggSig.reachQuorum()
}

func (self *CommitMsg) Init(pairing *pbc.Pairing) {
	self.FinalMsg.Init(pairing)
	self.PAggSig = &AggSig{}
	self.PAggSig.Init(pairing)
}

func (self *CommitMsg) Len() int {
	return self.FinalMsg.Len() + self.PAggSig.Len()
}

func (self *CommitMsg) Bytes() []byte {
	bytes := make([]byte, self.Len())
	copy(bytes[:], self.FinalMsg.Bytes())
	copy(bytes[self.FinalMsg.Len():], self.PAggSig.Bytes())
	bytes[0] = MsgCommit
	return bytes
}

func (self *CommitMsg) SetBytes(bytes []byte) {
	self.FinalMsg.SetBytes(bytes[:self.FinalMsg.Len()])
	self.PAggSig.SetBytes(bytes[self.FinalMsg.Len():])
}

func (self *CommitMsg) Verify(bls *BLS) bool {
	text := string(self.hash) + TextC
	h := sha256.Sum256([]byte(text))
	if ok := self.CAggSig.Verify(bls, h[:]); !ok {
		return false
	}
	if ok := self.PAggSig.Verify(bls, self.hash); !ok {
		return false
	}
	return self.PAggSig.reachQuorum()
}
