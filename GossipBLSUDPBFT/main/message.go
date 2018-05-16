package main

import (
	"github.com/Nik-U/pbc"
	"crypto/sha256"
	"encoding/binary"
	"log"
)

const (
	MessagePP byte = iota
	MessageP
	MessageC
	MessageF
)

const (
	TextC = "Commit"
)

type (
	IMessage interface {
		Init()
		Len(pairing *pbc.Pairing) int
		Bytes() []byte
		SetBytes(bytes []byte)
		Verify(pairing *pbc.Pairing, g *pbc.Element) bool
	}

	Message struct {
		hash []byte
	}

	PreprepareMsg struct {
		Message
		ProposerID uint32
		sig        *pbc.Element
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
	self.sig = pairing.NewG1()
}

func (self *PreprepareMsg) Len() int {
	// 1 byte for message type, 4 bytes for proposer ID
	return 1 + self.Message.Len() + 4 + self.sig.BytesLen()
}

func (self *PreprepareMsg) Bytes() []byte {
	bytes := make([]byte, self.Len())
	bytes[0] = MessagePP
	copy(bytes[1:], self.hash)
	binary.LittleEndian.PutUint32(bytes[1+self.Message.Len():], self.ProposerID)
	copy(bytes[1+self.Message.Len()+4:], self.sig.Bytes())
	return bytes
}

func (self *PreprepareMsg) SetBytes(bytes []byte) {
	copy(self.hash, bytes[1:])
	self.ProposerID = binary.LittleEndian.Uint32(bytes[1+self.Message.Len() : 1+self.Message.Len()+4])
	self.sig.SetBytes(bytes[1+self.Message.Len()+4:])
}

func (self *PreprepareMsg) Verify(pairing *pbc.Pairing, g *pbc.Element) bool {
	vPubKey := pubKeys[self.ProposerID]
	hash := pairing.NewG1().SetFromHash(self.hash[:])
	temp1 := pairing.NewGT().Pair(hash, vPubKey)
	temp2 := pairing.NewGT().Pair(self.sig, g)
	if !temp1.Equals(temp2) {
		log.Panic("Verification failed: ", self)
		return false
	}
	return true
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
	bytes[0] = MessageP
	return bytes
}

func (self *PrepareMsg) SetBytes(bytes []byte) {
	self.PreprepareMsg.SetBytes(bytes[:self.PreprepareMsg.Len()])
	self.aggSig.SetBytes(bytes[self.PreprepareMsg.Len():])
}

func (self *PrepareMsg) Verify(pairing *pbc.Pairing, g *pbc.Element) bool {
	if !self.PreprepareMsg.Verify(pairing, g) {
		log.Panic("Verification failed: ", self)
		return false
	}
	if !self.aggSig.Verify(pairing, g, self.hash) {
		log.Panic("Verification failed: ", self)
		return false
	}
	return true
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
	bytes[0] = MessageF
	copy(bytes[1:], self.hash)
	copy(bytes[1+self.Message.Len():], self.CAggSig.Bytes())
	return bytes
}

func (self *FinalMsg) SetBytes(bytes []byte) {
	copy(self.hash, bytes[1:])
	self.CAggSig.SetBytes(bytes[1+self.Message.Len():])
}

func (self *FinalMsg) Verify(pairing *pbc.Pairing, g *pbc.Element) bool {
	text := string(self.hash) + TextC
	h := sha256.Sum256([]byte(text))
	if ok := self.CAggSig.Verify(pairing, g, h[:]); !ok {
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
	bytes[0] = MessageC
	return bytes
}

func (self *CommitMsg) SetBytes(bytes []byte) {
	self.FinalMsg.SetBytes(bytes[:self.FinalMsg.Len()])
	self.PAggSig.SetBytes(bytes[self.FinalMsg.Len():])
}

func (self *CommitMsg) Verify(pairing *pbc.Pairing, g *pbc.Element) bool {
	text := string(self.hash) + TextC
	h := sha256.Sum256([]byte(text))
	if ok := self.CAggSig.Verify(pairing, g, h[:]); !ok {
		return false
	}
	if ok := self.PAggSig.Verify(pairing, g, self.hash); !ok {
		return false
	}
	return self.PAggSig.reachQuorum()
}
