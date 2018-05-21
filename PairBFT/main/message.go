package main

import (
	"crypto/sha256"
	"encoding/binary"
)

type (
	Msg struct {
		blockID    uint32
		hash       []byte
		PSig, CSig *AggSig
	}

	/*
	In a Prepare message:
	- blockID is the current block ID
	- hash is the hash of the current block
	- PSig is an AggSig of hash
	- PSig must contain the proposer of the current block
	- CSig is an Aggsig of (hash of the previous block | CommitNounce)
	- CSig much reach quorum
	*/
	PrepareMsg struct {
		Msg
	}

	/*
	In a Commit message:
	- blockID is the current block ID
	- hash is the hash of the current block
	- PSig is an AggSig of hash
	- PSig must contain the proposer of the current block
	- CSig is an Aggsig of (hash | CommitNounce)
	- PSig much reach quorum
	*/
	CommitMsg struct {
		Msg
	}

	/*
	In a CommitPrepare message:
	- blockID is the current block ID
	- hash is the hash of the current block
	- PSig is an AggSig of (hash | hash of previous block)
	- PSig must contain the proposer of the current block
	- CSig is an AggSig of (hash of previous block | hash of prev-prev block)
	- CSig much reach quorum
	*/
	CommitPrepareMsg struct {
		Msg
	}
)

func (self *Msg) Init(bls *BLS) {
	self.hash = make([]byte, LenHash)
	self.CSig = &AggSig{}
	self.CSig.Init(bls)
	self.PSig = &AggSig{}
	self.PSig.Init(bls)
}

func (self *Msg) Len() int {
	return LenMsgType + LenBlockID + LenHash + LenAggSig*2
}

func (self *Msg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	i := 0
	b := make([]byte, self.Len())
	b[i] = MsgTypeUnknown
	i += LenMsgType
	binary.LittleEndian.PutUint32(b[i:], blockID)
	i += LenBlockID
	copy(b[i:], hash)
	i += LenHash
	copy(b[i:], cSig.Bytes())
	i += LenAggSig
	copy(b[i:], pSig.Bytes())
	return b
}

func (self *Msg) SetBytes(b []byte) {
	i := LenMsgType
	self.blockID = binary.LittleEndian.Uint32(b[i:])
	i += LenBlockID
	copy(self.hash, b[i:])
	i += LenHash
	self.CSig.SetBytes(b[i:])
	i += LenAggSig
	self.PSig.SetBytes(b[i:])
}

func (self *Msg) VerifyPSig(bls *BLS, hash []byte) bool {
	proposerID := getProposerID(self.blockID)
	if self.PSig.counters[proposerID] == 0 {
		// Todo: slash all validators contained in the message
		return false
	}
	return self.PSig.Verify(bls, hash)
}

func (self *Msg) VerifyCSig(bls *BLS, hash []byte) bool {
	dataToSign := string(hash) + CommitNounce
	h := sha256.Sum256([]byte(dataToSign))
	return self.CSig.Verify(bls, h[:])
}

func (self *PrepareMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := self.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypePrepare
	return b
}

func (self *PrepareMsg) Verify(bls *BLS, prevHash []byte) bool {
	if !self.VerifyPSig(bls, self.hash) {
		return false
	}
	if self.blockID > 0 {
		if !self.VerifyCSig(bls, prevHash) {
			return false
		}
		if !self.CSig.ReachQuorum() {
			return false
		}
	}
	return true
}

func (self *CommitMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := self.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypeCommit
	return b
}

func (self *CommitMsg) Verify(bls *BLS) bool {
	if !self.VerifyPSig(bls, self.hash) {
		return false
	}
	if !self.VerifyCSig(bls, self.hash) {
		return false
	}
	return self.PSig.ReachQuorum()
}

func (self *CommitPrepareMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := self.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypeCommitPrepare
	return b
}

func (self *CommitPrepareMsg) Verify(bls *BLS, prevHash []byte) bool {
	if !self.VerifyPSig(bls, self.hash) {
		return false
	}

	if !self.CSig.Verify(bls, prevHash) {
		return false
	}
	return self.CSig.ReachQuorum()
}
