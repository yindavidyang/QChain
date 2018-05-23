package main

import (
	"encoding/binary"
	"github.com/Nik-U/pbc"
)

type (
	Msg struct {
		blockID    uint32
		hash       []byte
		PSig, CSig *AggSig

		pPairer, cPairer *pbc.Pairer
	}

	/*
	In a Prepare message:
	- blockID is the current block ID
	- hash is the hash of the current block
	- PSig is an AggSig of hash
	- PSig must contain the proposer of the current block
	- CSig is an Aggsig of (hash of the previous block | NounceCommit)
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
	- CSig is an Aggsig of (hash | NounceCommit)
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

func (msg *Msg) Init(bls *BLS, numVals int) {
	msg.hash = make([]byte, LenHash)
	msg.CSig = &AggSig{}
	msg.CSig.Init(bls, numVals)
	msg.PSig = &AggSig{}
	msg.PSig.Init(bls, numVals)
	msg.cPairer = nil
	msg.pPairer = nil
}

func (msg *Msg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	cBytes := cSig.Bytes()
	pBytes := pSig.Bytes()
	cLen := len(cBytes)
	pLen := len(pBytes)

	i := 0
	b := make([]byte, LenMsgType+LenBlockID+LenHash+cLen+pLen+2)
	b[i] = MsgTypeUnknown
	i += LenMsgType
	binary.LittleEndian.PutUint32(b[i:], blockID)
	i += LenBlockID
	copy(b[i:], hash)
	i += LenHash
	copy(b[i:], cBytes)
	i += cLen
	copy(b[i:], pBytes)
	return b
}

func (msg *Msg) SetBytes(b []byte) {
	i := LenMsgType
	msg.blockID = binary.LittleEndian.Uint32(b[i:])
	i += LenBlockID
	copy(msg.hash, b[i:])
	i += LenHash
	cLen := msg.CSig.SetBytes(b[i:])
	i += cLen
	msg.PSig.SetBytes(b[i:])
}

func (msg *Msg) VerifyPSig(bls *BLS, pubKeys []*pbc.Element) bool {
	numVals := len(pubKeys)
	proposerID := getProposerID(msg.blockID, numVals)
	if msg.PSig.counters[proposerID] == 0 {
		// Todo: slash all validators contained in the message
		return false
	}
	return msg.PSig.VerifyPreprocessed(bls, msg.pPairer, pubKeys)
}

func (msg *Msg) VerifyCSig(bls *BLS, pubKeys []*pbc.Element) bool {
	return msg.CSig.VerifyPreprocessed(bls, msg.cPairer, pubKeys)
}

func (msg *Msg) Preprocess(bls *BLS) {
	if msg.pPairer == nil {
		// Todo: commitprepare
		msg.pPairer = bls.PreprocessHash(msg.hash)
	}
	if msg.cPairer == nil {
		// Todo: check prepare
		// Todo: check commitprepare
		msg.cPairer = bls.PreprocessHash(getNouncedHash(msg.hash, NounceCommit))
	}
}

func (pMsg *PrepareMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := pMsg.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypePrepare
	return b
}

func (pMsg *PrepareMsg) Verify(bls *BLS, pubKeys []*pbc.Element) bool {
	if !pMsg.VerifyPSig(bls, pubKeys) {
		return false
	}
	if pMsg.blockID > 0 {
		if !pMsg.VerifyCSig(bls, pubKeys) {
			return false
		}
		if !pMsg.CSig.ReachQuorum() {
			return false
		}
	}
	return true
}

func (cMsg *CommitMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := cMsg.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypeCommit
	return b
}

func (cMsg *CommitMsg) Verify(bls *BLS, pubKeys []*pbc.Element) bool {
	if !cMsg.VerifyPSig(bls, pubKeys) {
		return false
	}
	if !cMsg.VerifyCSig(bls, pubKeys) {
		return false
	}
	return cMsg.PSig.ReachQuorum()
}

func (cpMsg *CommitPrepareMsg) BytesFromData(blockID uint32, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	b := cpMsg.Msg.BytesFromData(blockID, hash, cSig, pSig)
	b[0] = MsgTypeCommitPrepare
	return b
}

func (cpMsg *CommitPrepareMsg) Verify(bls *BLS, pubKeys []*pbc.Element) bool {
	if !cpMsg.VerifyPSig(bls, pubKeys) {
		return false
	}
	if cpMsg.blockID > 0 {
		if !cpMsg.VerifyCSig(bls, pubKeys) {
			return false
		}
		if !cpMsg.CSig.ReachQuorum() {
			return false
		}
	}
	return true
}
