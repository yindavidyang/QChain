package PairBFT

import (
	"encoding/binary"
	"github.com/Nik-U/pbc"
)

type (
	Msg struct {
		msgType        byte
		blockHeight    uint64
		hash           []byte
		PSig, CSig     *AggSig

		pPairer, cPairer *pbc.Pairer
	}
)

func (msg *Msg) Init(bls *BLS, numVals int, msgType byte) {
	msg.msgType = msgType
	msg.hash = make([]byte, LenHash)
	msg.CSig = &AggSig{}
	msg.CSig.Init(bls, numVals)
	msg.PSig = &AggSig{}
	msg.PSig.Init(bls, numVals)
}

func MsgBytesFromData(msgType byte, blockHeight uint64, hash []byte, cSig *AggSig, pSig *AggSig) []byte {
	if cSig == nil {
		cSig = pSig
	}
	cBytes := cSig.Bytes()
	pBytes := pSig.Bytes()
	cLen := len(cBytes)
	pLen := len(pBytes)

	i := 0
	b := make([]byte, LenMsgType+LenBlockHeight+LenHash+cLen+pLen)
	b[i] = msgType
	i += LenMsgType
	binary.LittleEndian.PutUint64(b[i:], blockHeight)
	i += LenBlockHeight
	copy(b[i:], hash)
	i += LenHash
	copy(b[i:], cBytes)
	i += cLen
	copy(b[i:], pBytes)
	return b
}

func (msg *Msg) SetBytes(b []byte) {
	msg.msgType = b[0]
	i := LenMsgType
	msg.blockHeight = binary.LittleEndian.Uint64(b[i:])
	i += LenBlockHeight
	copy(msg.hash, b[i:])
	i += LenHash
	cLen := msg.CSig.SetBytes(b[i:])
	i += cLen
	msg.PSig.SetBytes(b[i:])
}

func (msg *Msg) VerifyPSig(bls *BLS, pubKeys []*pbc.Element) bool {
	numVals := len(pubKeys)
	proposerID := getProposerID(msg.blockHeight, numVals)
	if msg.PSig.counters[proposerID] == 0 {
		// Todo: slash all validators contained in the message
		return false
	}
	return msg.PSig.VerifyPreprocessed(bls, msg.pPairer, pubKeys)
}

func (msg *Msg) VerifyCSig(bls *BLS, pubKeys []*pbc.Element) bool {
	return msg.CSig.VerifyPreprocessed(bls, msg.cPairer, pubKeys)
}

func (msg *Msg) Preprocess(bls *BLS, useCommitPrepare bool) {
	if msg.pPairer == nil {
		nonce := NoncePrepare
		if useCommitPrepare {
			nonce = NonceCommitPrepare
		}
		msg.pPairer = bls.PreprocessHash(getNoncedHash(msg.hash, nonce))
	}
	if msg.cPairer == nil {
		msg.cPairer = bls.PreprocessHash(getNoncedHash(msg.hash, NonceCommit))
	}
}

func (msg *Msg) Verify(bls *BLS, pubKeys []*pbc.Element) bool {
	if !msg.VerifyPSig(bls, pubKeys) {
		return false
	}

	if msg.msgType == MsgTypeCommit || msg.blockHeight > 1 {
		if !msg.VerifyCSig(bls, pubKeys) {
			return false
		}
	}

	if msg.msgType == MsgTypeCommit {
		return msg.PSig.ReachQuorum()
	} else if msg.blockHeight > 1 {
		return msg.CSig.ReachQuorum()
	}

	return true
}
