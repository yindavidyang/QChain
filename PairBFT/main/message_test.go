package main

import (
	"github.com/Nik-U/pbc"
	"testing"
	"crypto/sha256"
	"log"
	"bytes"
)

const (
	numPeers   = 10
	dataToSign = "Gossip BLS UDP BFT test data"
	ProposerID = 0
)

var (
	pubKeys []*pbc.Element
)

func TestPrepareMessage(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	proposerID := uint32(0)
	privKey, pubKey := bls.GenKey()
	pubKeys = make([]*pbc.Element, numPeers)
	pubKeys[proposerID] = pubKey

	h := sha256.Sum256([]byte(dataToSign))
	hash := h[:]
	sig := bls.Sign(bls.HashString(dataToSign), privKey)

	pMsg := &PrepareMsg{}
	pMsg.Init(bls)
	copy(pMsg.hash, hash)
	pMsg.aggSig.counters[proposerID] = 1
	pMsg.aggSig.sig.Set(sig)

	id2 := uint32(1)
	privKey2, pubKey2 := bls.GenKey()
	pubKeys[id2] = pubKey2
	pMsg.aggSig.counters[id2] = 1
	sig2 := bls.Sign(bls.HashString(dataToSign), privKey2)
	pMsg.aggSig.sig.ThenMul(sig2)

	if !pMsg.Verify(bls) {
		t.Error("ppMsg verification failed: ", pMsg)
	} else {
		log.Print("ppMsg verification passed.")
	}

	b := pMsg.Bytes()
	pMsg2 := &PrepareMsg{}
	pMsg2.Init(bls)
	pMsg2.SetBytes(b)
	if bytes.Compare(pMsg2.hash, pMsg.hash) != 0 {
		t.Error("Hash mismatch: ", pMsg2)
	}
	if !pMsg2.Verify(bls) {
		t.Error("ppMsg2 verification failed: ", pMsg2)
	} else {
		log.Print("ppMsg2 verification passed.")
	}
}