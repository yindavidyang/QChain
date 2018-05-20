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
)

var (
	pubKeys []*pbc.Element
)

func TestPreprepareMessage(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	proposerID := uint32(0)
	privKey, pubKey := bls.GenKey()
	pubKeys = make([]*pbc.Element, numPeers)
	pubKeys[proposerID] = pubKey

	h := sha256.Sum256([]byte(dataToSign))
	hash := h[:]
	sig := bls.Sign(bls.HashString(dataToSign), privKey)

	ppMsg := &PreprepareMsg{}
	ppMsg.Init(bls.pairing)
	copy(ppMsg.hash, hash)
	ppMsg.ProposerID = proposerID
	ppMsg.ProposerSig.Set(sig)

	if !ppMsg.Verify(bls.pairing, bls.g) {
		t.Error("ppMsg verification failed: ", ppMsg)
	} else {
		log.Print("ppMsg verification passed.")
	}

	b := ppMsg.Bytes()
	ppMsg2 := &PreprepareMsg{}
	ppMsg2.Init(bls.pairing)
	ppMsg2.SetBytes(b)
	if ppMsg2.ProposerID != ppMsg.ProposerID {
		t.Error("ProposerID mismatch: ", ppMsg2)
	}
	if bytes.Compare(ppMsg2.hash, ppMsg.hash) != 0 {
		t.Error("Hash mismatch: ", ppMsg2)
	}
	if !ppMsg2.Verify(bls.pairing, bls.g) {
		t.Error("ppMsg2 verification failed: ", ppMsg2)
	} else {
		log.Print("ppMsg2 verification passed.")
	}
}

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
	pMsg.Init(bls.pairing)
	copy(pMsg.hash, hash)
	pMsg.ProposerID = proposerID
	pMsg.ProposerSig.Set(sig)
	pMsg.aggSig.counters[proposerID] = 1
	pMsg.aggSig.sig.Set(sig)

	id2 := uint32(1)
	privKey2, pubKey2 := bls.GenKey()
	pubKeys[id2] = pubKey2
	pMsg.aggSig.counters[id2] = 1
	sig2 := bls.Sign(bls.HashString(dataToSign), privKey2)
	pMsg.aggSig.sig.ThenMul(sig2)

	if !pMsg.Verify(bls.pairing, bls.g) {
		t.Error("ppMsg verification failed: ", pMsg)
	} else {
		log.Print("ppMsg verification passed.")
	}

	b := pMsg.Bytes()
	ppMsg2 := &PreprepareMsg{}
	ppMsg2.Init(bls.pairing)
	ppMsg2.SetBytes(b)
	if ppMsg2.ProposerID != pMsg.ProposerID {
		t.Error("ProposerID mismatch: ", ppMsg2)
	}
	if bytes.Compare(ppMsg2.hash, pMsg.hash) != 0 {
		t.Error("Hash mismatch: ", ppMsg2)
	}
	if !ppMsg2.Verify(bls.pairing, bls.g) {
		t.Error("ppMsg2 verification failed: ", ppMsg2)
	} else {
		log.Print("ppMsg2 verification passed.")
	}
}