package main

import (
	"testing"
	"github.com/Nik-U/pbc"
	"github.com/dedis/onet/log"
	"bytes"
)

const (
	numPeers  = 10
)

var (
	pubKeys          []*pbc.Element
)

func TestAggSigSerialization(t *testing.T) {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	aggSig := &AggSig{}
	aggSig.Init(pairing)

	log.Print("Length of aggSig: ", aggSig.Len())
	b := aggSig.Bytes()

	aggSig2 := &AggSig{}
	aggSig2.Init(pairing)
	aggSig2.SetBytes(b)
	b2 := aggSig2.Bytes()

	if bytes.Compare(b, b2) != 0 {
		t.Error("b and b2 contain different contents.")
	}
}

func TestAggSigCopy(t *testing.T) {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	aggSig := &AggSig{}
	aggSig.Init(pairing)

	aggSig2 := aggSig.Copy()
	b := aggSig.Bytes()
	b2 := aggSig2.Bytes()

	if bytes.Compare(b, b2) != 0 {
		t.Error("b and b2 contain different contents.")
	}
}
