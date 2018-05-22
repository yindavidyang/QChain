package main

import (
	"testing"
	"bytes"
	"math/rand"
	"log"
)

const (
	numVals   = 10
	numEpochs = 100
)

var (
	finished = make(chan bool)
)

func TestAggSigSerialization(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	for rep := 0; rep < 1000; rep ++ {
		if rep%100 == 0 {
			log.Print("Rep:", rep)
		}

		privKey, pubKey := bls.GenKey()

		blockID := uint32(rep)
		aggSig := &AggSig{}
		aggSig.Init(bls)
		for i := 0; i < numVals; i ++ {
			aggSig.counters[i] = rand.Uint32()
		}
		hash := getBlockHash(blockID)
		hash = getNouncedHash(hash, NounceCommit)
		aggSig.sig = bls.SignHash(hash, privKey)

		pairer := bls.PreprocessHash(hash)
		if !bls.VerifyPreprocessed(pairer, aggSig.sig, pubKey) {
			t.Error("Verification failed.")
		}

		b := aggSig.Bytes()

		aggSig2 := &AggSig{}
		aggSig2.Init(bls)
		aggSig2.SetBytes(b)
		b2 := aggSig2.Bytes()

		if bytes.Compare(b, b2) != 0 {
			t.Error("b and b2 contain different contents.")
		}

		for i := 0; i < numVals; i++ {
			if aggSig.counters[i] != aggSig2.counters[i] {
				t.Error("Incorrect counter")
			}
		}

		if !aggSig.sig.Equals(aggSig2.sig) {
			t.Error("Signature not identical")
		}

		if !bls.VerifyPreprocessed(pairer, aggSig2.sig, pubKey) {
			t.Error("Verification failed.")
		}
	}
}

func TestAggSigCopy(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	aggSig := &AggSig{}
	aggSig.Init(bls)

	aggSig2 := aggSig.Copy()
	b := aggSig.Bytes()
	b2 := aggSig2.Bytes()

	if bytes.Compare(b, b2) != 0 {
		t.Error("b and b2 contain different contents.")
	}
}
