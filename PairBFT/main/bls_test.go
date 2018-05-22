package main

import (
	"testing"
)

// Aggregate signature: Alice and Bob sign the same text
func TestBLSAggregate(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	alicePrivKey, alicePubKey := bls.GenKey()
	bobPrivKey, bobPubKey := bls.GenKey()

	message := "some text to sign by both Alice and Bob"
	hash := bls.HashString(message)

	aliceSig := bls.Sign(hash, alicePrivKey)
	bobSig := bls.Sign(hash, bobPrivKey)

	aggSig := bls.AggSig(aliceSig, bobSig)
	aggKey := bls.AggKey(alicePubKey, bobPubKey)

	if ok := bls.Verify(hash, aggSig, aggKey); !ok {
		t.Error("Aggregate signature check failed.")
	}
}

// Aggregate signature: Alice and Bob sign different texts
func TestBLSAggregate2(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	alicePrivKey, alicePubKey := bls.GenKey()
	bobPrivKey, bobPubKey := bls.GenKey()

	aliceMsg := "some text to sign by Alice"
	bobMsg := "some text to sign by Bob"
	aliceHash := bls.HashString(aliceMsg)
	bobHash := bls.HashString(bobMsg)

	aliceSig := bls.Sign(aliceHash, alicePrivKey)
	bobSig := bls.Sign(bobHash, bobPrivKey)

	aggSig := bls.AggSig(aliceSig, bobSig)

	aggPairSig := bls.PairSig(aggSig)
	aggPairHash := bls.AggPairedHash(bls.PairHash(aliceHash, alicePubKey), bls.PairHash(bobHash, bobPubKey))

	if !aggPairHash.Equals(aggPairSig) {
		t.Error("Aggregate signature check failed.")
	}
}