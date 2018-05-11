package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/Nik-U/pbc"
)

// messageData represents a signed message sent over the network
type messageData struct {
	strData  string
	byteData []byte
}

func main() {
	finished := make(chan bool)
	laChan := make(chan *messageData)
	lbChan := make(chan *messageData)

	go leader(laChan, lbChan, finished)
	go alice(laChan, finished)
	go bob(lbChan, finished)

	<-finished
	<-finished
	<-finished
}

func leader(laChan chan *messageData, lbChan chan *messageData, finished chan bool) {
	// Step 1: leader generates shared params and broadcasts them
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	g := pairing.NewG2().Rand()

	laChan <- &messageData{params.String(), g.Bytes()}
	lbChan <- &messageData{params.String(), g.Bytes()}

	// Step 2: leader collects public keys, and computes aggregate key
	aliceKey := pairing.NewG2().SetBytes((<-laChan).byteData)
	bobKey := pairing.NewG2().SetBytes((<-lbChan).byteData)

	aggKey := pairing.NewG2().Mul(aliceKey, bobKey)
	fmt.Println("Length of Alice's public key:", len(aliceKey.Bytes()))
	fmt.Println("Length of Bob's public key:", len(bobKey.Bytes()))
	fmt.Println("Length of aggregate public key:", len(aggKey.Bytes()))

	// Case 1: both Alice and Bob sign the same hash

	// Step 3: leader broadcasts hash to sign
	message := "some text to sign by both Alice and Bob"
	h := pairing.NewG1().SetFromStringHash(message, sha256.New())
	laChan <- &messageData{"", h.Bytes()}
	lbChan <- &messageData{"", h.Bytes()}

	// Step 4: leader collects individual signatures, and computes aggregate signature
	aliceSig := pairing.NewG1().SetBytes((<-laChan).byteData)
	bobSig := pairing.NewG1().SetBytes((<-lbChan).byteData)

	aggSig := pairing.NewG1().Mul(aliceSig, bobSig)
	fmt.Println("Length of Alice's signature:", len(aliceSig.Bytes()))
	fmt.Println("Length of Bob's signature:", len(bobSig.Bytes()))
	fmt.Println("Length of aggregate signature:", len(aggSig.Bytes()))

	// Step 5: verify individual and aggregate signatures
	temp1 := pairing.NewGT().Pair(h, aliceKey)
	temp2 := pairing.NewGT().Pair(aliceSig, g)
	if !temp1.Equals(temp2) {
		fmt.Println("*BUG* Alice's signature check failed. *BUG*")
	} else {
		fmt.Println("Alice's signature verified correctly.")
	}

	temp3 := pairing.NewGT().Pair(h, bobKey)
	temp4 := pairing.NewGT().Pair(bobSig, g)
	if !temp3.Equals(temp4) {
		fmt.Println("*BUG* Bob's signature check failed. *BUG*")
	} else {
		fmt.Println("Bob's signature verified correctly.")
	}

	temp5 := pairing.NewGT().Pair(h, aggKey)
	temp6 := pairing.NewGT().Pair(aggSig, g)
	if !temp5.Equals(temp6) {
		fmt.Println("*BUG* Aggregate signature check failed. *BUG*")
	} else {
		fmt.Println("Aggregate signature verified correctly.")
	}

	// Case 2: Alice and Bob sign different hashes.

	// Step 3: leader broadcasts hash to sign
	aliceMsg := "some text to sign by Alice"
	bobMsg := "some text to sign by Bob"
	aliceHash := pairing.NewG1().SetFromStringHash(aliceMsg, sha256.New())
	bobHash := pairing.NewG1().SetFromStringHash(bobMsg, sha256.New())
	laChan <- &messageData{"", aliceHash.Bytes()}
	lbChan <- &messageData{"", bobHash.Bytes()}

	// Step 4: leader collects individual signatures, and computes aggregate signature
	aliceSig = pairing.NewG1().SetBytes((<-laChan).byteData)
	bobSig = pairing.NewG1().SetBytes((<-lbChan).byteData)
	aggSig = pairing.NewG1().Mul(aliceSig, bobSig)

	// Step 5: verify individual and aggregate signatures
	temp1 = pairing.NewGT().Pair(aliceHash, aliceKey)
	temp2 = pairing.NewGT().Pair(aliceSig, g)
	if !temp1.Equals(temp2) {
		fmt.Println("*BUG* Alice's signature check failed. *BUG*")
	} else {
		fmt.Println("Alice's signature verified correctly.")
	}

	temp3 = pairing.NewGT().Pair(bobHash, bobKey)
	temp4 = pairing.NewGT().Pair(bobSig, g)
	if !temp3.Equals(temp4) {
		fmt.Println("*BUG* Bob's signature check failed. *BUG*")
	} else {
		fmt.Println("Bob's signature verified correctly.")
	}

	temp6 = pairing.NewGT().Pair(aggSig, g)

	// using only alice's hash obviously fails, since bob signs a different hash
	temp5 = pairing.NewGT().Pair(aliceHash, aggKey)
	if !temp5.Equals(temp6) {
		fmt.Println("Aggregate signature check failed (as expected).")
	} else {
		fmt.Println("*BUG* Aggregate signature verified correctly.*BUG*")
	}

	// using Bob's hash similarly fails
	temp5 = pairing.NewGT().Pair(bobHash, aggKey)
	if !temp5.Equals(temp6) {
		fmt.Println("Aggregate signature check failed (as expected).")
	} else {
		fmt.Println("*BUG* Aggregate signature verified correctly.*BUG*")
	}

	// correct way
	temp5 = pairing.NewGT().Mul(temp1, temp2)
	if !temp1.Equals(temp2) {
		fmt.Println("*BUG* Aggregate signature check failed. *BUG*")
	} else {
		fmt.Println("Aggregate signature verified correctly.")
	}

	finished <- true
}

func alice(laChan chan *messageData, finished chan bool) {
	s := <-laChan
	pairing, _ := pbc.NewPairingFromString(s.strData)
	g := pairing.NewG2().SetBytes(s.byteData)

	alicePrivKey := pairing.NewZr().Rand()
	alicePubKey := pairing.NewG2().PowZn(g, alicePrivKey)

	// Don't reuse messages; otherwise we get race conditions.
	laChan <- &messageData{"", alicePubKey.Bytes()}

	// Case 1: both Alice and Bob sign the same hash

	hash := pairing.NewG1().SetBytes((<-laChan).byteData)
	aliceSig := pairing.NewG2().PowZn(hash, alicePrivKey)
	laChan <- &messageData{"", aliceSig.Bytes()}

	// Case 2: Alice and Bob sign different hashes.

	hash = pairing.NewG1().SetBytes((<-laChan).byteData)
	aliceSig = pairing.NewG2().PowZn(hash, alicePrivKey)
	laChan <- &messageData{"", aliceSig.Bytes()}

	finished <- true
}

func bob(lbChan chan *messageData, finished chan bool) {
	s := <-lbChan
	pairing, _ := pbc.NewPairingFromString(s.strData)
	g := pairing.NewG2().SetBytes(s.byteData)

	bobPrivKey := pairing.NewZr().Rand()
	bobPubKey := pairing.NewG2().PowZn(g, bobPrivKey)

	// Don't reuse messages; otherwise we get race conditions.
	lbChan <- &messageData{"", bobPubKey.Bytes()}

	// Case 1: both Alice and Bob sign the same hash

	hash := pairing.NewG1().SetBytes((<-lbChan).byteData)
	bobSig := pairing.NewG2().PowZn(hash, bobPrivKey)
	lbChan <- &messageData{"", bobSig.Bytes()}

	// Case 2: Alice and Bob sign different hashes.

	hash = pairing.NewG1().SetBytes((<-lbChan).byteData)
	bobSig = pairing.NewG2().PowZn(hash, bobPrivKey)
	lbChan <- &messageData{"", bobSig.Bytes()}

	finished <- true
}
