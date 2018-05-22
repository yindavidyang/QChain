package main

import (
	"github.com/sirupsen/logrus"
	"github.com/Nik-U/pbc"
	"time"
	"os"
)

const (
	numValidators = 4
	numEpochs     = 100
	bf            = 1
	epoch         = time.Millisecond * 50 // increase epoch size if the program crashes or verification fails
)

var (
	finished           = make(chan bool)
	numSend, numRecv   int64
	pubKeys            []*pbc.Element
	log                = logrus.New()
	validatorAddresses []string
)

// Verifying individual public keys is necessary to defend against related key attacks
func verifyPubKeys(vals []Validator) {
	for i := 0; i < numValidators; i++ {
		if !vals[i].VerifyPubKeySig() {
			log.Panic("Public key signature verification failed for Peer: ", i)
		}
	}
}

func main() {
	log.SetLevel(logLevel)
	log.Out = os.Stdout

	bls := &BLS{}
	bls.Init()

	validatorAddresses = genValidatorAddresses()

	validators := make([]Validator, numValidators)
	for i := 0; i < numValidators; i++ {
		validators[i].Init(uint32(i), bls)
	}
	verifyPubKeys(validators)

	pubKeys = make([]*pbc.Element, numValidators)
	for i := 0; i < numValidators; i++ {
		pubKeys[i] = validators[i].PubKey
	}

	finished = make(chan bool)

	proposerID := getProposerID(0)
	validators[proposerID].commitProposeBlock(0)

	for i := 0; i < numValidators; i++ {
		go validators[i].Gossip()
	}
	for i := 0; i < numValidators; i++ {
		<-finished
	}

	log.Print("Number of messages sent: ", numSend)
	log.Print("Number of messages received: ", numRecv)
}
