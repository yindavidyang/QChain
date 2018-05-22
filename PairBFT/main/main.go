package main

import (
	"github.com/sirupsen/logrus"
	"github.com/Nik-U/pbc"
	"os"
)

const (
	numVals   = 10
	numEpochs = 100
)

var (
	finished = make(chan bool)
)

func main() {
	log := logrus.New()

	log.SetLevel(logLevel)
	log.Out = os.Stdout

	bls := &BLS{}
	bls.Init()

	validatorAddresses := genValidatorAddresses()

	vals := make([]Validator, numVals)
	for i := 0; i < numVals; i++ {
		vals[i].Init(uint32(i), bls)
	}

	pubKeys := make([]*pbc.Element, numVals)
	pubKeySigs := make([]*pbc.Element, numVals)
	for i := 0; i < numVals; i++ {
		pubKeys[i] = vals[i].PubKey
		pubKeySigs[i] = vals[i].PubKeySig
	}
	for i := 0; i < numVals; i++ {
		vals[i].SetValSet(validatorAddresses, pubKeys, pubKeySigs)
	}
	log.Print("Setup complete.")

	finished = make(chan bool)

	proposerID := getProposerID(0)
	//vals[proposerID].commitProposeBlock(0)
	vals[proposerID].proposeBlock(0)

	for i := 0; i < numVals; i++ {
		go vals[i].Gossip()
	}
	for i := 0; i < numVals; i++ {
		<-finished
	}
}
