package main

import "time"

const (
	numEpochs = 100
)

var (
	finished = make(chan bool)
)

func main() {
	numVals := 40
	bf := 5
	epoch := time.Millisecond * 500

	vals := genValidators(numVals, bf, epoch)

	finished = make(chan bool)

	proposerID := getProposerID(0, numVals)
	//vals[proposerID].commitProposeBlock(0)
	vals[proposerID].proposeBlock(0)

	for i := 0; i < numVals; i++ {
		go vals[i].Start()
	}
	for i := 0; i < numVals; i++ {
		<-finished
	}
}
