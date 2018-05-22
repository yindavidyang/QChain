package main

import "testing"

const (
	numVals   = 10
	numEpochs = 100
)

var (
	finished = make(chan bool)
)

func TestBFTHandlers(t *testing.T) {
	vals := genValidators()

	proposerID := getProposerID(0)
	//vals[proposerID].commitProposeBlock(0)
	vals[proposerID].proposeBlock(0)

	for i := 0; i < numEpochs; i++ {
		for j := 0; j < numVals; j ++ {
			for k := 0; k < branchFactor; k++ {
				rcpt := vals[j].chooseRcpt()
				data := vals[j].genMsgData(rcpt)
				if data != nil {
					vals[rcpt].handleMsgData(data)
				}
			}
		}
	}
}
