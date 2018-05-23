package PairBFT

import (
	"testing"
	"time"
)

func TestBFTHandlers(t *testing.T) {
	numVals := 10
	bf := 2
	epoch := 100 * time.Millisecond

	vals := genValidators(numVals, bf, epoch)

	proposerID := getProposerID(0, numVals)
	//vals[proposerID].commitProposeBlock(0)
	vals[proposerID].proposeBlock(0)

	for i := 0; i < numEpochs; i++ {
		for j := 0; j < numVals; j ++ {
			for k := 0; k < bf; k++ {
				rcpt := vals[j].chooseRcpt()
				data := vals[j].genMsgData(rcpt)
				if data != nil {
					vals[rcpt].handleMsgData(data)
				}
			}
		}
	}
}
