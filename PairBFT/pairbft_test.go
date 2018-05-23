package PairBFT

import (
	"time"
	"testing"
	"sync"
)

func SimulatePairBFT(numVals int, bf int, epoch time.Duration, numEpochs int) {
	vals := genValidators(numVals, bf, epoch)

	proposerID := getProposerID(0, numVals)
	//vals[proposerID].commitProposeBlock(0)
	vals[proposerID].proposeBlock(0)

	var wg sync.WaitGroup
	for i := 0; i < numVals; i++ {
		vals[i].debugEpochLimit = numEpochs
		val := vals[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			val.Start()
		}()
	}
	wg.Wait()
}

func TestPairBFT_n4_bf1_e50(t *testing.T) {
	numVals := 4
	bf := 1
	numEpochs := 10
	epoch := time.Millisecond * 50
	SimulatePairBFT(numVals, bf, epoch, numEpochs)
}

func TestPairBFT_n10_bf2_e100(t *testing.T) {
	numVals := 10
	bf := 2
	numEpochs := 100
	epoch := time.Millisecond * 100
	SimulatePairBFT(numVals, bf, epoch, numEpochs)
}

func TestPairBFT_n40_bf5_e500(t *testing.T) {
	numVals := 40
	bf := 5
	numEpochs := 100
	epoch := time.Millisecond * 500
	SimulatePairBFT(numVals, bf, epoch, numEpochs)
}
