package PairBFT

import (
	"time"
	"testing"
	"sync"
	"github.com/Nik-U/pbc"
)

func genValidators(numVals int, bf int, epochLen time.Duration) []Validator {
	bls := &BLS{}
	bls.Init()

	validatorAddresses := genValidatorAddresses(numVals)

	vals := make([]Validator, numVals)
	for i := 0; i < numVals; i++ {
		vals[i].Init(uint32(i), bls, bf, epochLen)
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
	return vals
}

func SimulatePairBFT(numVals int, bf int, epoch time.Duration, numEpochs int, useCommitPrepare bool) {
	vals := genValidators(numVals, bf, epoch)

	proposerID := getProposerID(0, numVals)

	if useCommitPrepare {
		for i := 0; i < numVals; i++ {
			vals[i].useCommitPrepare = true
		}
		vals[proposerID].commitProposeBlock(0)
	} else {
		vals[proposerID].proposeBlock(0)

	}

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
	SimulatePairBFT(numVals, bf, epoch, numEpochs, false)
}

func TestPairBFT_cp_n4_bf1_e50(t *testing.T) {
	return
	numVals := 4
	bf := 1
	numEpochs := 10
	epoch := time.Millisecond * 50
	SimulatePairBFT(numVals, bf, epoch, numEpochs, true)
}

func TestPairBFT_n10_bf2_e100(t *testing.T) {
	return
	numVals := 10
	bf := 2
	numEpochs := 100
	epoch := time.Millisecond * 100
	SimulatePairBFT(numVals, bf, epoch, numEpochs, false)
}

func TestPairBFT_cp_n10_bf2_e100(t *testing.T) {
	return
	numVals := 10
	bf := 2
	numEpochs := 100
	epoch := time.Millisecond * 100
	SimulatePairBFT(numVals, bf, epoch, numEpochs, true)
}

func TestPairBFT_n40_bf5_e500(t *testing.T) {
	numVals := 40
	bf := 5
	numEpochs := 100
	epoch := time.Millisecond * 500
	SimulatePairBFT(numVals, bf, epoch, numEpochs, false)
}
