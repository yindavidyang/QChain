package PairBFT

import (
	"github.com/Nik-U/pbc"
	"encoding/binary"
)

type (
	AggSig struct {
		counters []uint32
		sig      *pbc.Element
	}
)

func (sig *AggSig) Init(bls *BLS, numVals int) {
	sig.counters = make([]uint32, numVals)
	sig.sig = bls.pairing.NewG1()
}

func (sig *AggSig) Len() int {
	numVals := len(sig.counters)
	return lenCounter*numVals + sig.sig.BytesLen()
}

func (sig *AggSig) Bytes() []byte {
	numVals := len(sig.counters)
	bytes := make([]byte, sig.Len())
	j := 0
	for i := 0; i < numVals; i++ {
		binary.LittleEndian.PutUint32(bytes[j:], sig.counters[i])
		j += lenCounter
	}
	copy(bytes[j:], sig.sig.Bytes())
	return bytes
}

func (sig *AggSig) SetBytes(b []byte) int {
	numVals := len(sig.counters)
	j := 0
	for i := 0; i < numVals; i++ {
		sig.counters[i] = binary.LittleEndian.Uint32(b[j:])
		j += lenCounter
	}
	sig.sig.SetBytes(b[j:])
	j += sig.sig.BytesLen()
	return j
}

func (sig *AggSig) computeAggKey(bls *BLS, pubKeys []*pbc.Element) *pbc.Element {
	numVals := len(sig.counters)
	vPubKey := bls.pairing.NewG2()
	tempKey := bls.pairing.NewG2()
	tempNum := bls.pairing.NewZr()
	for i := 0; i < numVals; i++ {
		if sig.counters[i] != 0 {
			tempNum.SetInt32(int32(sig.counters[i]))
			tempKey.PowZn(pubKeys[i], tempNum)
			if i == 0 {
				vPubKey.Set(tempKey)
			} else {
				vPubKey.ThenMul(tempKey)
			}
		}
	}
	return vPubKey
}

func (sig *AggSig) Verify(bls *BLS, hash []byte, pubKeys []*pbc.Element) bool {
	vPubKey := sig.computeAggKey(bls, pubKeys)
	return bls.VerifyHash(hash, sig.sig, vPubKey)
}

func (sig *AggSig) VerifyPreprocessed(bls *BLS, hash *pbc.Pairer, pubKeys []*pbc.Element) bool {
	vPubKey := sig.computeAggKey(bls, pubKeys)
	return bls.VerifyPreprocessed(hash, sig.sig, vPubKey)
}

func (sig *AggSig) Aggregate(otherSig *AggSig) {
	numVals := len(sig.counters)
	isSuperSet := true
	isSubSet := true
	for i := 0; i < numVals; i++ {
		if sig.counters[i] == 0 && otherSig.counters[i] != 0 {
			isSuperSet = false
		}
		if otherSig.counters[i] == 0 && sig.counters[i] != 0 {
			isSubSet = false
		}
	}

	if isSuperSet {
		return
	}

	if isSubSet {
		sig.sig.Set(otherSig.sig)
		copy(sig.counters, otherSig.counters)
		return
	}

	sig.sig.ThenMul(otherSig.sig)
	for i := 0; i < numVals; i++ {
		sig.counters[i] += otherSig.counters[i]
	}
}

func (sig *AggSig) AggregateOne(id uint32, otherSig *pbc.Element) {
	if sig.counters[id] != 0 {
		return
	}

	sig.sig.ThenMul(otherSig)
	sig.counters[id] = 1
}

func (sig *AggSig) ReachQuorum() bool {
	numVals := len(sig.counters)
	c := 0
	for i := 0; i < numVals; i++ {
		if sig.counters[i] > 0 {
			c++
		}
	}
	return c > numVals/3*2
}
