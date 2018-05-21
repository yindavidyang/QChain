package main

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

func (sig *AggSig) Init(bls *BLS) {
	sig.counters = make([]uint32, numValidators)
	sig.sig = bls.pairing.NewG1()
}

func (sig *AggSig) Len() int {
	return 4*numValidators + sig.sig.BytesLen()
}

func (sig *AggSig) Bytes() []byte {
	bytes := make([]byte, sig.Len())
	j := 0
	for i := 0; i < numValidators; i++ {
		binary.LittleEndian.PutUint32(bytes[j:j+lenCounter], sig.counters[i])
		j += lenCounter
	}
	copy(bytes[j:], sig.sig.Bytes())
	return bytes
}

func (sig *AggSig) SetBytes(bytes []byte) {
	j := 0
	for i := 0; i < numValidators; i++ {
		sig.counters[i] = binary.LittleEndian.Uint32(bytes[j : j+lenCounter])
		j += lenCounter
	}
	sig.sig.SetBytes(bytes[j:])
}

func (sig *AggSig) computeAggKey(bls *BLS) *pbc.Element {
	vPubKey := bls.pairing.NewG2()
	tempKey := bls.pairing.NewG2()
	tempNum := bls.pairing.NewZr()
	for i := 0; i < numValidators; i++ {
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

func (sig *AggSig) Verify(bls *BLS, hash []byte) bool {
	vPubKey := sig.computeAggKey(bls)
	return bls.VerifyHash(hash, sig.sig, vPubKey)
}

func (sig *AggSig) VerifyPreprocessed(bls *BLS, hash *pbc.Pairer) bool {
	vPubKey := sig.computeAggKey(bls)
	return bls.VerifyPreprocessed(hash, sig.sig, vPubKey)
}

func (sig *AggSig) Copy() *AggSig {
	ret := AggSig{}
	ret.sig = sig.sig.NewFieldElement().Set(sig.sig)
	ret.counters = make([]uint32, numValidators)
	for i := 0; i < numValidators; i++ {
		ret.counters[i] = sig.counters[i]
	}
	return &ret
}

func (sig *AggSig) Aggregate(otherSig *AggSig) {
	isSuperSet := true
	isSubSet := true

	for i := 0; i < numValidators; i++ {
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
	for i := 0; i < numValidators; i++ {
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
	c := 0
	for i := 0; i < numValidators; i++ {
		if sig.counters[i] > 0 {
			c++
		}
	}
	return c > numValidators/3*2
}
