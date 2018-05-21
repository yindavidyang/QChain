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

func (self *AggSig) Init(bls *BLS) {
	self.counters = make([]uint32, numValidators)
	self.sig = bls.pairing.NewG1()
}

func (self *AggSig) Len() int {
	return 4*numValidators + self.sig.BytesLen()
}

func (self *AggSig) Bytes() []byte {
	bytes := make([]byte, self.Len())
	for i := 0; i < numValidators; i++ {
		binary.LittleEndian.PutUint32(bytes[i*4:i*4+4], self.counters[i])
	}
	copy(bytes[numValidators*4:], self.sig.Bytes())
	return bytes
}

func (self *AggSig) SetBytes(bytes []byte) {
	for i := 0; i < numValidators; i++ {
		self.counters[i] = binary.LittleEndian.Uint32(bytes[i*4 : i*4+4])
	}
	self.sig.SetBytes(bytes[numValidators*4:])
}

func (self *AggSig) Verify(bls *BLS, h []byte) bool {
	vPubKey := bls.pairing.NewG2()
	tempKey := bls.pairing.NewG2()
	tempNum := bls.pairing.NewZr()
	for i := 0; i < numValidators; i++ {
		if (self.counters[i] != 0) {
			tempNum.SetInt32(int32(self.counters[i]))
			tempKey.PowZn(pubKeys[i], tempNum)
			if i == 0 {
				vPubKey.Set(tempKey)
			} else {
				vPubKey.ThenMul(tempKey)
			}
		}
	}

	return bls.VerifyHash(h, self.sig, vPubKey)
}

func (self *AggSig) Copy() *AggSig {
	ret := AggSig{}
	ret.sig = self.sig.NewFieldElement().Set(self.sig)
	ret.counters = make([]uint32, numValidators)
	for i := 0; i < numValidators; i++ {
		ret.counters[i] = self.counters[i]
	}
	return &ret
}

func (self *AggSig) Aggregate(aggSig *AggSig) {
	isSuperSet := true
	isSubSet := true

	for i := 0; i < numValidators; i++ {
		if self.counters[i] == 0 && aggSig.counters[i] != 0 {
			isSuperSet = false
		}
		if aggSig.counters[i] == 0 && self.counters[i] != 0 {
			isSubSet = false
		}
	}

	if isSuperSet {
		return
	}

	if isSubSet {
		self.sig.Set(aggSig.sig)
		copy(self.counters, aggSig.counters)
		return
	}

	self.sig.ThenMul(aggSig.sig)
	for i := 0; i < numValidators; i++ {
		self.counters[i] += aggSig.counters[i]
	}
}

func (self *AggSig) AggregateOne(id uint32, sig *pbc.Element) {
	if self.counters[id] != 0 {
		return
	}

	self.sig.ThenMul(sig)
	self.counters[id] = 1
}

func (self *AggSig) ReachQuorum() bool {
	c := 0
	for i := 0; i < numValidators; i++ {
		if self.counters[i] > 0 {
			c++
		}
	}
	return c > numValidators/3*2
}
