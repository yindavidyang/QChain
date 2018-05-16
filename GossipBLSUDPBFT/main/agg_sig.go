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

func (self *AggSig) Init(pairing *pbc.Pairing) {
	self.counters = make([]uint32, numPeers)
	self.sig = pairing.NewG1()
}

func (self *AggSig) Len() int {
	return 4*numPeers + self.sig.BytesLen()
}

func (self *AggSig) Bytes() []byte {
	bytes := make([]byte, self.Len())
	for i := 0; i < numPeers; i++ {
		binary.LittleEndian.PutUint32(bytes[i*4:i*4+4], self.counters[i])
	}
	copy(bytes[numPeers*4:], self.sig.Bytes())
	return bytes
}

func (self *AggSig) SetBytes(bytes []byte) {
	for i := 0; i < numPeers; i++ {
		self.counters[i] = binary.LittleEndian.Uint32(bytes[i*4 : i*4+4])
	}
	self.sig.SetBytes(bytes[numPeers*4:])
}

func (self *AggSig) Verify(pairing *pbc.Pairing, g *pbc.Element, h []byte) bool {
	vPubKey := pairing.NewG2()
	tempKey := pairing.NewG2()
	tempNum := pairing.NewZr()
	for j := 0; j < numPeers; j++ {
		if (self.counters[j] != 0) {
			tempNum.SetInt32(int32(self.counters[j]))
			tempKey.PowZn(pubKeys[j], tempNum)
			if j == 0 {
				vPubKey.Set(tempKey)
			} else {
				vPubKey.ThenMul(tempKey)
			}
		}
	}

	hash := pairing.NewG1().SetFromHash(h[:])
	temp1 := pairing.NewGT().Pair(hash, vPubKey)
	temp2 := pairing.NewGT().Pair(self.sig, g)

	return temp1.Equals(temp2)
}

func (self *AggSig) Copy() *AggSig {
	ret := AggSig{}
	ret.sig = self.sig.NewFieldElement().Set(self.sig)
	ret.counters = make([]uint32, numPeers)
	for i := 0; i < numPeers; i++ {
		ret.counters[i] = self.counters[i]
	}
	return &ret
}

func (self *AggSig) Aggregate(aggSig *AggSig) {
	var i int

	for i = 0; i < numPeers; i++ {
		if self.counters[i] == 0 && aggSig.counters[i] != 0 {
			break
		}
	}
	if i == numPeers {
		return
	}

	self.sig.ThenMul(aggSig.sig)
	for i := 0; i < numPeers; i++ {
		self.counters[i] += aggSig.counters[i]
	}
}

func (self *AggSig) reachQuorum() bool {
	c := 0
	for i := 0; i < numPeers; i++ {
		if self.counters[i] > 0 {
			c++
		}
	}
	return c > numPeers/3*2
}
