package main

import (
	"github.com/NIk-U/pbc"
	"crypto/sha256"
	"encoding/binary"
)

func (self *message) fromBytes(bytes []byte) {
	for i := 0; i < numPeers; i++ {
		self.counters[i] = int(binary.LittleEndian.Uint32(bytes[i*4 : i*4+4]))
	}
	self.aggSig.SetBytes(bytes[numPeers*4:])
}

func (self *message) toBytes() []byte {
	len :=	4 * numPeers + self.aggSig.BytesLen()
	bytes := make([]byte, len)
	for i := 0; i < numPeers; i++ {
		binary.LittleEndian.PutUint32(bytes[i*4 : i*4+4], uint32(self.counters[i]))
	}
	copy(bytes[numPeers*4:], self.aggSig.Bytes())
	return bytes
}

func (self *message) copy() *message {
	ret := message{}
	ret.aggSig = self.aggSig.NewFieldElement().Set(self.aggSig)
	ret.counters = make([]int, numPeers)
	for i := 0; i < numPeers; i++ {
		ret.counters[i] = self.counters[i]
	}
	return &ret
}

func (self *message) verifyMessage(pairing *pbc.Pairing, g *pbc.Element) bool {
	vPubKey := pairing.NewG2()
	tempKey := pairing.NewG2()
	tempNum := pairing.NewZr()
	for j := 0; j < numPeers; j++ {
		tempNum.SetInt32(int32(self.counters[j]))
		tempKey.PowZn(pubKeys[j], tempNum)
		if j == 0 {
			vPubKey.Set(tempKey)
		} else {
			vPubKey.ThenMul(tempKey)
		}
	}

	h := sha256.Sum256([]byte(textToSign))
	hash := pairing.NewG1().SetFromHash(h[:])
	temp1 := pairing.NewGT().Pair(hash, vPubKey)
	temp2 := pairing.NewGT().Pair(self.aggSig, g)

	return temp1.Equals(temp2)
}
