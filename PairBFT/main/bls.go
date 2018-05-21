package main

import (
	"github.com/Nik-U/pbc"
	"crypto/sha256"
)

type (
	BLS struct {
		pairing *pbc.Pairing
		g       *pbc.Element
		params  *pbc.Params
	}
)

func (self *BLS) Init() {
	self.params = pbc.GenerateA(160, 512)
	self.pairing = self.params.NewPairing()
	self.g = self.pairing.NewG2().Rand()
}

func (self *BLS) GenKey() (*pbc.Element, *pbc.Element) {
	privKey := self.pairing.NewZr().Rand()
	pubKey := self.pairing.NewG2().PowZn(self.g, privKey)
	return privKey, pubKey
}

func (self *BLS) HashString(text string) *pbc.Element {
	return self.pairing.NewG1().SetFromStringHash(text, sha256.New())
}

func (self *BLS) HashBytes(data []byte) *pbc.Element {
	h := sha256.Sum256(data)
	return self.pairing.NewG1().SetFromHash(h[:])
}

func (self *BLS) Sign(hash *pbc.Element, privKey *pbc.Element) *pbc.Element {
	return self.pairing.NewG1().PowZn(hash, privKey)
}

func (self *BLS) SignBytes(data []byte, privKey *pbc.Element) *pbc.Element {
	h := self.HashBytes(data)
	return self.Sign(h, privKey)
}

func (self *BLS) SignHash(hash []byte, privKey *pbc.Element) *pbc.Element {
	h := self.pairing.NewG1().SetFromHash(hash)
	return self.Sign(h, privKey)
}

func (self *BLS) SignString(text string, privKey *pbc.Element) *pbc.Element {
	h := self.HashString(text)
	return self.Sign(h, privKey)
}

func (self *BLS) Verify(hash *pbc.Element, sig *pbc.Element, pubKey *pbc.Element) bool {
	temp1 := self.PairHash(hash, pubKey)
	temp2 := self.PairSig(sig)
	return temp1.Equals(temp2)
}

func (self *BLS) VerifyBytes(data []byte, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := self.HashBytes(data)
	return self.Verify(h, sig, pubKey)
}

func (self *BLS) VerifyHash(hash []byte, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := self.pairing.NewG1().SetFromHash(hash)
	return self.Verify(h, sig, pubKey)
}

func (self *BLS) VerifyString(text string, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := self.HashString(text)
	return self.Verify(h, sig, pubKey)
}

func (self *BLS) AggSig(sig1 *pbc.Element, sig2 *pbc.Element) *pbc.Element {
	return self.pairing.NewG1().Mul(sig1, sig2)
}

func (self *BLS) AggKey(pubKey1 *pbc.Element, pubKey2 *pbc.Element) *pbc.Element {
	return self.pairing.NewG2().Mul(pubKey1, pubKey2)
}

func (self *BLS) AggPairedHash(pairedHash1 *pbc.Element, pairedHash2 *pbc.Element) *pbc.Element {
	return self.pairing.NewGT().Mul(pairedHash1, pairedHash2)
}

func (self *BLS) PairSig(sig *pbc.Element) *pbc.Element {
	return self.pairing.NewGT().Pair(sig, self.g)
}

func (self *BLS) PairHash(hash *pbc.Element, pubKey *pbc.Element) *pbc.Element {
	return self.pairing.NewGT().Pair(hash, pubKey)
}

func (self *BLS) cloneSig(sig *pbc.Element) *pbc.Element {
	return self.pairing.NewG1().Set(sig)
}
