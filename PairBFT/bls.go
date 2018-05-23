package PairBFT

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

func (bls *BLS) Init() {
	bls.params = pbc.GenerateA(160, 512)
	bls.pairing = bls.params.NewPairing()
	bls.g = bls.pairing.NewG2().Rand()
}

func (bls *BLS) GenKey() (*pbc.Element, *pbc.Element) {
	privKey := bls.pairing.NewZr().Rand()
	pubKey := bls.pairing.NewG2().PowZn(bls.g, privKey)
	return privKey, pubKey
}

func (bls *BLS) HashString(text string) *pbc.Element {
	return bls.pairing.NewG1().SetFromStringHash(text, sha256.New())
}

func (bls *BLS) HashBytes(data []byte) *pbc.Element {
	h := sha256.Sum256(data)
	return bls.pairing.NewG1().SetFromHash(h[:])
}

func (bls *BLS) Sign(hash *pbc.Element, privKey *pbc.Element) *pbc.Element {
	return bls.pairing.NewG1().PowZn(hash, privKey)
}

func (bls *BLS) SignBytes(data []byte, privKey *pbc.Element) *pbc.Element {
	h := bls.HashBytes(data)
	return bls.Sign(h, privKey)
}

func (bls *BLS) SignHash(hash []byte, privKey *pbc.Element) *pbc.Element {
	h := bls.pairing.NewG1().SetFromHash(hash)
	return bls.Sign(h, privKey)
}

func (bls *BLS) SignString(text string, privKey *pbc.Element) *pbc.Element {
	h := bls.HashString(text)
	return bls.Sign(h, privKey)
}

func (bls *BLS) Verify(hash *pbc.Element, sig *pbc.Element, pubKey *pbc.Element) bool {
	temp1 := bls.PairHash(hash, pubKey)
	temp2 := bls.PairSig(sig)
	return temp1.Equals(temp2)
}

func (bls *BLS) VerifyPreprocessed(hash *pbc.Pairer, sig *pbc.Element, pubKey *pbc.Element) bool {
	temp1 := bls.pairing.NewGT().PairerPair(hash, pubKey)
	temp2 := bls.PairSig(sig)
	return temp1.Equals(temp2)
}

func (bls *BLS) PreprocessHash(hash []byte) *pbc.Pairer {
	h := bls.pairing.NewG1().SetFromHash(hash)
	return h.PreparePairer()
}

func (bls *BLS) VerifyBytes(data []byte, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := bls.HashBytes(data)
	return bls.Verify(h, sig, pubKey)
}

func (bls *BLS) VerifyHash(hash []byte, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := bls.pairing.NewG1().SetFromHash(hash)
	return bls.Verify(h, sig, pubKey)
}

func (bls *BLS) VerifyString(text string, sig *pbc.Element, pubKey *pbc.Element) bool {
	h := bls.HashString(text)
	return bls.Verify(h, sig, pubKey)
}

func (bls *BLS) AggSig(sig1 *pbc.Element, sig2 *pbc.Element) *pbc.Element {
	return bls.pairing.NewG1().Mul(sig1, sig2)
}

func (bls *BLS) AggKey(pubKey1 *pbc.Element, pubKey2 *pbc.Element) *pbc.Element {
	return bls.pairing.NewG2().Mul(pubKey1, pubKey2)
}

func (bls *BLS) AggPairedHash(pairedHash1 *pbc.Element, pairedHash2 *pbc.Element) *pbc.Element {
	return bls.pairing.NewGT().Mul(pairedHash1, pairedHash2)
}

func (bls *BLS) PairSig(sig *pbc.Element) *pbc.Element {
	return bls.pairing.NewGT().Pair(sig, bls.g)
}

func (bls *BLS) PairHash(hash *pbc.Element, pubKey *pbc.Element) *pbc.Element {
	return bls.pairing.NewGT().Pair(hash, pubKey)
}

func (bls *BLS) cloneSig(sig *pbc.Element) *pbc.Element {
	return bls.pairing.NewG1().Set(sig)
}
