package PairBFT

import (
	"testing"
	"github.com/Nik-U/pbc"
)

// Aggregate signature: Alice and Bob sign the same text
func TestBLSAggregate(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	alicePrivKey, alicePubKey := bls.GenKey()
	bobPrivKey, bobPubKey := bls.GenKey()

	message := "some text to sign by both Alice and Bob"
	hash := bls.HashString(message)

	aliceSig := bls.Sign(hash, alicePrivKey)
	bobSig := bls.Sign(hash, bobPrivKey)

	aggSig := bls.AggSig(aliceSig, bobSig)
	aggKey := bls.AggKey(alicePubKey, bobPubKey)

	if ok := bls.Verify(hash, aggSig, aggKey); !ok {
		t.Error("Aggregate signature check failed.")
	}
}

// Aggregate signature: Alice and Bob sign different texts
func TestBLSAggregateAdvanced(t *testing.T) {
	bls := &BLS{}
	bls.Init()

	alicePrivKey, alicePubKey := bls.GenKey()
	bobPrivKey, bobPubKey := bls.GenKey()

	aliceMsg := "some text to sign by Alice"
	bobMsg := "some text to sign by Bob"
	aliceHash := bls.HashString(aliceMsg)
	bobHash := bls.HashString(bobMsg)

	aliceSig := bls.Sign(aliceHash, alicePrivKey)
	bobSig := bls.Sign(bobHash, bobPrivKey)

	aggSig := bls.AggSig(aliceSig, bobSig)

	aggPairSig := bls.PairSig(aggSig)
	aggPairHash := bls.AggPairedHash(bls.PairHash(aliceHash, alicePubKey), bls.PairHash(bobHash, bobPubKey))

	if !aggPairHash.Equals(aggPairSig) {
		t.Error("Aggregate signature check failed.")
	}
}

func TestTemp1(t *testing.T) {
	bls := &BLS{}
	pairing, err := pbc.NewPairingFromString("type a\nq 14255759452639307747360153296102950097185643642557958736505085125768588700181548014943655760582420667819109497042378880810655425413635876266394044272557923\nh 9754186439827859727359616674335773951552816794888290482843940922454506422457865588951007462960529245126812\nr 1461501637330902918201208952637712259106134294527\nexp2 160\nexp1 91\nsign1 -1\nsign0 -1\n")
	bls.pairing = pairing
	if err != nil {
		t.Fail()
	}
	bls.g = pairing.NewG2()
	_, ok := bls.g.SetString("[10467352847911607598050049190975136090444027587047940907873094216858474140927391844829692354113031289472189241991241578406091114631824835025428953723870372, 6650146029439536739472091218841247672678916506746637963424081676476684621488134906197662252773496841568565444649104687212784228280065853189171854929344369]", 10)
	if !ok {
		t.Fail()
	}
	hash := []byte{101, 29, 98, 156, 89, 208, 118, 231, 239, 255, 164, 72, 58, 111, 209, 242, 178, 176, 46, 113, 34, 47, 82, 166, 75, 187, 144, 73, 193, 168, 72, 74}
	sig, ok := pairing.NewG1().SetString("[2585304474702287808962058926803426073580107388068955913556585699918641373456691842340798958277226967794192540068265834986478655475085089597805755852260170, 2421009350094661465352660846420880506148694327446478879229472893148795569958785153332446307933089053342528796910891480891495324252776716718779714822363927]", 10)
	if !ok {
		t.Fail()
	}
	pubKey, ok := pairing.NewG2().SetString("[7074136223250544235178829215882176210752428730601570473068972564898746023249359311358740717250440184496344828079194047301709185144068866230036186572033269, 10871185960701226893145854007839623292604299534396819649098091858136470794116146772679208072839906893873751775013515470614844583447843206428014295040079887]", 10)
	if !ok {
		t.Fail()
	}
	ok = bls.VerifyHash(hash, sig, pubKey)
	if ok {
		t.Fail()
	}
}
