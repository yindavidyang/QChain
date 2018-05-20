package main

import "crypto/sha256"

const (
	LenHash        = sha256.Size
	LenSig         = 128
	LenAggSig      = numPeers*4 + LenSig
	LenMsgType     = 1
)
