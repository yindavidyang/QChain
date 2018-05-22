package main

import (
	"crypto/sha256"
	"github.com/sirupsen/logrus"
	"time"
)

const (
	logLevel     = logrus.DebugLevel
	branchFactor = 2
	epoch        = time.Millisecond * 50
)

const (
	LenBlockID = 4
	LenHash    = sha256.Size
	LenSig     = 130 // setting this to 128 leads to occasional verification failures
	lenCounter = 4
	LenAggSig  = numVals*lenCounter + LenSig
	LenMsgType = 1
)

const (
	MsgTypeUnknown       byte = iota
	MsgTypePrepare
	MsgTypeCommit
	MsgTypeCommitPrepare
)

const (
	StateIdle           = iota
	StatePrepared
	StateCommitted
	StateFinal
	StateCommitPrepared
	StateFinalPrepared
)

const (
	MaxPacketSize = 4096
)

const (
	CommitNounce        = "Commit Nounce"
	PrepareNounce       = "Prepare Nounce"
	CommitPrepareNounce = "CommitPrepare Nounce"
	PubKeyNounce        = "Public Key Nounce"
)
