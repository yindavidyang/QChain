package main

import "crypto/sha256"

const (
	CommitNounce = "Commit Nounce"
)

const (
	LenBlockID = 4
	LenHash    = sha256.Size
	LenSig     = 128
	LenAggSig  = numValidators*4 + LenSig
	LenMsgType = 1
)

const (
	MsgTypeUnknown       byte = iota
	MsgTypePrepare
	MsgTypeCommit
	MsgTypeCommitPrepare
)

const (
	StateIdle              = iota
	StatePrepared
	StateCommitted
	StateFinal
	StateCommittedPrepared
	StateFinalPrepared
)

const (
	MaxPacketSize = 4096
)
