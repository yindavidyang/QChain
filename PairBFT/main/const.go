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
	lenCounter = 4
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
	NounceCommit        = "Commit Nounce"
	NouncePrepare       = "Prepare Nounce"
	NounceCommitPrepare = "CommitPrepare Nounce"
	NouncePubKey        = "Public Key Nounce"
)
