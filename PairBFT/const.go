package PairBFT

import (
	"crypto/sha256"
	"github.com/sirupsen/logrus"
)

const (
	logLevel     = logrus.DebugLevel
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