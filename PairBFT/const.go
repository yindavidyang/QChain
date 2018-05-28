package PairBFT

import (
	"crypto/sha256"
	"github.com/sirupsen/logrus"
)

const (
	logLevel = logrus.DebugLevel
)

const (
	LenBlockHeight = 8
	LenHash        = sha256.Size
	lenCounter     = 4
	LenMsgType     = 1
)

const (
	MsgTypeUnknown       byte = iota
	MsgTypePrepare
	MsgTypeCommit
	MsgTypeCommitPrepare
	MsgTypeSyncRequest
	MsgTypeSyncResponse
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
	NonceCommit        = "Commit1831791051689911347319517648892253961232204362231776413310149115351165421519937"
	NoncePrepare       = "Prepare2441491481761971821351735919983126136878719861412001628783236206511298664521024082"
	NonceCommitPrepare = "CommitPrepare561102092383925104549199356790242961851017412821315924618619041207140122342062379"
	NoncePubKey        = "PublicKey184 294491111767962128176251109214135170276146201125206161342435891271641642430140"
)
