package auth

import (
	"crypto/mlkem"
	"time"
)

const (
	CHALLENGE_SIZE = 40
)

var ENCAP_KEY_SIZES = map[uint16]int{
	768:  mlkem.EncapsulationKeySize768,
	1024: mlkem.EncapsulationKeySize1024,
}

var CIPHERTEXT_SIZES = map[uint16]int{
	768:  mlkem.CiphertextSize768,
	1024: mlkem.CiphertextSize1024,
}

type Auth struct {
	ID   []byte
	Meta map[string]string
	Key  []byte

	time time.Time
	err  *Err
}

type Err struct {
	reason string
	err    error
}

type ServerOpts struct {
	Bits          uint16
	Timeout       time.Duration
	MaxSigSize    uint16
	MinSigSize    uint16
	MinIdMetaSize uint16
	MaxIdMetaSize uint16
	DelayOnAuth   time.Duration
	VerifySig     func(auth *Auth, msg []byte, sig []byte) (bool, error)
}

type ClientOpts struct {
	Bits    uint16
	ID      []byte
	Meta    map[string]string
	Timeout time.Duration
	SignMsg func(msg []byte) ([]byte, error)
}

type readopts struct {
	full    bool
	timeout time.Duration
}
