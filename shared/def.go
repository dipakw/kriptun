package shared

import (
	"net"
	"time"
)

const (
	INVALID_PROTOCOL uint8 = iota + 1
	RESOLVE_FAILED
	MALFORMED_REQUEST

	CONN_OPENED
	CONN_EOF
	CONN_REFUSED
	CONN_RESET
	CONN_ERRORED

	// Read timeouts
	A_READ_TIMEOUT
	B_READ_TIMEOUT

	// Write timeouts
	A_WRITE_TIMEOUT
	B_WRITE_TIMEOUT

	// Connect timeouts
	A_CONNECT_TIMEOUT
	B_CONNECT_TIMEOUT
)

const (
	MAX_TARGET_SIZE = 1 + 8 + 1 + 255 + 2 + 2 + 2 + 2 + 2 + 2 + 2
)

type Addr struct {
	Net  string
	Addr string
}

type ReadConn struct {
	Conn    net.Conn
	Buf     []byte
	Timeout time.Duration
	Full    bool

	n   int
	err error
}

type Target struct {
	Net  string
	Host string
	Port uint16
	RToA uint16
	RToB uint16
	WToA uint16
	WToB uint16
	CToA uint16
	CToB uint16
}
