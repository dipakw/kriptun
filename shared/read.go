package shared

import (
	"io"
	"time"
)

func Read(rc *ReadConn) *ReadConn {
	defer rc.Conn.SetReadDeadline(time.Time{})

	rc.Conn.SetReadDeadline(time.Now().Add(rc.Timeout))

	var err error
	var n int

	if rc.Full {
		n, err = io.ReadFull(rc.Conn, rc.Buf)
	} else {
		n, err = rc.Conn.Read(rc.Buf)
	}

	if err != nil {
		rc.err = err
		return rc
	}

	rc.n = n
	rc.err = err

	return rc
}

func (rc *ReadConn) Bytes() []byte {
	if rc.err != nil || rc.n == 0 {
		return nil
	}

	return rc.Buf[:rc.n]
}

func (rc *ReadConn) Err() error {
	return rc.err
}

func (rc *ReadConn) N() int {
	return rc.n
}
