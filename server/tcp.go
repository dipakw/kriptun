package server

import (
	"io"
	"kriptun/shared"
	"net"
	"strconv"
	"strings"
	"time"
)

func (s *Server) tcp(userID string, target *shared.Target, conn net.Conn) {
	// Dialing target
	bconn, err := net.DialTimeout(
		target.Net,
		net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))),
		time.Duration(target.CToB)*time.Second,
	)

	if err != nil {
		// Detecting conn timeout
		if e, ok := err.(net.Error); ok && e.Timeout() {
			s.conf.Log.Errf("Connection timed out: user: %s | error: %s", userID, err.Error())
			conn.Write([]byte{shared.B_CONNECT_TIMEOUT})
			return
		}

		// Check if name resolution failed
		if strings.Contains(err.Error(), "no such host") {
			s.conf.Log.Errf("Name resolution failed: user: %s | error: %s", userID, err.Error())
			conn.Write([]byte{shared.RESOLVE_FAILED})
			return
		}

		// Check if connection refused
		if strings.Contains(err.Error(), "connection refused") {
			s.conf.Log.Errf("Connection refused: user: %s | error: %s", userID, err.Error())
			conn.Write([]byte{shared.CONN_REFUSED})
			return
		}

		// Check if connection reset
		if strings.Contains(err.Error(), "connection reset by peer") {
			s.conf.Log.Errf("Connection reset by peer: user: %s | error: %s", userID, err.Error())
			conn.Write([]byte{shared.CONN_RESET})
			return
		}

		// Send connection error
		s.conf.Log.Errf("Connection error: user: %s | error: %s", userID, err.Error())
		conn.Write([]byte{shared.CONN_ERRORED})
		return
	}

	if _, err := conn.Write([]byte{shared.CONN_OPENED}); err != nil {
		s.conf.Log.Errf("Failed to write conn opened: user: %s | error: %s", userID, err.Error())
		return
	}

	err = relayTCP(s.ctx, &RelayOptsTCP{
		Src:  conn,
		Dst:  bconn,
		RToS: target.RToA,
		WToS: target.WToA,
		RToD: target.RToB,
		WToD: target.WToB,

		// Report: func(sr uint8, dw uint8, n int) {
		// 	s.conf.Log.Inff("Report: user: %s | sr: %d | dw: %d | n: %d", userID, sr, dw, n)
		// },
	})

	if err != nil && err != io.EOF {
		s.conf.Log.Errf("Failed to relay: user: %s | error: %s", userID, err.Error())
		return
	}
}
