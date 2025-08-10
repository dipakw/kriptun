package server

import (
	"io"
	"kriptun/shared"
	"net"
	"strconv"
)

func (s *Server) udp(userID string, target *shared.Target, conn net.Conn) {
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))

	if err != nil {
		s.conf.Log.Errf("Failed to resolve UDP address: user: %s | error: %s", userID, err.Error())
		conn.Write([]byte{shared.RESOLVE_FAILED})
		return
	}

	if _, err := conn.Write([]byte{shared.CONN_OPENED}); err != nil {
		s.conf.Log.Errf("Failed to write conn opened: user: %s | error: %s", userID, err.Error())
		return
	}

	udpConn, err := net.DialUDP("udp", nil, remoteAddr)

	if err != nil {
		s.conf.Log.Errf("Failed to dial UDP: user: %s | error: %s", userID, err.Error())
		conn.Write([]byte{shared.CONN_ERRORED})
		return
	}

	err = relayUDP(s.ctx, &RelayOptsUDP{
		Src:  conn,
		Dst:  udpConn,
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
