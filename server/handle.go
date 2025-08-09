package server

import (
	"bytes"
	"kriptun/auth"
	"kriptun/shared"
	"net"
	"time"

	"github.com/dipakw/uconn"
)

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	authUser := auth.Server(conn, &auth.ServerOpts{
		Bits:          768,
		Timeout:       5 * time.Second,
		MinSigSize:    32,
		MaxSigSize:    32,
		MinIdMetaSize: 2,
		MaxIdMetaSize: 256,

		VerifySig: func(auth *auth.Auth, msg []byte, sig []byte) (bool, error) {
			pw, err := s.conf.PwFN(string(auth.ID))

			if err != nil {
				return false, err
			}

			hash, err := shared.Hamc(pw, msg)

			if err != nil {
				return false, err
			}

			return bytes.Equal(hash, sig), nil
		},
	})

	if !authUser.Ok() {
		s.conf.Log.Errf("Failed to authenticate: %s : %s : %s", conn.RemoteAddr().String(), authUser.Err().Main().Error(), authUser.Err().Reason())
		return
	}

	conn, err := uconn.New(conn, &uconn.Opts{
		Algo: uconn.ALGO_AES256_GCM,
		Key:  authUser.Key,
	})

	userID := string(authUser.ID)

	if err != nil {
		s.conf.Log.Errf("Failed to create uconn: user: %s | error: %s", userID, err.Error())
		return
	}

	s.connect(conn, userID)
}

func (s *Server) connect(conn net.Conn, userID string) {
	req := shared.Read(&shared.ReadConn{
		Conn:    conn,
		Buf:     make([]byte, shared.MAX_TARGET_SIZE),
		Timeout: 5 * time.Second,
		Full:    false,
	})

	if req.Err() != nil {
		s.conf.Log.Errf("Failed to read request: user: %s | error: %s", userID, req.Err().Error())
		return
	}

	target, err := (&shared.Target{}).Unpack(req.Bytes())

	if err != nil {
		s.conf.Log.Errf("Failed to unpack target: user: %s | error: %s", userID, err.Error())
		conn.Write([]byte{shared.MALFORMED_REQUEST})
		return
	}

	if !s.conf.ProtoFN(userID, target.Net) {
		s.conf.Log.Errf("Requested unsupported protocol: user: %s | protocol: %s", userID, target.Net)
		conn.Write([]byte{shared.INVALID_PROTOCOL})
		return
	}

	switch target.Net {
	case "tcp":
		s.tcp(userID, target, conn)
	case "udp":
		s.udp(userID, target, conn)
	default:
		s.conf.Log.Errf("Unsupported protocol: user: %s | protocol: %s", userID, target.Net)
		conn.Write([]byte{shared.INVALID_PROTOCOL})
		return
	}
}
