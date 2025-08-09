package client

import (
	"fmt"
	"kriptun/auth"
	"kriptun/shared"
	"net"
	"time"

	"github.com/dipakw/uconn"
)

func New(conf *Config) (*Client, error) {
	c := &Client{
		conf: conf,
	}

	return c, nil
}

func (c *Client) Dial(t *shared.Target) (net.Conn, error) {
	conn, err := net.Dial(c.conf.Server.Net, c.conf.Server.Addr)

	if err != nil {
		return nil, err
	}

	authUser := auth.Client(conn, &auth.ClientOpts{
		Bits:    768,
		ID:      []byte(c.conf.Username),
		Timeout: 5 * time.Second,

		SignMsg: func(msg []byte) ([]byte, error) {
			return shared.Hamc([]byte(c.conf.Password), msg)
		},
	})

	if !authUser.Ok() {
		return nil, authUser.Err().Main()
	}

	conn, err = uconn.New(conn, &uconn.Opts{
		Algo: uconn.ALGO_AES256_GCM,
		Key:  authUser.Key,
	})

	if err != nil {
		return nil, err
	}

	buf, err := t.Pack()

	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	buf = make([]byte, 1)

	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}

	if buf[0] != shared.CONN_OPENED {
		return nil, fmt.Errorf("connection not opened: %d", buf[0])
	}

	return conn, nil
}
