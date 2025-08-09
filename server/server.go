package server

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/dipakw/logs"
)

func New(conf *Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		conf:     conf,
		ctx:      ctx,
		cancel:   cancel,
		listener: nil,
		wg:       sync.WaitGroup{},
	}

	return s, nil
}

func (s *Server) Start() error {
	var err error

	s.listener, err = net.Listen(s.conf.Bind.Net, s.conf.Bind.Addr)

	if err != nil {
		s.conf.Log.Mustf(logs.ERROR, logs.DTAG, "Failed to start server: %s", err.Error())
		return err
	}

	s.conf.Log.Mustf(logs.INFO, logs.DTAG, "Server running on: %s", s.Addr())

	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		defer s.listener.Close()

		for {
			conn, err := s.listener.Accept()

			if err != nil {
				if err != io.EOF {
					s.conf.Log.Err("Failed to accept:", err.Error())
				}

				return
			}

			go s.handle(conn)
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	s.cancel()
	return s.listener.Close()
}

func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) Addr() string {
	return s.conf.Bind.Addr
}
