package server

import (
	"context"
	"kriptun/auth"
	"kriptun/shared"
	"net"
	"sync"

	"github.com/dipakw/logs"
)

type Config struct {
	Bind *shared.Addr
	Log  logs.Log

	PwFN    func(id string) ([]byte, error)
	ProtoFN func(id string, proto string) bool
}

type Server struct {
	conf     *Config
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
	wg       sync.WaitGroup
}

type User struct {
	id    string
	mu    sync.RWMutex
	auths []*auth.Auth
}
