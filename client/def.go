package client

import (
	"kriptun/shared"

	"github.com/dipakw/logs"
)

type Config struct {
	Server   *shared.Addr
	Log      logs.Log
	Username string
	Password string
}

type Client struct {
	conf *Config
}
