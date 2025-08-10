package app

import (
	"context"
	"sync"
)

type Cli struct {
	main        string
	opts        map[string]*ValName
	defaultOpts map[string]string
}

type CliArg struct {
	Passed  bool
	Input   string
	Default string
	Name    string
}

type ValName struct {
	Val  string
	Name string
}

type Config struct {
	Net  string
	Addr string
}

type Server struct {
	conf   *Config
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}
