package app

import (
	"kriptun/server"
	"kriptun/shared"
	"os"

	"github.com/dipakw/logs"
)

func runServer(network, addr string) (*server.Server, error) {
	logger := logs.New(&logs.Config{
		Allow: logs.ALL,
		Outs: []*logs.Out{
			{
				Target: os.Stdout,
				Color:  true,
			},
		},
	})

	return server.New(&server.Config{
		Log: logger,

		Bind: &shared.Addr{
			Net:  network,
			Addr: addr,
		},

		PwFN: func(id string) ([]byte, error) {
			return []byte("password"), nil
		},

		ProtoFN: func(id string, proto string) bool {
			return proto == "tcp" || proto == "udp"
		},
	})
}
