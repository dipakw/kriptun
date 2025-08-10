package app

import (
	"fmt"
	"net"
	"os"
)

func Run(version string) {
	cmd := "start"

	cli := NewCli(map[string]string{
		"host": "::",
		"port": "8890",
	})

	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "start", "s":
		addr := net.JoinHostPort(cli.Get("host").Value(), cli.Get("port").Value())
		srv, err := runServer("tcp", addr)

		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		if srv.Start() == nil {
			srv.Wait()
		}

	case "version", "v":
		fmt.Printf("Version: %s\n", version)

	case "help", "h":
		cli.Help("")

	default:
		fmt.Println("Unknown command: " + cmd)
	}
}
