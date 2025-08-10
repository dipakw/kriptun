package app

import (
	"fmt"
	"os"
	"strings"
)

var cli_doc = strings.TrimSpace(`
Usage:
  kriptun <command> [options]

Commands:
  version, v   Show version
  start, s     Start the server (default)
  help, h      Show this help message

Options:
  --host, -h    Server host (default: ::)
  --port, -p    Server port (default: 14000)

Notes:
  - All options can use either --long or -short forms.
`)

var parseArgs = map[string]bool{
	"--host": true,
	"--port": true,
}

var parseArgsShort = map[string]bool{
	"-h": true,
	"-p": true,
}

var mapShortToLong = map[string]string{
	"-h": "--host",
	"-p": "--port",
}

func NewCli(defaultOpts map[string]string) *Cli {
	args := os.Args[1:]

	main := ""
	opts := map[string]*ValName{}

	if len(args) > 0 {
		main = args[0]

		for i := 1; i < len(args); i++ {
			parts := strings.SplitN(args[i], "=", 2)
			key := parts[0]
			val := ""

			if !parseArgs[key] && !parseArgsShort[key] {
				continue
			}

			if len(parts) == 2 {
				val = parts[1]
			}

			optKey := key

			if parseArgsShort[key] {
				optKey = mapShortToLong[key]
			}

			opts[optKey[2:]] = &ValName{
				Val:  val,
				Name: key,
			}
		}
	}

	return &Cli{
		main:        main,
		opts:        opts,
		defaultOpts: defaultOpts,
	}
}

func (c *Cli) Help(message string) {
	if message != "" {
		fmt.Println(message)
		fmt.Println()
	}

	fmt.Println(cli_doc)
}

func (c *Cli) Get(key string) *CliArg {
	val := ""
	name := "--" + key

	input, passed := c.opts[key]

	if passed {
		name = input.Name
		val = input.Val
	}

	return &CliArg{
		Passed:  passed,
		Input:   val,
		Default: c.defaultOpts[key],
		Name:    name,
	}
}

func (c *Cli) Gets(keys ...string) map[string]*CliArg {
	args := map[string]*CliArg{}

	for _, key := range keys {
		args[key] = c.Get(key)
	}

	return args
}

func (c *CliArg) Value() string {
	if c.Passed && c.Input != "" {
		return c.Input
	}

	return c.Default
}
