package main

import (
	"os"

	"github.com/nickylogan/go-blockchainz/cli"
)

func main() {
	defer os.Exit(0)

	cmd := cli.CommandLine{}
	cmd.Run()
}
