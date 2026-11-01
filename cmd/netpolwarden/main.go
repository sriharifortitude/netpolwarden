// Command netpolwarden works out who can reach whom under Kubernetes NetworkPolicies.
package main

import (
	"os"

	"github.com/sriharifortitude/netpolwarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
