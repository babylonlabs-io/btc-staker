package main

import (
	"fmt"
	"os"

	cmdadmin "github.com/babylonlabs-io/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonlabs-io/btc-staker/cmd/stakercli/daemon"
	cmdtx "github.com/babylonlabs-io/btc-staker/cmd/stakercli/transaction"
	"github.com/urfave/cli"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[btc-staker] %v\n", err)
	os.Exit(1)
}

func main() {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Usage = "Bitcoin staking controller"

	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, cmdtx.TransactionCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
