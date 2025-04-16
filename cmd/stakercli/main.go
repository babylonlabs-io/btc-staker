package main

import (
	"fmt"
	"os"

	cmdadmin "github.com/babylonlabs-io/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonlabs-io/btc-staker/cmd/stakercli/daemon"
	cmdpop "github.com/babylonlabs-io/btc-staker/cmd/stakercli/pop"
	cmdtx "github.com/babylonlabs-io/btc-staker/cmd/stakercli/transaction"
	"github.com/joho/godotenv"
	"github.com/urfave/cli"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[btc-staker] %v\n", err)
	os.Exit(1)
}

func main() {
	_ = godotenv.Load()

	app := cli.NewApp()
	app.Name = "stakercli"
	app.Usage = "Bitcoin staking controller"

	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, cmdtx.TransactionCommands...)
	app.Commands = append(app.Commands, cmdpop.PopCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
