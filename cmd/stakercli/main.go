package main

import (
	"fmt"
	"os"

	cmdadmin "github.com/babylonlabs-io/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonlabs-io/btc-staker/cmd/stakercli/daemon"
	cmdpop "github.com/babylonlabs-io/btc-staker/cmd/stakercli/pop"
	cmdtx "github.com/babylonlabs-io/btc-staker/cmd/stakercli/transaction"
	"github.com/urfave/cli"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[btc-staker] %v\n", err)
	os.Exit(1)
}

const (
	btcNetworkFlag          = "btc-network"
	btcWalletHostFlag       = "btc-wallet-host"
	btcWalletRPCUserFlag    = "btc-wallet-rpc-user"
	btcWalletRPCPassFlag    = "btc-wallet-rpc-pass"
	btcWalletPassphraseFlag = "btc-wallet-passphrase"
)

func main() {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Usage = "Bitcoin staking controller"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  btcWalletHostFlag,
			Usage: "Bitcoin wallet rpc host",
			Value: "127.0.0.1:18554",
		},
		cli.StringFlag{
			Name:  btcWalletRPCUserFlag,
			Usage: "Bitcoin wallet rpc user",
			Value: "user",
		},
		cli.StringFlag{
			Name:  btcWalletRPCPassFlag,
			Usage: "Bitcoin wallet rpc password",
			Value: "pass",
		},
		cli.StringFlag{
			Name:  btcWalletPassphraseFlag,
			Usage: "Bitcoin wallet passphrase",
		},
	}

	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, cmdtx.TransactionCommands...)
	app.Commands = append(app.Commands, cmdpop.PopCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
