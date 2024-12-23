package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	dc "github.com/babylonlabs-io/btc-staker/stakerservice/client"
	"github.com/babylonlabs-io/networks/parameters/parser"
	"github.com/cometbft/cometbft/libs/os"
	"github.com/urfave/cli"
)

var DaemonCommands = []cli.Command{
	{
		Name:      "daemon",
		ShortName: "dn",
		Usage:     "More advanced commands which require staker daemon to be running.",
		Category:  "Daemon commands",
		Subcommands: []cli.Command{
			checkDaemonHealthCmd,
			listOutputsCmd,
			babylonFinalityProvidersCmd,
			stakeCmd,
			unstakeCmd,
			stakingDetailsCmd,
			listStakingTransactionsCmd,
			withdrawableTransactionsCmd,
			unbondCmd,
			stakeFromPhase1Cmd,
		},
	},
}

const (
	stakingDaemonAddressFlag   = "daemon-address"
	offsetFlag                 = "offset"
	limitFlag                  = "limit"
	fpPksFlag                  = "finality-providers-pks"
	stakingTransactionHashFlag = "staking-transaction-hash"
	stakerAddressFlag          = "staker-address"
	txInclusionHeightFlag      = "tx-inclusion-height"
)

var (
	defaultStakingDaemonAddress = "tcp://127.0.0.1:" + strconv.Itoa(scfg.DefaultRPCPort)
)

var checkDaemonHealthCmd = cli.Command{
	Name:      "check-health",
	ShortName: "ch",
	Usage:     "Check if staker daemon is running.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: checkHealth,
}

var listOutputsCmd = cli.Command{
	Name:      "list-outputs",
	ShortName: "lo",
	Usage:     "List unspent outputs in connected wallet.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: listOutputs,
}

var babylonFinalityProvidersCmd = cli.Command{
	Name:      "babylon-finality-providers",
	ShortName: "bfp",
	Usage:     "List current BTC finality providers on Babylon chain",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first finality provider to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of finality providers to return",
			Value: 100,
		},
	},
	Action: babylonFinalityProviders,
}

var stakeCmd = cli.Command{
	Name:      "stake",
	ShortName: "st",
	Usage:     "Stake an amount of BTC to Babylon",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakerAddressFlag,
			Usage:    "BTC address of the staker in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     fpPksFlag,
			Usage:    "BTC public keys of the finality providers in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingTimeBlocksFlag,
			Usage:    "Staking time in BTC blocks",
			Required: true,
		},
		cli.BoolFlag{
			Name:  helpers.SendToBabylonFirstFlag,
			Usage: "Whether staking transaction should be first to Babylon or BTC",
		},
	},
	Action: stake,
}

var stakeFromPhase1Cmd = cli.Command{
	Name:      "stake-from-phase1",
	ShortName: "stfp1",
	Usage: "\nstakercli daemon stake-from-phase1 [fullpath/to/global_parameters.json]" +
		" --staking-transaction-hash [txHashHex] --staker-address [btcStakerAddrHex] --tx-inclusion-height [blockHeightTxInclusion]",
	Description: "Creates a Babylon BTC delegation transaction from the Phase1 BTC staking transaction",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
		cli.StringFlag{
			Name:     stakerAddressFlag,
			Usage:    "BTC address of the staker (bech32 format)",
			Required: true,
		},
		cli.Uint64Flag{
			Name:  txInclusionHeightFlag,
			Usage: "Expected BTC height at which transaction was included. This value is important to choose correct global parameters for transaction, if set doesn't query bitcoin to get the block height from txHash",
		},
	},
	Action: stakeFromPhase1TxBTC,
}

var unstakeCmd = cli.Command{
	Name:      "unstake",
	ShortName: "ust",
	Usage:     "Spends staking transaction and sends funds back to staker; this can only be done after timelock of staking transaction expires",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unstake,
}

var unbondCmd = cli.Command{
	Name:      "unbond",
	ShortName: "ubd",
	Usage:     "initiates unbonding flow: build unbonding tx, send to babylon, wait for signatures, and send unbonding tx to bitcoin",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unbond,
}

var stakingDetailsCmd = cli.Command{
	Name:      "staking-details",
	ShortName: "sds",
	Usage:     "Displays details of staking transaction with given hash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: stakingDetails,
}

var listStakingTransactionsCmd = cli.Command{
	Name:      "list-staking-transactions",
	ShortName: "lst",
	Usage:     "List current staking transactions in db",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first transactions to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of transactions to return",
			Value: 100,
		},
	},
	Action: listStakingTransactions,
}

var withdrawableTransactionsCmd = cli.Command{
	Name:      "withdrawable-transactions",
	ShortName: "wt",
	Usage:     "List current tranactions that can be withdrawn i.e funds can be transferred back to staker address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first transactions to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of transactions to return",
			Value: 100,
		},
	},
	Action: withdrawableTransactions,
}

func checkHealth(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	health, err := client.Health(sctx)

	if err != nil {
		return err
	}

	helpers.PrintRespJSON(health)

	return nil
}

func listOutputs(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	outputs, err := client.ListOutputs(sctx)

	if err != nil {
		return err
	}

	helpers.PrintRespJSON(outputs)

	return nil
}

func babylonFinalityProviders(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	finalityProviders, err := client.BabylonFinalityProviders(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	helpers.PrintRespJSON(finalityProviders)

	return nil
}

func stake(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingAmount := ctx.Int64(helpers.StakingAmountFlag)
	fpPks := ctx.StringSlice(fpPksFlag)
	stakingTimeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)
	sendToBabylonFirst := ctx.Bool(helpers.SendToBabylonFirstFlag)

	results, err := client.Stake(sctx, stakerAddress, stakingAmount, fpPks, stakingTimeBlocks, sendToBabylonFirst)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(results)

	return nil
}

func stakeFromPhase1TxBTC(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()
	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)
	if len(stakingTransactionHash) == 0 {
		return errors.New("staking tx hash hex is empty")
	}

	inputGlobalParamsFilePath := ctx.Args().First()
	if len(inputGlobalParamsFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputGlobalParamsFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputGlobalParamsFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputGlobalParamsFilePath)
	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputGlobalParamsFilePath, err)
	}

	blockHeighTxInclusion := ctx.Uint64(txInclusionHeightFlag)
	if blockHeighTxInclusion == 0 {
		resp, err := client.BtcTxDetails(sctx, stakingTransactionHash)
		if err != nil {
			return fmt.Errorf("error to get btc tx and block data from staking tx %s: %w", stakingTransactionHash, err)
		}

		blockHeighTxInclusion = uint64(resp.Blk.Height)
	}

	paramsForHeight := globalParams.GetVersionedGlobalParamsByHeight(blockHeighTxInclusion)
	if paramsForHeight == nil {
		return fmt.Errorf("error getting param version from global params %s with height %d", inputGlobalParamsFilePath, blockHeighTxInclusion)
	}

	stakerAddress := ctx.String(stakerAddressFlag)
	_, err = client.BtcDelegationFromBtcStakingTx(sctx, stakerAddress, stakingTransactionHash, paramsForHeight)
	return err
}

func unstake(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.SpendStakingTransaction(sctx, stakingTransactionHash)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(result)

	return nil
}

func unbond(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.UnbondStaking(sctx, stakingTransactionHash)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(result)

	return nil
}

func stakingDetails(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.StakingDetails(sctx, stakingTransactionHash)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(result)

	return nil
}

func listStakingTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	transactions, err := client.ListStakingTransactions(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	helpers.PrintRespJSON(transactions)

	return nil
}

func withdrawableTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	transactions, err := client.WithdrawableTransactions(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	helpers.PrintRespJSON(transactions)

	return nil
}
