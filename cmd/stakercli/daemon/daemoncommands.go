// Package daemon exposes CLI commands that talk to the running staker daemon.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/urfave/cli"

	"github.com/babylonlabs-io/btc-staker/cmd"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	dc "github.com/babylonlabs-io/btc-staker/stakerservice/client"
)

// DaemonCommands is the set of stakercli commands that require a running daemon.
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
			stakeMultisigCmd,
			stakeExpansionCmd,
			stakeExpansionMultisigCmd,
			consolidateUtxosCmd,
			unstakeCmd,
			unstakeMultisigCmd,
			stakingDetailsCmd,
			listStakingTransactionsCmd,
			withdrawableTransactionsCmd,
			unbondCmd,
			unbondMultisigCmd,
			stakeFromPhase1Cmd,
		},
	},
}

const (
	offsetFlag                 = "offset"
	limitFlag                  = "limit"
	fpPksFlag                  = "finality-providers-pks"
	stakingTransactionHashFlag = "staking-transaction-hash"
	stakerAddressFlag          = "staker-address"
	fundingAddressFlag         = "funding-address"
	targetAmountFlag           = "target-amount"
)

var checkDaemonHealthCmd = cli.Command{
	Name:      "check-health",
	ShortName: "ch",
	Usage:     "Check if staker daemon is running.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
	},
	Action: stake,
}

var stakeMultisigCmd = cli.Command{
	Name:      "stake-multisig",
	ShortName: "stm",
	Usage:     "Stake an amount of BTC to Babylon using multisig staker keys loaded in stakerd",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name: fundingAddressFlag,
			// TODO: should we merge funding address and the staker address into one for multisig?
			Usage:    "BTC funding/change address (must be controlled by the wallet configured in stakerd)",
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
	},
	Action: stakeMultisig,
}

var stakeExpansionCmd = cli.Command{
	Name:      "stake-expand",
	ShortName: "stxp",
	Usage:     "Stakes an amount of BTC to Babylon and uses a previous active BTC staking tx as input",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of previous staking transaction in bitcoin hex format which is currently an active BTC delegation",
			Required: true,
		},
	},
	Action: stakeExpand,
}

var stakeExpansionMultisigCmd = cli.Command{
	Name:      "stake-expand-multisig",
	ShortName: "stxpm",
	Usage:     "Stakes an amount of BTC to Babylon using multisig staker keys and a previous active BTC staking tx as input",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     fundingAddressFlag,
			Usage:    "BTC funding/change address (must be controlled by the wallet configured in stakerd)",
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
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of previous staking transaction in bitcoin hex format which is currently an active BTC delegation",
			Required: true,
		},
	},
	Action: stakeExpandMultisig,
}

var consolidateUtxosCmd = cli.Command{
	Name:      "consolidate-utxos",
	ShortName: "cu",
	Usage:     "Consolidate small UTXOs into a single larger UTXO",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakerAddressFlag,
			Usage:    "BTC address of the staker in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     targetAmountFlag,
			Usage:    "Target amount in satoshis for the consolidated UTXO",
			Required: true,
		},
	},
	Action: consolidateUtxos,
}

var stakeFromPhase1Cmd = cli.Command{
	Name:      "stake-from-phase1",
	ShortName: "stfp1",
	Usage: "\nstakercli daemon stake-from-phase1" +
		" --staking-transaction-hash [txHashHex] --staker-address [btcStakerAddrHex] --tx-inclusion-height [blockHeightTxInclusion]",
	Description: "Creates a Babylon BTC delegation transaction from the Phase1 BTC staking transaction",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.TxInclusionHeightFlag,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unstake,
}

var unstakeMultisigCmd = cli.Command{
	Name:      "unstake-multisig",
	ShortName: "ustm",
	Usage:     "Spends staking transaction using multisig staker keys configured in stakerd; sends funds back to the funding/change address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unstakeMultisig,
}

var unbondCmd = cli.Command{
	Name:      "unbond",
	ShortName: "ubd",
	Usage:     "initiates unbonding flow: build unbonding tx, send to babylon, wait for signatures, and send unbonding tx to bitcoin",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unbond,
}

var unbondMultisigCmd = cli.Command{
	Name:      "unbond-multisig",
	ShortName: "ubdm",
	Usage:     "initiates unbonding flow using multisig staker keys",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unbondMultisig,
}

var stakingDetailsCmd = cli.Command{
	Name:      "staking-details",
	ShortName: "sds",
	Usage:     "Displays details of staking transaction with given hash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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
			Name:  helpers.StakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: helpers.DefaultStakingDaemonAddress,
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

// checkHealth checks if staker daemon is running.
func checkHealth(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	health, err := client.Health(sctx)

	if err != nil {
		return fmt.Errorf("failed to check health: %w", err)
	}

	helpers.PrintRespJSON(health)

	return nil
}

// listOutputs lists current unspent outputs in connected wallet.
func listOutputs(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	outputs, err := client.ListOutputs(sctx)

	if err != nil {
		return fmt.Errorf("failed to list outputs: %w", err)
	}

	helpers.PrintRespJSON(outputs)

	return nil
}

// babylonFinalityProviders lists current finality providers.
func babylonFinalityProviders(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
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
		return fmt.Errorf("failed to get finality providers: %w", err)
	}

	helpers.PrintRespJSON(finalityProviders)

	return nil
}

// stake stakes a BTC.
func stake(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingAmount := ctx.Int64(helpers.StakingAmountFlag)
	fpPks := ctx.StringSlice(fpPksFlag)
	stakingTimeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)

	results, err := client.Stake(sctx, stakerAddress, stakingAmount, fpPks, stakingTimeBlocks)
	if err != nil {
		return fmt.Errorf("failed to stake: %w", err)
	}

	helpers.PrintRespJSON(results)

	return nil
}

func stakeMultisig(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	fundingAddress := ctx.String(fundingAddressFlag)
	stakingAmount := ctx.Int64(helpers.StakingAmountFlag)
	fpPks := ctx.StringSlice(fpPksFlag)
	stakingTimeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)

	results, err := client.StakeMultisig(sctx, fundingAddress, stakingAmount, fpPks, stakingTimeBlocks)
	if err != nil {
		return fmt.Errorf("failed to stake multisig: %w", err)
	}

	helpers.PrintRespJSON(results)

	return nil
}

// stakeExpand creates a new btc staking transaction from an previous
// active BTC staking delegation and another new input.
func stakeExpand(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingAmount := ctx.Int64(helpers.StakingAmountFlag)
	fpPks := ctx.StringSlice(fpPksFlag)
	stakingTimeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)

	prevActiveStkTxHashHex := ctx.String(stakingTransactionHashFlag)
	if len(prevActiveStkTxHashHex) == 0 {
		return errors.New("previous active staking tx hash hex for stake expansion is empty")
	}

	results, err := client.StakeExpand(sctx, stakerAddress, stakingAmount, fpPks, stakingTimeBlocks, prevActiveStkTxHashHex)
	if err != nil {
		return fmt.Errorf("failed to stake expand: %w", err)
	}

	helpers.PrintRespJSON(results)

	return nil
}

// stakeExpandMultisig creates a new btc staking transaction from an previous
// active BTC staking delegation and another new input by using multisig staker keys
func stakeExpandMultisig(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	fundingAddress := ctx.String(fundingAddressFlag)
	stakingAmount := ctx.Int64(helpers.StakingAmountFlag)
	fpPks := ctx.StringSlice(fpPksFlag)
	stakingTimeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)
	prevActiveStkTxHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.StakeExpandMultisig(sctx, fundingAddress, stakingAmount, fpPks, stakingTimeBlocks, prevActiveStkTxHash)
	if err != nil {
		return fmt.Errorf("failed to stake expand (multisig): %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// consolidateUtxos consolidates small UTXOs into a single larger UTXO
func consolidateUtxos(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakerAddress := ctx.String(stakerAddressFlag)
	targetAmount := ctx.Int64(targetAmountFlag)

	result, err := client.ConsolidateUTXOs(sctx, stakerAddress, targetAmount)
	if err != nil {
		return fmt.Errorf("failed to consolidate UTXOs: %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// stakeFromPhase1TxBTC delegates a staking transaction from a phase 1 tx BTC.
func stakeFromPhase1TxBTC(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()
	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)
	if len(stakingTransactionHash) == 0 {
		return errors.New("staking tx hash hex is empty")
	}

	blockHeighTxInclusion := ctx.Uint64(helpers.TxInclusionHeightFlag)
	if blockHeighTxInclusion == 0 {
		resp, err := client.BtcTxDetails(sctx, stakingTransactionHash)
		if err != nil {
			return fmt.Errorf("error to get btc tx and block data from staking tx %s: %w", stakingTransactionHash, err)
		}

		blockHeighTxInclusion = uint64(resp.Blk.Height)
	}

	respParamsByHeight, err := client.BtcStakingParamByBtcHeight(sctx, uint32(blockHeighTxInclusion))
	if err != nil {
		return fmt.Errorf("failed to get btc staking parameters: %w", err)
	}
	btcStakingParams := respParamsByHeight.StakingParams

	stakerAddress := ctx.String(stakerAddressFlag)
	_, err = client.BtcDelegationFromBtcStakingTx(sctx, stakerAddress, stakingTransactionHash, btcStakingParams.CovenantPkHex, btcStakingParams.CovenantQuorum)
	if err != nil {
		return fmt.Errorf("failed to delegate from btc staking tx: %w", err)
	}
	return nil
}

func unstake(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.SpendStakingTransaction(sctx, stakingTransactionHash)
	if err != nil {
		return fmt.Errorf("failed to spend staking transaction: %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

func unstakeMultisig(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.SpendStakingTransactionMultisig(sctx, stakingTransactionHash)
	if err != nil {
		return fmt.Errorf("failed to spend staking transaction (multisig): %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// unbond unbonds a staking transaction.
func unbond(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.UnbondStaking(sctx, stakingTransactionHash)
	if err != nil {
		return fmt.Errorf("failed to unbond staking: %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// unbondMultisig unbonds a staking transaction using multisig staker keys.
func unbondMultisig(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.UnbondStakingMultisig(sctx, stakingTransactionHash)
	if err != nil {
		return fmt.Errorf("failed to unbond staking (multisig): %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// stakingDetails gets the details of a staking transaction.
func stakingDetails(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.StakingDetails(sctx, stakingTransactionHash)
	if err != nil {
		return fmt.Errorf("failed to get staking details: %w", err)
	}

	helpers.PrintRespJSON(result)

	return nil
}

// listStakingTransactions lists all the staking transactions.
func listStakingTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
	if err != nil {
		return fmt.Errorf("failed to create staker service JSON-RPC client: %w", err)
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
		return fmt.Errorf("failed to get staking transactions: %w", err)
	}

	helpers.PrintRespJSON(transactions)

	return nil
}

// withdrawableTransactions lists all the withdrawable staking transactions.
func withdrawableTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(helpers.StakingDaemonAddressFlag)
	client, err := NewStakerServiceJSONRPCClient(daemonAddress)
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

// NewStakerServiceJSONRPCClient creates a client connection with basic auth
// The username and password are loaded from environment variables
func NewStakerServiceJSONRPCClient(remoteAddressWithoutAuth string) (*dc.StakerServiceJSONRPCClient, error) {
	parsedURL, err := url.Parse(remoteAddressWithoutAuth)
	if err != nil {
		return nil, err
	}

	user, pwd, err := cmd.GetEnvBasicAuth()
	if err != nil {
		return nil, err
	}
	parsedURL.User = url.UserPassword(user, pwd)

	return dc.NewStakerServiceJSONRPCClient(parsedURL.String())
}
