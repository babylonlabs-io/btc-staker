package transaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/babylonlabs-io/babylon/btcstaking"
	bbn "github.com/babylonlabs-io/babylon/types"
	"github.com/babylonlabs-io/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/libs/os"
	"github.com/urfave/cli"

	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonlabs-io/btc-staker/utils"
)

const (
	stakingTransactionFlag       = "staking-transaction"
	unbondingTransactionFlag     = "unbonding-transaction"
	networkNameFlag              = "network"
	stakerPublicKeyFlag          = "staker-pk"
	finalityProviderKeyFlag      = "finality-provider-pk"
	txInclusionHeightFlag        = "tx-inclusion-height"
	tagFlag                      = "tag"
	covenantMembersPksFlag       = "covenant-committee-pks"
	covenantQuorumFlag           = "covenant-quorum"
	minStakingAmountFlag         = "min-staking-amount"
	maxStakingAmountFlag         = "max-staking-amount"
	withdrawalAddressFlag        = "withdrawal-address"
	withdrawalTransactionFeeFlag = "withdrawal-fee"
)

var TransactionCommands = []cli.Command{
	{
		Name:      "transaction",
		ShortName: "tr",
		Usage:     "Commands related to Babylon BTC transactions Staking/Unbonding/Slashing",
		Category:  "transaction commands",
		Subcommands: []cli.Command{
			createPhase1StakingTransactionCmd,
			checkPhase1StakingTransactionCmd,
			checkPhase1StakingTransactionParamsCmd,
			createPhase1StakingTransactionWithParamsCmd,
			createPhase1UnbondingTransactionCmd,
			createPhase1WithdrawalTransactionCmd,
		},
	},
}

var checkPhase1StakingTransactionParamsCmd = cli.Command{
	Name:      "check-phase1-staking-transaction-params",
	ShortName: "cpstp",
	Usage:     "stakercli transaction check-phase1-staking-transaction-params [fullpath/to/parameters.json]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "Staking transaction in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
	Action: checkPhase1StakingTransactionParams,
}

type StakingTxData struct {
	StakerPublicKeyHex           string `json:"staker_public_key_hex"`
	FinalityProviderPublicKeyHex string `json:"finality_provider_public_key_hex"`
	StakingAmount                int64  `json:"staking_amount"`
	StakingTimeBlocks            int64  `json:"staking_time_blocks"`
}

type ValidityInfo struct {
	ParametersVersion uint64         `json:"parameters_version"`
	IsValid           bool           `json:"is_valid"`
	ErrMsg            string         `json:"err_msg,omitempty"`
	StakingData       *StakingTxData `json:"staking_data,omitempty"`
}

type CheckPhase1StakingTxResponse struct {
	ValidityInfo []*ValidityInfo `json:"validity_info"`
}

func validateTxAgainstParams(
	tx *wire.MsgTx,
	globalParams *parser.ParsedGlobalParams,
	net *chaincfg.Params) *CheckPhase1StakingTxResponse {
	var info []*ValidityInfo

	for i := len(globalParams.Versions) - 1; i >= 0; i-- {
		params := globalParams.Versions[i]

		parsed, err := btcstaking.ParseV0StakingTx(
			tx,
			params.Tag,
			params.CovenantPks,
			params.CovenantQuorum,
			net,
		)
		if err != nil {
			info = append(info, &ValidityInfo{
				ParametersVersion: params.Version,
				IsValid:           false,
				ErrMsg:            fmt.Sprintf("error parsing tx: %s", err.Error()),
			})
			continue
		}

		if parsed.OpReturnData.StakingTime < params.MinStakingTime || parsed.OpReturnData.StakingTime > params.MaxStakingTime {
			info = append(info, &ValidityInfo{
				ParametersVersion: params.Version,
				IsValid:           false,
				ErrMsg:            fmt.Sprintf("staking time %d is out of bounds", parsed.OpReturnData.StakingTime),
			})
			continue
		}

		if btcutil.Amount(parsed.StakingOutput.Value) < params.MinStakingAmount || btcutil.Amount(parsed.StakingOutput.Value) > params.MaxStakingAmount {
			info = append(info, &ValidityInfo{
				ParametersVersion: params.Version,
				IsValid:           false,
				ErrMsg:            fmt.Sprintf("staking amount %d is out of bounds", parsed.StakingOutput.Value),
			})
			continue
		}

		info = append(info, &ValidityInfo{
			ParametersVersion: params.Version,
			IsValid:           true,
			StakingData: &StakingTxData{
				StakerPublicKeyHex:           hex.EncodeToString(schnorr.SerializePubKey(parsed.OpReturnData.StakerPublicKey.PubKey)),
				FinalityProviderPublicKeyHex: hex.EncodeToString(schnorr.SerializePubKey(parsed.OpReturnData.FinalityProviderPublicKey.PubKey)),
				StakingAmount:                parsed.StakingOutput.Value,
				StakingTimeBlocks:            int64(parsed.OpReturnData.StakingTime),
			}})

		// We found latest valid version, no need to check further
		break
	}

	return &CheckPhase1StakingTxResponse{
		ValidityInfo: info,
	}
}

func checkPhase1StakingTransactionParams(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

	net := ctx.String(networkNameFlag)

	currentNetwork, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	stakingTx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}

	resp := validateTxAgainstParams(stakingTx, globalParams, currentNetwork)

	helpers.PrintRespJSON(resp)

	return nil
}

var createPhase1StakingTransactionCmd = cli.Command{
	Name:      "create-phase1-staking-transaction",
	ShortName: "crpst",
	Usage:     "Creates unsigned and unfunded phase 1 staking transaction",
	Description: "Creates unsigned and unfunded phase 1 staking transaction." +
		"This method does not validate tx against global parameters, and is dedicated " +
		"for advanced use cases. For most cases use safer `create-phase1-staking-transaction-with-params`",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakerPublicKeyFlag,
			Usage:    "Staker public key in Schnorr format (32 byte) in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     finalityProviderKeyFlag,
			Usage:    "Finality provider public key inSchnorr format (32 byte) in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingTimeBlocksFlag,
			Usage:    "Staking time in BTC blocks",
			Required: true,
		},
		cli.StringFlag{
			Name:     tagFlag,
			Usage:    "Tag in op_return output in hex",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     covenantMembersPksFlag,
			Usage:    "BTC public keys of the covenant committee members",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantQuorumFlag,
			Usage:    "Required quorum for the covenant members",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
	Action: createPhase1StakingTransaction,
}

func createPhase1StakingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakerPk, err := parseSchnorPubKeyFromCliCtx(ctx, stakerPublicKeyFlag)

	if err != nil {
		return err
	}

	fpPk, err := parseSchnorPubKeyFromCliCtx(ctx, finalityProviderKeyFlag)

	if err != nil {
		return err
	}

	stakingAmount, err := parseAmountFromCliCtx(ctx, helpers.StakingAmountFlag)

	if err != nil {
		return err
	}

	stakingTimeBlocks, err := parseLockTimeBlocksFromCliCtx(ctx, helpers.StakingTimeBlocksFlag)

	if err != nil {
		return err
	}

	tag, err := parseTagFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantMembersPks, err := parseCovenantKeysFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantQuorum, err := parseCovenantQuorumFromCliCtx(ctx)
	if err != nil {
		return err
	}

	_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		tag,
		stakerPk,
		fpPk,
		covenantMembersPks,
		covenantQuorum,
		stakingTimeBlocks,
		stakingAmount,
		currentParams,
	)
	if err != nil {
		return err
	}

	serializedTx, err := utils.SerializeBtcTransaction(tx)
	if err != nil {
		return err
	}

	resp := &CreatePhase1StakingTxResponse{
		StakingTxHex: hex.EncodeToString(serializedTx),
	}

	helpers.PrintRespJSON(*resp)
	return nil
}

var checkPhase1StakingTransactionCmd = cli.Command{
	Name:      "check-phase1-staking-transaction",
	ShortName: "cpst",
	Usage:     "Checks whether provided staking transactions is valid staking transaction (tx must be funded/have inputs)",
	Description: "Checks staking transaction against custom set of parameters. Use for custom transactions" +
		"that may not obey the global parameters. For most cases use `check-phase1-staking-transaction-params`",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "Staking transaction in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     tagFlag,
			Usage:    "Tag in op return output in hex",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     covenantMembersPksFlag,
			Usage:    "BTC public keys of the covenant committee members",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantQuorumFlag,
			Usage:    "Required quorum for the covenant members",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
		cli.StringFlag{
			Name:  stakerPublicKeyFlag,
			Usage: "Optional staker pub key hex to match the staker pub key in tx",
		},
		cli.StringFlag{
			Name:  finalityProviderKeyFlag,
			Usage: "Optional finality provider public key hex to match the finality provider public key in tx",
		},
		cli.Int64Flag{
			Name:  minStakingAmountFlag,
			Usage: "Optional minimum staking amount in satoshis to check if the amount spent in tx is higher than the flag",
		},
		cli.Int64Flag{
			Name:  maxStakingAmountFlag,
			Usage: "Optional maximum staking amount in satoshis to check if the amount spent in tx is lower than the flag",
		},
		cli.Int64Flag{
			Name:  helpers.StakingTimeBlocksFlag,
			Usage: "Optional staking time in BTC blocks to match how long it was locked for",
		},
	},
	Action: checkPhase1StakingTransaction,
}

func checkPhase1StakingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	tx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}
	tag, err := parseTagFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantMembersPks, err := parseCovenantKeysFromCliCtx(ctx)
	if err != nil {
		return err
	}

	covenantQuorum, err := parseCovenantQuorumFromCliCtx(ctx)
	if err != nil {
		return err
	}

	stakingTx, err := btcstaking.ParseV0StakingTx(
		tx,
		tag,
		covenantMembersPks,
		covenantQuorum,
		currentParams,
	)
	if err != nil {
		return err
	}

	// verify if optional flags match.
	stakerPk := ctx.String(stakerPublicKeyFlag)
	if len(stakerPk) > 0 {
		stakerPkFromTx := schnorr.SerializePubKey(stakingTx.OpReturnData.StakerPublicKey.PubKey)
		stakerPkHexFromTx := hex.EncodeToString(stakerPkFromTx)
		if !strings.EqualFold(stakerPk, stakerPkHexFromTx) {
			return fmt.Errorf("staker pk in tx %s do not match with flag %s", stakerPkHexFromTx, stakerPk)
		}
	}

	fpPk := ctx.String(finalityProviderKeyFlag)
	if len(fpPk) > 0 {
		fpPkFromTx := schnorr.SerializePubKey(stakingTx.OpReturnData.FinalityProviderPublicKey.PubKey)
		fpPkHexFromTx := hex.EncodeToString(fpPkFromTx)
		if !strings.EqualFold(fpPk, fpPkHexFromTx) {
			return fmt.Errorf("finality provider pk in tx %s do not match with flag %s", fpPkHexFromTx, fpPk)
		}
	}

	if ctx.Int64(helpers.StakingTimeBlocksFlag) != 0 {
		timeBlocks, err := parseLockTimeBlocksFromCliCtx(ctx, helpers.StakingTimeBlocksFlag)
		if err != nil {
			return err
		}
		if timeBlocks != stakingTx.OpReturnData.StakingTime {
			return fmt.Errorf("staking time in tx %d do not match with flag %d", stakingTx.OpReturnData.StakingTime, timeBlocks)
		}
	}

	txAmount := stakingTx.StakingOutput.Value
	minAmount := ctx.Int64(minStakingAmountFlag)
	if minAmount > 0 && txAmount < minAmount {
		return fmt.Errorf("staking amount in tx %d is less than the min-staking-amount in flag %d", txAmount, minAmount)
	}

	maxAmount := ctx.Int64(maxStakingAmountFlag)
	if maxAmount > 0 && txAmount > maxAmount {
		return fmt.Errorf("staking amount in tx %d is more than the max-staking-amount in flag %d", txAmount, maxAmount)
	}

	fmt.Println("Provided transaction is valid staking transaction!")
	return nil
}

var createPhase1StakingTransactionWithParamsCmd = cli.Command{
	Name:        "create-phase1-staking-transaction-with-params",
	ShortName:   "crpstp",
	Usage:       "stakercli transaction create-phase1-staking-transaction-with-params [fullpath/to/parameters.json]",
	Description: "Creates unsigned and unfunded phase 1 staking transaction. It also validates the transaction against provided global parameters",
	Action:      createPhase1StakingTransactionWithParams,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakerPublicKeyFlag,
			Usage:    "Staker public key in Schnorr format (32 byte) in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     finalityProviderKeyFlag,
			Usage:    "Finality provider public key in Schnorr format (32 byte) in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingTimeBlocksFlag,
			Usage:    "Staking time in BTC blocks",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     txInclusionHeightFlag,
			Usage:    "Expected BTC height at which transaction will be included. This value is important to choose correct global parameters for transaction",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
}

type CreatePhase1StakingTxResponse struct {
	StakingTxHex string `json:"staking_tx_hex"`
}

func createPhase1StakingTransactionWithParams(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	params, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

	currentNetwork, err := utils.GetBtcNetworkParams(ctx.String(networkNameFlag))

	if err != nil {
		return err
	}

	stakerPk, err := parseSchnorPubKeyFromCliCtx(ctx, stakerPublicKeyFlag)

	if err != nil {
		return err
	}

	fpPk, err := parseSchnorPubKeyFromCliCtx(ctx, finalityProviderKeyFlag)

	if err != nil {
		return err
	}

	stakingAmount, err := parseAmountFromCliCtx(ctx, helpers.StakingAmountFlag)

	if err != nil {
		return err
	}

	stakingTimeBlocks, err := parseLockTimeBlocksFromCliCtx(ctx, helpers.StakingTimeBlocksFlag)

	if err != nil {
		return err
	}

	expectedHeight := ctx.Uint64(txInclusionHeightFlag)

	resp, err := MakeCreatePhase1StakingTxResponse(
		stakerPk,
		fpPk,
		stakingTimeBlocks,
		stakingAmount,
		params,
		expectedHeight,
		currentNetwork,
	)

	if err != nil {
		return fmt.Errorf("error building staking tx: %w", err)
	}

	helpers.PrintRespJSON(*resp)
	return nil
}

// MakeCreatePhase1StakingTxResponse builds and serialize staking tx as hex response.
func MakeCreatePhase1StakingTxResponse(
	stakerPk *btcec.PublicKey,
	fpPk *btcec.PublicKey,
	stakingTimeBlocks uint16,
	stakingAmount btcutil.Amount,
	gp *parser.ParsedGlobalParams,
	expectedInclusionHeight uint64,
	net *chaincfg.Params,
) (*CreatePhase1StakingTxResponse, error) {
	params := gp.GetVersionedGlobalParamsByHeight(expectedInclusionHeight)

	if params == nil {
		return nil, fmt.Errorf("no global params found for height %d", expectedInclusionHeight)
	}

	if stakingTimeBlocks < params.MinStakingTime || stakingTimeBlocks > params.MaxStakingTime {
		return nil, fmt.Errorf("provided staking time %d is out of bounds for params active at height %d", stakingTimeBlocks, expectedInclusionHeight)
	}

	if stakingAmount < params.MinStakingAmount || stakingAmount > params.MaxStakingAmount {
		return nil, fmt.Errorf("provided staking amount %d is out of bounds for params active at height %d", stakingAmount, expectedInclusionHeight)
	}

	_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		params.Tag,
		stakerPk,
		fpPk,
		params.CovenantPks,
		params.CovenantQuorum,
		stakingTimeBlocks,
		stakingAmount,
		net,
	)
	if err != nil {
		return nil, err
	}

	serializedTx, err := utils.SerializeBtcTransaction(tx)
	if err != nil {
		return nil, err
	}

	return &CreatePhase1StakingTxResponse{
		StakingTxHex: hex.EncodeToString(serializedTx),
	}, nil
}

// createPhase1UnbondingTransactionCmd creates un-signed unbonding transaction based on
// provided valid phase1 staking transaction.
var createPhase1UnbondingTransactionCmd = cli.Command{
	Name:      "create-phase1-unbonding-transaction",
	ShortName: "crput",
	Usage:     "stakercli transaction create-phase1-unbonding-transaction [fullpath/to/parameters.json]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "hex encoded staking transaction for which unbonding transaction will be created",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     txInclusionHeightFlag,
			Usage:    "Inclusion height of the staking transactions. Necessary to chose correct global parameters for transaction",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
	Action: createPhase1UnbondingTransaction,
}

type CreatePhase1UnbondingTxResponse struct {
	// bare hex of created unbonding transaction
	UnbondingTxHex string `json:"unbonding_tx_hex"`
	// base64 encoded psbt packet which can be used to sign the transaction using
	// staker bitcoind wallet using `walletprocesspsbt` rpc call
	UnbondingPsbtPacketBase64 string `json:"unbonding_psbt_packet_base64"`
}

func createPhase1UnbondingTransaction(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	stakingTx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}

	stakingTxInclusionHeight := ctx.Uint64(txInclusionHeightFlag)

	paramsForHeight := globalParams.GetVersionedGlobalParamsByHeight(stakingTxInclusionHeight)

	if paramsForHeight == nil {
		return fmt.Errorf("no global params found for height %d", stakingTxInclusionHeight)
	}

	stakingTxInfo, err := btcstaking.ParseV0StakingTx(
		stakingTx,
		paramsForHeight.Tag,
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("provided staking transaction is not valid: %w, for params at height %d", err, stakingTxInclusionHeight)
	}

	unbondingAmount := stakingTxInfo.StakingOutput.Value - int64(paramsForHeight.UnbondingFee)

	if unbondingAmount <= 0 {
		return fmt.Errorf(
			"staking output value is too low to create unbonding transaction. Stake amount: %d, Unbonding fee: %d",
			stakingTxInfo.StakingOutput.Value,
			paramsForHeight.UnbondingFee,
		)
	}

	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		stakingTxInfo.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{stakingTxInfo.OpReturnData.FinalityProviderPublicKey.PubKey},
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		paramsForHeight.UnbondingTime,
		btcutil.Amount(unbondingAmount),
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("error building unbonding info: %w", err)
	}

	stakingTxHash := stakingTx.TxHash()
	stakingTxInput := wire.NewTxIn(
		wire.NewOutPoint(
			&stakingTxHash,
			uint32(stakingTxInfo.StakingOutputIdx),
		),
		nil,
		nil,
	)

	unbondingPsbtPacket, err := psbt.New(
		[]*wire.OutPoint{&stakingTxInput.PreviousOutPoint},
		[]*wire.TxOut{unbondingInfo.UnbondingOutput},
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)

	if err != nil {
		return err
	}

	// re-build staking scripts to properly fill data necessary for signing
	// in psbt packet
	stakingScriptInfo, err := btcstaking.BuildStakingInfo(
		stakingTxInfo.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{stakingTxInfo.OpReturnData.FinalityProviderPublicKey.PubKey},
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		stakingTxInfo.OpReturnData.StakingTime,
		btcutil.Amount(stakingTxInfo.StakingOutput.Value),
		currentParams,
	)

	if err != nil {
		return err
	}

	unbondingPathInfo, err := stakingScriptInfo.UnbondingPathSpendInfo()

	if err != nil {
		return err
	}

	unbondingPathCtrlBlock, err := unbondingPathInfo.ControlBlock.ToBytes()

	if err != nil {
		return err
	}

	// Fill psbt packet with data which will make it possible for staker to sign
	// it using his bitcoind wallet
	unbondingPsbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	unbondingPsbtPacket.Inputs[0].WitnessUtxo = stakingTxInfo.StakingOutput
	unbondingPsbtPacket.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		{
			XOnlyPubKey: stakingTxInfo.OpReturnData.StakerPublicKey.Marshall(),
		},
	}
	unbondingPsbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: unbondingPathCtrlBlock,
			Script:       unbondingPathInfo.RevealedLeaf.Script,
			LeafVersion:  unbondingPathInfo.RevealedLeaf.LeafVersion,
		},
	}

	unbondingTxBytes, err := utils.SerializeBtcTransaction(unbondingPsbtPacket.UnsignedTx)
	if err != nil {
		return err
	}

	unbondingPacketEncoded, err := unbondingPsbtPacket.B64Encode()

	if err != nil {
		return err
	}

	resp := &CreatePhase1UnbondingTxResponse{
		UnbondingTxHex:            hex.EncodeToString(unbondingTxBytes),
		UnbondingPsbtPacketBase64: unbondingPacketEncoded,
	}
	helpers.PrintRespJSON(resp)
	return nil
}

type withdrawalInfo struct {
	withdrawalOutputvalue btcutil.Amount
	withdrawalSequence    uint32
	withdrawalInput       *wire.OutPoint
	withdrawalFundingUtxo *wire.TxOut
	withdrawalSpendInfo   *btcstaking.SpendInfo
}

func outputsAreEqual(a *wire.TxOut, b *wire.TxOut) bool {
	return a.Value == b.Value && bytes.Equal(a.PkScript, b.PkScript)
}

// createPhase1WithdrawalTransactionCmd creates un-signed withdrawal transaction based on
// provided valid phase1 staking transaction or valid unbonding transaction.
var createPhase1WithdrawalTransactionCmd = cli.Command{
	Name:      "create-phase1-withdrawal-transaction",
	ShortName: "crpwt",
	Usage:     "stakercli transaction create-phase1-withdrawal-transaction [fullpath/to/parameters.json]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "original hex encoded staking transaction",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     txInclusionHeightFlag,
			Usage:    "Inclusion height of the staking transaction. Necessary to chose correct global parameters for transaction",
			Required: true,
		},
		cli.StringFlag{
			Name:     withdrawalAddressFlag,
			Usage:    "btc address to which send the withdrawed funds",
			Required: true,
		},
		cli.Int64Flag{
			Name:     withdrawalTransactionFeeFlag,
			Usage:    "fee to pay for withdrawal transaction",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which withdrawal should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
		cli.StringFlag{
			Name:  unbondingTransactionFlag,
			Usage: "hex encoded unbonding transaction. This should only be provided, if withdrawal is being done from unbonding output",
		},
	},
	Action: createPhase1WitdrawalTransaction,
}

type CreateWithdrawalTxResponse struct {
	// bare hex of created withdrawal transaction
	WithdrawalTxHex string `json:"withdrawal_tx_hex"`
	// base64 encoded psbt packet which can be used to sign the transaction using
	// staker bitcoind wallet using `walletprocesspsbt` rpc call
	WithdrawalPsbtPacketBase64 string `json:"withdrawal_psbt_packet_base64"`
}

func createWithdrawalInfo(
	unbondingTxHex string,
	stakingTxHash *chainhash.Hash,
	withdrawalFee btcutil.Amount,
	parsedStakingTransaction *btcstaking.ParsedV0StakingTx,
	paramsForHeight *parser.ParsedVersionedGlobalParams,
	net *chaincfg.Params) (*withdrawalInfo, error) {
	if len(unbondingTxHex) > 0 {
		// withdrawal from unbonding output
		unbondingTx, _, err := bbn.NewBTCTxFromHex(unbondingTxHex)

		if err != nil {
			return nil, fmt.Errorf("error parsing unbonding transaction: %w", err)
		}

		unbondingTxHash := unbondingTx.TxHash()

		if err := btcstaking.IsSimpleTransfer(unbondingTx); err != nil {
			return nil, fmt.Errorf("unbonding transaction is not valid: %w", err)
		}

		if !unbondingTx.TxIn[0].PreviousOutPoint.Hash.IsEqual(stakingTxHash) {
			return nil, fmt.Errorf("unbonding transaction does not spend staking transaction hash")
		}

		if unbondingTx.TxIn[0].PreviousOutPoint.Index != uint32(parsedStakingTransaction.StakingOutputIdx) {
			return nil, fmt.Errorf("unbonding transaction does not spend staking transaction index")
		}

		expectedUnbondingAmount := parsedStakingTransaction.StakingOutput.Value - int64(paramsForHeight.UnbondingFee)

		if expectedUnbondingAmount <= 0 {
			return nil, fmt.Errorf("too low staking output value to create unbonding transaction. Staking amount: %d, Unbonding fee: %d", parsedStakingTransaction.StakingOutput.Value, paramsForHeight.UnbondingFee)
		}

		unbondingInfo, err := btcstaking.BuildUnbondingInfo(
			parsedStakingTransaction.OpReturnData.StakerPublicKey.PubKey,
			[]*btcec.PublicKey{parsedStakingTransaction.OpReturnData.FinalityProviderPublicKey.PubKey},
			paramsForHeight.CovenantPks,
			paramsForHeight.CovenantQuorum,
			paramsForHeight.UnbondingTime,
			btcutil.Amount(expectedUnbondingAmount),
			net,
		)

		if err != nil {
			return nil, fmt.Errorf("error building unbonding info: %w", err)
		}

		if !outputsAreEqual(unbondingInfo.UnbondingOutput, unbondingTx.TxOut[0]) {
			return nil, fmt.Errorf("unbonding transaction output does not match with expected output")
		}

		timeLockPathInfo, err := unbondingInfo.TimeLockPathSpendInfo()

		if err != nil {
			return nil, fmt.Errorf("error building time lock path spend info: %w", err)
		}

		withdrawalOutputValue := unbondingTx.TxOut[0].Value - int64(withdrawalFee)

		if withdrawalOutputValue <= 0 {
			return nil, fmt.Errorf("too low unbonding output value to create withdrawal transaction. Unbonding amount: %d, Withdrawal fee: %d", unbondingTx.TxOut[0].Value, withdrawalFee)
		}

		return &withdrawalInfo{
			withdrawalOutputvalue: btcutil.Amount(withdrawalOutputValue),
			withdrawalSequence:    uint32(paramsForHeight.UnbondingTime),
			withdrawalInput:       wire.NewOutPoint(&unbondingTxHash, 0),
			withdrawalFundingUtxo: unbondingTx.TxOut[0],
			withdrawalSpendInfo:   timeLockPathInfo,
		}, nil
	}
	stakingInfo, err := btcstaking.BuildStakingInfo(
		parsedStakingTransaction.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{parsedStakingTransaction.OpReturnData.FinalityProviderPublicKey.PubKey},
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		parsedStakingTransaction.OpReturnData.StakingTime,
		btcutil.Amount(parsedStakingTransaction.StakingOutput.Value),
		net,
	)

	if err != nil {
		return nil, fmt.Errorf("error building staking info: %w", err)
	}

	timelockPathInfo, err := stakingInfo.TimeLockPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("error building timelock path spend info: %w", err)
	}

	withdrawalOutputValue := parsedStakingTransaction.StakingOutput.Value - int64(withdrawalFee)

	if withdrawalOutputValue <= 0 {
		return nil, fmt.Errorf("too low staking output value to create withdrawal transaction. Staking amount: %d, Withdrawal fee: %d", parsedStakingTransaction.StakingOutput.Value, withdrawalFee)
	}

	return &withdrawalInfo{
		withdrawalOutputvalue: btcutil.Amount(withdrawalOutputValue),
		withdrawalSequence:    uint32(parsedStakingTransaction.OpReturnData.StakingTime),
		withdrawalInput:       wire.NewOutPoint(stakingTxHash, uint32(parsedStakingTransaction.StakingOutputIdx)),
		withdrawalFundingUtxo: parsedStakingTransaction.StakingOutput,
		withdrawalSpendInfo:   timelockPathInfo,
	}, nil
}

func createPhase1WitdrawalTransaction(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	withdrawalFee, err := parseAmountFromCliCtx(ctx, withdrawalTransactionFeeFlag)

	if err != nil {
		return err
	}

	withdrawalAddressString := ctx.String(withdrawalAddressFlag)

	withdrawalAddress, err := btcutil.DecodeAddress(withdrawalAddressString, currentParams)

	if err != nil {
		return fmt.Errorf("error decoding withdrawal address: %w", err)
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	stakingTx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}

	stakingTxInclusionHeight := ctx.Uint64(txInclusionHeightFlag)

	paramsForHeight := globalParams.GetVersionedGlobalParamsByHeight(stakingTxInclusionHeight)

	if paramsForHeight == nil {
		return fmt.Errorf("no global params found for height %d", stakingTxInclusionHeight)
	}

	parsedStakingTransaction, err := btcstaking.ParseV0StakingTx(
		stakingTx,
		paramsForHeight.Tag,
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("provided staking transaction is not valid: %w, for params at height %d", err, stakingTxInclusionHeight)
	}

	stakingTxHash := stakingTx.TxHash()

	unbondingTxHex := ctx.String(unbondingTransactionFlag)

	wi, err := createWithdrawalInfo(
		unbondingTxHex,
		&stakingTxHash,
		withdrawalFee,
		parsedStakingTransaction,
		paramsForHeight,
		currentParams,
	)

	if err != nil {
		return err
	}

	withdrawalPkScript, err := txscript.PayToAddrScript(withdrawalAddress)

	if err != nil {
		return fmt.Errorf("error creating pk script for withdrawal address: %w", err)
	}

	withdrawTxPsbPacket, err := psbt.New(
		[]*wire.OutPoint{wi.withdrawalInput},
		[]*wire.TxOut{
			wire.NewTxOut(int64(wi.withdrawalOutputvalue), withdrawalPkScript),
		},
		2,
		0,
		[]uint32{wi.withdrawalSequence},
	)

	if err != nil {
		return err
	}

	serializedControlBlock, err := wi.withdrawalSpendInfo.ControlBlock.ToBytes()

	if err != nil {
		return err
	}

	// Fill psbt packet with data which will make it possible for staker to sign
	// it using his bitcoind wallet
	withdrawTxPsbPacket.Inputs[0].SighashType = txscript.SigHashDefault
	withdrawTxPsbPacket.Inputs[0].WitnessUtxo = wi.withdrawalFundingUtxo
	withdrawTxPsbPacket.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		{
			XOnlyPubKey: parsedStakingTransaction.OpReturnData.StakerPublicKey.Marshall(),
		},
	}
	withdrawTxPsbPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: serializedControlBlock,
			Script:       wi.withdrawalSpendInfo.RevealedLeaf.Script,
			LeafVersion:  wi.withdrawalSpendInfo.RevealedLeaf.LeafVersion,
		},
	}

	withdrawalTxBytes, err := utils.SerializeBtcTransaction(withdrawTxPsbPacket.UnsignedTx)
	if err != nil {
		return err
	}

	encodedPsbtPacket, err := withdrawTxPsbPacket.B64Encode()

	if err != nil {
		return err
	}

	resp := &CreateWithdrawalTxResponse{
		WithdrawalTxHex:            hex.EncodeToString(withdrawalTxBytes),
		WithdrawalPsbtPacketBase64: encodedPsbtPacket,
	}

	helpers.PrintRespJSON(resp)
	return nil
}
