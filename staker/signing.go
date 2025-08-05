package staker

import (
	"fmt"

	staking "github.com/babylonlabs-io/babylon/v3/btcstaking"
	bbntypes "github.com/babylonlabs-io/babylon/v3/types"
	btcstktypes "github.com/babylonlabs-io/babylon/v3/x/btcstaking/types"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

type stakeExpSignInfo struct {
	StakingOutput *wire.TxOut
	FundingOutput *wire.TxOut
	SpendInfo     *staking.SpendInfo
	// Params contains the staking parameters for the previous delegation
	Params *cl.StakingParams
}

// signStakingTransaction signs a staking transaction, handling both regular staking
// and stake expansion transactions with different signing requirements
func (app *App) signStakingTransaction(tx *wire.MsgTx, di *btcstktypes.QueryBTCDelegationResponse) (*wire.MsgTx, error) {
	// Check if this is a stake expansion transaction (exactly 2 inputs)
	if len(tx.TxIn) == 2 {
		// This is likely a stake expansion transaction
		// Input 0: Previous staking output (taproot, needs special signing)
		// Input 1: Funding output (regular UTXO, can be signed normally)

		// Try to sign as stake expansion transaction first
		// The signStakeExpansionTransaction function will validate via Babylon query
		// and return proper error if this is not actually a stake expansion
		// If it is not, it will fall back to regular staking signing
		// which is what we want for regular staking transactions with 2 inputs.
		return app.signStakeExpansionTransaction(tx, di)
	}

	// Regular staking transaction - use normal wallet signing
	return app.signRegularStakingTransaction(tx)
}

// signStakeExpansionTransaction signs a stake expansion transaction with mixed input types
func (app *App) signStakeExpansionTransaction(tx *wire.MsgTx, di *btcstktypes.QueryBTCDelegationResponse) (*wire.MsgTx, error) {
	// Verify this is a stake expansion transaction
	if di == nil || di.BtcDelegation == nil || di.BtcDelegation.StkExp == nil {
		// if it is not a stake expansion delegation, it might be a regular delegation
		// with 2 inputs, so we sign it as a regular staking transaction
		return app.signRegularStakingTransaction(tx)
	}

	// Check if we have covenant signatures for stake expansion
	params, err := app.babylonClient.Params()
	if err != nil {
		return nil, fmt.Errorf("failed to get babylon params: %w", err)
	}

	// For stake expansion, we need to check both:
	// 1. PreviousStkCovenantSigs - for spending the previous staking output (validated later)
	// 2. Regular covenant unbonding signatures - for the new staking transaction
	undelegationInfo, err := app.babylonClient.GetUndelegationInfo(di)
	if err != nil {
		return nil, fmt.Errorf("failed to get undelegation info for expansion: %w", err)
	}

	if len(undelegationInfo.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("not enough covenant unbonding signatures for stake expansion: have %d, need %d",
			len(undelegationInfo.CovenantUnbondingSignatures), params.CovenantQuruomThreshold)
	}

	// Build the unbondWitness for the taproot input
	unbondWitness, err := app.buildUnbondingPathWitness(tx, di.BtcDelegation.StkExp)
	if err != nil {
		return nil, fmt.Errorf("failed to create unbonding path witness: %w", err)
	}

	// Add the witness to the taproot spent and sign the staking expansion transaction
	tx.TxIn[0].Witness = unbondWitness
	signedTx, err := app.signTx(tx)
	if err != nil {
		return nil, fmt.Errorf("staking expansion transaction: %w", err)
	}

	if signedTx == nil {
		app.logTxDetails(tx, "stake expansion")
	}

	return signedTx, nil
}

// getStakeExpansionSignInfo retrieves the necessary information for stake expansion signing.
// This includes inputs, the previous delegation's unbonding spend path and the
// parameters for the previous delegation.
func (app *App) getStakeExpansionSignInfo(stakerAddr btcutil.Address, fundingOutpoint wire.OutPoint, previousStakingTxHashHex string) (*stakeExpSignInfo, error) {
	// Get the funding transaction (we need it for validation but don't use it directly)
	fundingTx, err := app.wc.Tx(&fundingOutpoint.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get funding transaction: %w", err)
	}

	// Get the previous staking transaction
	prevStakingHash, err := chainhash.NewHashFromStr(previousStakingTxHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous staking transaction hash: %w", err)
	}

	prevDelegationResult, err := app.babylonClient.QueryBTCDelegation(prevStakingHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous delegation: %w", err)
	}

	if prevDelegationResult.BtcDelegation == nil {
		return nil, fmt.Errorf("previous delegation not found")
	}

	prevDel := prevDelegationResult.BtcDelegation

	prevStakingMsgTx, _, err := bbntypes.NewBTCTxFromHex(prevDel.StakingTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse staking tx from previous delegation: %w", err)
	}

	// get the params from the previous delegation
	prevDelParams, err := app.babylonClient.ParamsByBtcHeight(prevDel.ParamsVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get babylon params: %w", err)
	}

	// get the unbonding spend info for the previous delegation
	si, err := app.getUnbondingSpendInfo(prevDelParams, stakerAddr, prevDel)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous staking transaction unbonding spend path: %w", err)
	}

	return &stakeExpSignInfo{
		StakingOutput: prevStakingMsgTx.TxOut[prevDel.StakingOutputIdx],
		FundingOutput: fundingTx.MsgTx().TxOut[fundingOutpoint.Index],
		SpendInfo:     si,
		Params:        prevDelParams,
	}, nil
}

func (app *App) getUnbondingSpendInfo(params *cl.StakingParams, stakerAddr btcutil.Address, del *btcstktypes.BTCDelegationResponse) (*staking.SpendInfo, error) {
	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get staker public key: %w", err)
	}

	// Get finality provider public keys from the delegation
	fpBtcPubkeys, err := convertFpBtcPkToBtcPk(del.FpBtcPkList)
	if err != nil {
		return nil, fmt.Errorf("failed to convert previous fp btc pubkeys: %w", err)
	}

	// Build the unbonding spend info using the provided parameters
	prevStakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		fpBtcPubkeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		uint16(del.StakingTime),
		btcutil.Amount(del.TotalSat),
		app.network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build previous staking info: %w", err)
	}

	return prevStakingInfo.UnbondingPathSpendInfo()
}

// buildUnbondingPathWitness retrieves the witness for the unbonding path of a stake expansion transaction.
// This is used to sign the taproot input that spends the previous staking output.
// It handles the covenant signatures and the taproot signature for the staker.
func (app *App) buildUnbondingPathWitness(tx *wire.MsgTx, stkExp *btcstktypes.StakeExpansionResponse) (wire.TxWitness, error) {
	var (
		fundingOutpoint  = tx.TxIn[1].PreviousOutPoint
		stakingTxHash    = tx.TxHash()
		_, stakerAddress = app.mustGetTransactionAndStakerAddress(&stakingTxHash)
	)

	si, err := app.getStakeExpansionSignInfo(stakerAddress, fundingOutpoint, stkExp.PreviousStakingTxHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to get stake expansion signing info: %w", err)
	}

	if len(stkExp.PreviousStkCovenantSigs) < int(si.Params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("not enough previous staking covenant signatures for stake expansion: have %d, need %d",
			len(stkExp.PreviousStkCovenantSigs), si.Params.CovenantQuruomThreshold)
	}

	// Use the two-input signing method that matches the covenant signature approach
	// to get the taproot signature for the staker
	stakerSig, err := app.wc.SignTwoInputTaprootSpendingTransaction(
		&walletcontroller.TwoInputTaprootSigningRequest{
			TxToSign:      tx,               // Complete two-input staking expansion transaction
			StakingOutput: si.StakingOutput, // Input 0: Previous staking output
			FundingOutput: si.FundingOutput, // Input 1: Funding output
			SignerAddress: stakerAddress,
			SpendDescription: &walletcontroller.SpendPathDescription{
				ScriptLeaf:   &si.SpendInfo.RevealedLeaf,
				ControlBlock: &si.SpendInfo.ControlBlock,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign taproot input: %w", err)
	}

	if stakerSig.Signature == nil {
		return nil, fmt.Errorf("failed to get taproot signature")
	}

	prevStkCovSigs, err := parseCovenantSigs(stkExp.PreviousStkCovenantSigs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse covenant signatures: %w", err)
	}
	// Create covenant signatures witness using the stake expansion signatures
	covenantSignatures, err := createWitnessSignaturesForPubKeys(
		si.Params.CovenantPks,
		si.Params.CovenantQuruomThreshold,
		prevStkCovSigs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create covenant signatures: %w", err)
	}

	// Build the unbondWitness for the taproot input
	return si.SpendInfo.CreateUnbondingPathWitness(
		covenantSignatures,
		stakerSig.Signature,
	)
}

// signRegularStakingTransaction signs a regular staking transaction using wallet signing
func (app *App) signRegularStakingTransaction(tx *wire.MsgTx) (*wire.MsgTx, error) {
	signedTx, err := app.signTx(tx)
	if err != nil {
		return nil, fmt.Errorf("regular staking transaction: %w", err)
	}

	if signedTx == nil {
		app.logTxDetails(tx, "regular staking")
	}

	return signedTx, nil
}

// signTx signs a transaction using wallet signing
func (app *App) signTx(tx *wire.MsgTx) (*wire.MsgTx, error) {
	signedTx, fullySigned, err := app.wc.SignRawTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	if !fullySigned {
		return nil, nil // Return nil to indicate signing failed
	}

	return signedTx, nil
}

func (app *App) logTxDetails(tx *wire.MsgTx, txType string) {
	// Collect all input UTXO details for checking if already spent
	inputUTXOs := make([]map[string]interface{}, 0, len(tx.TxIn))
	unsignedInputs := make([]int, 0)
	for i, in := range tx.TxIn {
		inputUTXOs = append(inputUTXOs, map[string]interface{}{
			"inputIndex": i,
			"txHash":     in.PreviousOutPoint.Hash.String(),
			"outputIdx":  in.PreviousOutPoint.Index,
		})
		if len(in.Witness) == 0 {
			unsignedInputs = append(unsignedInputs, i)
			break
		}
	}

	// Get the configured wallet address
	stakingTxHash := tx.TxHash()
	_, stakerAddr := app.mustGetTransactionAndStakerAddress(&stakingTxHash)
	stkAddrStr := "nil"
	if stakerAddr != nil {
		stkAddrStr = stakerAddr.EncodeAddress()
	}

	logFields := logrus.Fields{
		"transactionType":   txType,
		"inputsNum":         len(tx.TxIn),
		"unsignedInputsIdx": unsignedInputs,
		"stakerAddr":        stkAddrStr,
		"stakingTxHash":     tx.TxHash().String(),
		"inputUTXOs":        inputUTXOs,
	}

	app.logger.WithFields(logFields).Debug("could not fully sign transaction with configured wallet")
}

func isTransacionFullySigned(tx *wire.MsgTx) (bool, error) {
	if len(tx.TxIn) == 0 {
		return false, fmt.Errorf("transaction has no inputs")
	}

	signed := true

	for _, in := range tx.TxIn {
		if len(in.Witness) == 0 {
			signed = false
			break
		}
	}

	return signed, nil
}

func parseCovenantSigs(covenantSigs []*btcstktypes.SignatureInfo) ([]cl.CovenantSignatureInfo, error) {
	var parsedSigs []cl.CovenantSignatureInfo
	for _, sig := range covenantSigs {
		btcSig, err := sig.Sig.ToBTCSig()
		if err != nil {
			return nil, fmt.Errorf("failed to convert covenant signature: %w", err)
		}

		btcPk, err := sig.Pk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("failed to convert covenant public key: %w", err)
		}

		parsedSigs = append(parsedSigs, cl.CovenantSignatureInfo{
			Signature: btcSig,
			PubKey:    btcPk,
		})
	}
	return parsedSigs, nil
}
