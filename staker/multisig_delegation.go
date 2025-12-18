package staker

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
	staking "github.com/babylonlabs-io/babylon/v4/btcstaking"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

func (app *App) buildDelegationMultisig(
	req *sendDelegationRequest,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
) (*cl.DelegationData, error) {
	if app.config == nil || app.config.StakerKeysConfig == nil || len(app.config.StakerKeysConfig.DecodedWIFs) == 0 {
		return nil, fmt.Errorf("multisig staker keys are not configured")
	}

	externalData, err := app.retrieveExternalDelegationDataMultisig(req.inclusionInfo)
	if err != nil {
		return nil, fmt.Errorf("error retrieving external delegation data: %w", err)
	}

	stakerQuorum := app.config.StakerKeysConfig.StakerThreshold
	stakerPubKeys := make([]*btcec.PublicKey, 0, len(app.config.StakerKeysConfig.DecodedWIFs))
	stakerPrivKeys := make([]*btcec.PrivateKey, 0, len(app.config.StakerKeysConfig.DecodedWIFs))
	for _, w := range app.config.StakerKeysConfig.DecodedWIFs {
		stakerPrivKeys = append(stakerPrivKeys, w.PrivKey)
		stakerPubKeys = append(stakerPubKeys, w.PrivKey.PubKey())
	}

	if stakerQuorum == 0 || int(stakerQuorum) > len(stakerPrivKeys) {
		return nil, fmt.Errorf("invalid staker multisig threshold %d for %d keys", stakerQuorum, len(stakerPrivKeys))
	}

	// The "main" staker key is the first one after config sorting.
	mainStakerSk := stakerPrivKeys[0]
	mainStakerPk := mainStakerSk.PubKey()

	slashingFee := app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat)

	stakingSlashingTx, stakingSlashingSpendInfo, err := slashingTxForStakingTxMultisig(
		slashingFee,
		externalData.babylonParams.UnbondingTime,
		externalData.babylonParams.SlashingPkScript,
		externalData.babylonParams.SlashingRate,
		externalData.babylonParams.CovenantPks,
		externalData.babylonParams.CovenantQuruomThreshold,
		stakerPubKeys,
		stakerQuorum,
		stakingOutputIndex,
		stakingTime,
		storedTx,
		req.fpBtcPubkeys,
		app.network,
	)
	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"btcTxHash": req.btcTxHash,
			"err":       err,
		}).Fatalf("Failed to build delegation data for staking transaction (multisig)")
	}

	undelegationDesc, err := createUndelegationDataMultisig(
		storedTx,
		stakerPubKeys,
		stakerQuorum,
		externalData.babylonParams.CovenantPks,
		externalData.babylonParams.CovenantQuruomThreshold,
		externalData.babylonParams.SlashingPkScript,
		externalData.babylonParams.UnbondingFee,
		externalData.babylonParams.UnbondingTime,
		app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat),
		externalData.babylonParams.SlashingRate,
		req.fpBtcPubkeys,
		stakingOutputIndex,
		app.network,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating undelegation data: %w", err)
	}

	mainStakingSlashingSig, extraStakingSlashingSigs, err := signMultisigScriptSpendSigs(
		stakingSlashingTx,
		storedTx.StakingTx.TxOut[stakingOutputIndex],
		stakingSlashingSpendInfo.RevealedLeaf,
		stakerPrivKeys,
		mainStakerSk,
	)
	if err != nil {
		return nil, fmt.Errorf("error signing slashing transaction for staking transaction (multisig): %w", err)
	}

	mainUnbondingSlashingSig, extraUnbondingSlashingSigs, err := signMultisigScriptSpendSigs(
		undelegationDesc.SlashUnbondingTransaction,
		undelegationDesc.UnbondingTransaction.TxOut[0],
		undelegationDesc.SlashUnbondingTransactionSpendInfo.RevealedLeaf,
		stakerPrivKeys,
		mainStakerSk,
	)
	if err != nil {
		return nil, fmt.Errorf("error signing slashing transaction for unbonding transaction (multisig): %w", err)
	}

	// sanity check that all our transactions are standard
	if err := utils.CheckTransaction(stakingSlashingTx); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build staking slashing tx: %w", err)
	}
	if err := utils.CheckTransaction(undelegationDesc.UnbondingTransaction); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build unbonding tx: %w", err)
	}
	if err := utils.CheckTransaction(undelegationDesc.SlashUnbondingTransaction); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build unbonding slashing tx: %w", err)
	}

	dg := createDelegationDataMultisig(
		req,
		mainStakerPk,
		stakerPubKeys[1:],
		stakerQuorum,
		extraStakingSlashingSigs,
		extraUnbondingSlashingSigs,
		stakingOutputIndex,
		stakingTime,
		storedTx,
		stakingSlashingTx,
		mainStakingSlashingSig,
		externalData.babylonStakerAddr,
		&cl.UndelegationData{
			UnbondingTransaction:         undelegationDesc.UnbondingTransaction,
			UnbondingTxValue:             undelegationDesc.UnbondingTxValue,
			UnbondingTxUnbondingTime:     undelegationDesc.UnbondingTxUnbondingTime,
			SlashUnbondingTransaction:    undelegationDesc.SlashUnbondingTransaction,
			SlashUnbondingTransactionSig: mainUnbondingSlashingSig,
		},
	)

	return dg, nil
}

func (app *App) retrieveExternalDelegationDataMultisig(inclusionInfo *inclusionInfo) (*externalDelegationData, error) {
	var params *cl.StakingParams

	if inclusionInfo == nil {
		tipHeight, err := app.babylonClient.QueryBtcLightClientTipHeight()
		if err != nil {
			return nil, fmt.Errorf("error getting tip height: %w", err)
		}

		p, err := app.babylonClient.ParamsByBtcHeight(tipHeight)
		if err != nil {
			return nil, fmt.Errorf("error getting params: %w", err)
		}
		params = p
	} else {
		p, err := app.babylonClient.ParamsByBtcHeight(inclusionInfo.inclusionBlockBtcHeight)
		if err != nil {
			return nil, fmt.Errorf("error getting params: %w", err)
		}
		params = p
	}

	stakerPublicKey := app.config.StakerKeysConfig.DecodedWIFs[0].PrivKey.PubKey()

	return &externalDelegationData{
		babylonStakerAddr: app.babylonClient.GetKeyAddress(),
		stakerPublicKey:   stakerPublicKey,
		babylonParams:     params,
	}, nil
}

func slashingTxForStakingTxMultisig(
	slashingFee btcutil.Amount,
	slashChangeLockTime uint16,
	slashingPkScript []byte,
	slashingRate sdkmath.LegacyDec,
	covenantPks []*btcec.PublicKey,
	covenantQuorum uint32,
	stakerPks []*btcec.PublicKey,
	stakerQuorum uint32,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	fpBtcPubkeys []*btcec.PublicKey,
	net *chaincfg.Params,
) (*wire.MsgTx, *staking.SpendInfo, error) {
	slashingTx, err := staking.BuildMultisigSlashingTxFromStakingTxStrict(
		storedTx.StakingTx,
		stakingOutputIndex,
		slashingPkScript,
		stakerPks,
		stakerQuorum,
		slashChangeLockTime,
		int64(slashingFee),
		slashingRate,
		net,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("building slashing transaction failed: %w", err)
	}

	stakingInfo, err := staking.BuildMultisigStakingInfo(
		stakerPks,
		stakerQuorum,
		fpBtcPubkeys,
		covenantPks,
		covenantQuorum,
		stakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[stakingOutputIndex].Value),
		net,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("building multisig staking info failed: %w", err)
	}

	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("building slashing path info failed: %w", err)
	}

	return slashingTx, slashingPathInfo, nil
}

func createUndelegationDataMultisig(
	storedTx *stakerdb.StoredTransaction,
	stakerPubKeys []*btcec.PublicKey,
	stakerQuorum uint32,
	covenantPubKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	slashingPkScript []byte,
	unbondingTxFee btcutil.Amount,
	unbondingTime uint16,
	slashingFee btcutil.Amount,
	slashingRate sdkmath.LegacyDec,
	fpBtcPubkeys []*btcec.PublicKey,
	stakingOutputIndex uint32,
	btcNetwork *chaincfg.Params,
) (*UnbondingSlashingDesc, error) {
	stakingTxHash := storedTx.StakingTx.TxHash()
	stakingOutput := storedTx.StakingTx.TxOut[stakingOutputIndex]

	unbondingOutputValue := stakingOutput.Value - int64(unbondingTxFee)
	if unbondingOutputValue <= 0 {
		return nil, fmt.Errorf("staking output value:%d sats. unbonding tx fee:%d sats", stakingOutput.Value, int64(unbondingTxFee))
	}

	if unbondingOutputValue <= int64(slashingFee) {
		return nil, fmt.Errorf("unbonding output value %d sats. slashing tx fee: %d sats", unbondingOutputValue, int64(slashingFee))
	}

	unbondingInfo, err := staking.BuildMultisigUnbondingInfo(
		stakerPubKeys,
		stakerQuorum,
		fpBtcPubkeys,
		covenantPubKeys,
		covenantThreshold,
		unbondingTime,
		btcutil.Amount(unbondingOutputValue),
		btcNetwork,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: %w", err)
	}

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, stakingOutputIndex), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildMultisigSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		slashingPkScript,
		stakerPubKeys,
		stakerQuorum,
		unbondingTime,
		int64(slashingFee),
		slashingRate,
		btcNetwork,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: failed to build slashing tx: %w", err)
	}

	slashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to build slashing path info: %w", err)
	}

	return &UnbondingSlashingDesc{
		UnbondingTransaction:               unbondingTx,
		UnbondingTxValue:                   btcutil.Amount(unbondingOutputValue),
		UnbondingTxUnbondingTime:           unbondingTime,
		SlashUnbondingTransaction:          slashUnbondingTx,
		SlashUnbondingTransactionSpendInfo: slashingPathInfo,
	}, nil
}

func signMultisigScriptSpendSigs(
	txToSign *wire.MsgTx,
	fundingOutput *wire.TxOut,
	leaf txscript.TapLeaf,
	stakerPrivKeys []*btcec.PrivateKey,
	mainStakerSk *btcec.PrivateKey,
) (*schnorr.Signature, []*schnorr.Signature, error) {
	var (
		mainSig   *schnorr.Signature
		extraSigs []*schnorr.Signature
	)

	for _, sk := range stakerPrivKeys {
		sig, err := staking.SignTxWithOneScriptSpendInputFromTapLeaf(txToSign, fundingOutput, sk, leaf)
		if err != nil {
			return nil, nil, err
		}

		if sk.PubKey().IsEqual(mainStakerSk.PubKey()) {
			mainSig = sig
		} else {
			extraSigs = append(extraSigs, sig)
		}
	}

	if mainSig == nil {
		return nil, nil, fmt.Errorf("missing main staker signature")
	}

	return mainSig, extraSigs, nil
}
