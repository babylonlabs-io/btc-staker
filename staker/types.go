package staker

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	sdkmath "cosmossdk.io/math"
	staking "github.com/babylonlabs-io/babylon/btcstaking"

	bbn "github.com/babylonlabs-io/babylon/types"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/proto"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type spendStakeTxInfo struct {
	spendStakeTx           *wire.MsgTx
	fundingOutput          *wire.TxOut
	fundingOutputSpendInfo *staking.SpendInfo
	calculatedFee          btcutil.Amount
}

// babylonPopToDBPop receives already validated pop from external sources and converts it to database representation
func babylonPopToDBPop(pop *cl.BabylonPop) *stakerdb.ProofOfPossession {
	return &stakerdb.ProofOfPossession{
		BtcSigType:            pop.PopTypeNum(),
		BtcSigOverBabylonAddr: pop.BtcSig,
	}
}

func babylonCovSigToDBCovSig(covSig cl.CovenantSignatureInfo) stakerdb.PubKeySigPair {
	return stakerdb.NewCovenantMemberSignature(covSig.Signature, covSig.PubKey)
}

func babylonCovSigsToDBSigSigs(covSigs []cl.CovenantSignatureInfo) []stakerdb.PubKeySigPair {
	sigSigs := make([]stakerdb.PubKeySigPair, len(covSigs))

	for i := range covSigs {
		sigSigs[i] = babylonCovSigToDBCovSig(covSigs[i])
	}

	return sigSigs
}

// Helper function to sort all signatures in reverse lexicographical order of signing public keys
// this way signatures are ready to be used in multisig witness with corresponding public keys
func sortPubKeysForWitness(infos []*btcec.PublicKey) []*btcec.PublicKey {
	sortedInfos := make([]*btcec.PublicKey, len(infos))
	copy(sortedInfos, infos)
	sort.SliceStable(sortedInfos, func(i, j int) bool {
		keyIBytes := schnorr.SerializePubKey(sortedInfos[i])
		keyJBytes := schnorr.SerializePubKey(sortedInfos[j])
		return bytes.Compare(keyIBytes, keyJBytes) == 1
	})

	return sortedInfos
}

func pubKeyToString(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(pubKey))
}

func createWitnessSignaturesForPubKeys(
	covenantPubKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	receivedSignaturePairs []stakerdb.PubKeySigPair,
) ([]*schnorr.Signature, error) {
	if len(receivedSignaturePairs) < int(covenantQuorum) {
		return nil, fmt.Errorf("not enough signatures to create witness. Required: %d, received: %d", covenantQuorum, len(receivedSignaturePairs))
	}

	// create map of received signatures
	receivedSignaturesUpToQuorum := make(map[string]*schnorr.Signature)

	for _, pair := range receivedSignaturePairs {
		// we are only interested in quorum number of signatures
		if len(receivedSignaturesUpToQuorum) >= int(covenantQuorum) {
			break
		}

		receivedSignaturesUpToQuorum[pubKeyToString(pair.PubKey)] = pair.Signature
	}

	sortedPubKeys := sortPubKeysForWitness(covenantPubKeys)

	// this makes sure number of signatures is equal to number of public keys
	signatures := make([]*schnorr.Signature, len(sortedPubKeys))

	for i, key := range sortedPubKeys {
		k := key
		if signature, found := receivedSignaturesUpToQuorum[pubKeyToString(k)]; found {
			signatures[i] = signature
		}
	}

	return signatures, nil
}

func slashingTxForStakingTx(
	slashingFee btcutil.Amount,
	delegationData *externalDelegationData,
	storedTx *stakerdb.StoredTransaction,
	net *chaincfg.Params,
) (*wire.MsgTx, *staking.SpendInfo, error) {
	stakerPubKey := delegationData.stakerPublicKey
	lockSlashTxLockTime := delegationData.babylonParams.UnbondingTime

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		storedTx.StakingTx,
		storedTx.StakingOutputIndex,
		delegationData.babylonParams.SlashingPkScript,
		stakerPubKey,
		lockSlashTxLockTime,
		int64(slashingFee),
		delegationData.babylonParams.SlashingRate,
		net,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("building slashing transaction failed: %w", err)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		storedTx.FinalityProvidersBtcPks,
		delegationData.babylonParams.CovenantPks,
		delegationData.babylonParams.CovenantQuruomThreshold,
		storedTx.StakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		net,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("building staking info failed: %w", err)
	}

	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, nil, fmt.Errorf("building slashing path info failed: %w", err)
	}

	return slashingTx, slashingPathInfo, nil
}

func createDelegationData(
	stakerBtcPk *btcec.PublicKey,
	inclusionInfo *inclusionInfo,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	babylonStakerAddr sdk.AccAddress,
	undelegationData *cl.UndelegationData,
) *cl.DelegationData {
	var incInfo *cl.StakingTransactionInclusionInfo

	if inclusionInfo != nil {
		inclusionBlockHash := inclusionInfo.inclusionBlock.BlockHash()

		incInfo = &cl.StakingTransactionInclusionInfo{
			StakingTransactionIdx:                inclusionInfo.txIndex,
			StakingTransactionInclusionProof:     inclusionInfo.inclusionProof,
			StakingTransactionInclusionBlockHash: &inclusionBlockHash,
		}
	}

	dg := cl.DelegationData{
		StakingTransaction:              storedTx.StakingTx,
		StakingTransactionInclusionInfo: incInfo,
		StakingTime:                     storedTx.StakingTime,
		StakingValue:                    btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		FinalityProvidersBtcPks:         storedTx.FinalityProvidersBtcPks,
		StakerBtcPk:                     stakerBtcPk,
		SlashingTransaction:             slashingTx,
		SlashingTransactionSig:          slashingTxSignature,
		BabylonStakerAddr:               babylonStakerAddr,
		BabylonPop:                      storedTx.Pop,
		Ud:                              undelegationData,
	}

	return &dg
}

func createSpendStakeTx(
	destinationScript []byte,
	fundingOutput *wire.TxOut,
	fundingOutputIdx uint32,
	fundingTxHash *chainhash.Hash,
	lockTime uint16,
	feeRate chainfee.SatPerKVByte,
) (*wire.MsgTx, *btcutil.Amount, error) {
	newOutput := wire.NewTxOut(fundingOutput.Value, destinationScript)

	stakingOutputOutpoint := wire.NewOutPoint(fundingTxHash, fundingOutputIdx)
	stakingOutputAsInput := wire.NewTxIn(stakingOutputOutpoint, nil, nil)
	// need to set valid sequence to unlock tx.
	stakingOutputAsInput.Sequence = uint32(lockTime)

	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(stakingOutputAsInput)
	spendTx.AddTxOut(newOutput)

	// transaction have 1 P2TR input and does not have any change
	txSize := txsizes.EstimateVirtualSize(0, 1, 0, 0, []*wire.TxOut{newOutput}, 0)

	fee := txrules.FeeForSerializeSize(btcutil.Amount(feeRate), txSize)

	spendTx.TxOut[0].Value -= int64(fee)

	if spendTx.TxOut[0].Value <= 0 {
		return nil, nil, fmt.Errorf("too big fee rate for spend stake tx. calculated fee: %d. funding output value: %d", fee, fundingOutput.Value)
	}

	return spendTx, &fee, nil
}

func createSpendStakeTxFromStoredTx(
	stakerBtcPk *btcec.PublicKey,
	covenantPublicKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	storedtx *stakerdb.StoredTransaction,
	destinationScript []byte,
	feeRate chainfee.SatPerKVByte,
	net *chaincfg.Params,
) (*spendStakeTxInfo, error) {
	// Note: we enable withdrawal only even if staking transaction is confirmed on btc.
	// This is to cover cases:
	// - staker is unable to sent delegation to babylon
	// - staking transaction on babylon fail to get covenant signatures
	//nolint:gocritic
	if storedtx.StakingTxConfirmedOnBtc() && !storedtx.UnbondingTxConfirmedOnBtc() {
		stakingInfo, err := staking.BuildStakingInfo(
			stakerBtcPk,
			storedtx.FinalityProvidersBtcPks,
			covenantPublicKeys,
			covenantThreshold,
			storedtx.StakingTime,
			btcutil.Amount(storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex].Value),
			net,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to build staking info while spending staking transaction: %w", err)
		}

		stakingTimeLockPathInfo, err := stakingInfo.TimeLockPathSpendInfo()

		if err != nil {
			return nil, fmt.Errorf("failed to build time lock path info while spending staking transaction: %w", err)
		}

		stakingTxHash := storedtx.StakingTx.TxHash()
		// transaction is only in sent to babylon state we try to spend staking output directly
		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			storedtx.StakingOutputIndex,
			&stakingTxHash,
			storedtx.StakingTime,
			feeRate,
		)

		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:           spendTx,
			fundingOutputSpendInfo: stakingTimeLockPathInfo,
			fundingOutput:          storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			calculatedFee:          *calculatedFee,
		}, nil
	} else if storedtx.StakingTxConfirmedOnBtc() && storedtx.UnbondingTxConfirmedOnBtc() {
		data := storedtx.UnbondingTxData

		unbondingInfo, err := staking.BuildUnbondingInfo(
			stakerBtcPk,
			storedtx.FinalityProvidersBtcPks,
			covenantPublicKeys,
			covenantThreshold,
			data.UnbondingTime,
			btcutil.Amount(data.UnbondingTx.TxOut[0].Value),
			net,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to build staking info while spending unbonding transaction: %w", err)
		}

		unbondingTimeLockPathInfo, err := unbondingInfo.TimeLockPathSpendInfo()

		if err != nil {
			return nil, fmt.Errorf("failed to build time lock path info while spending unbonding transaction: %w", err)
		}

		unbondingTxHash := data.UnbondingTx.TxHash()

		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			// unbonding tx has only one output
			data.UnbondingTx.TxOut[0],
			0,
			&unbondingTxHash,
			data.UnbondingTime,
			feeRate,
		)
		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:           spendTx,
			fundingOutput:          data.UnbondingTx.TxOut[0],
			fundingOutputSpendInfo: unbondingTimeLockPathInfo,
			calculatedFee:          *calculatedFee,
		}, nil
	}
	return nil, fmt.Errorf("cannot build spend stake transactions.Staking transaction is in invalid state: %s", storedtx.State)
}

type UnbondingSlashingDesc struct {
	UnbondingTransaction               *wire.MsgTx
	UnbondingTxValue                   btcutil.Amount
	UnbondingTxUnbondingTime           uint16
	SlashUnbondingTransaction          *wire.MsgTx
	SlashUnbondingTransactionSpendInfo *staking.SpendInfo
}

func createUndelegationData(
	storedTx *stakerdb.StoredTransaction,
	stakerPubKey *btcec.PublicKey,
	covenantPubKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	slashingPkScript []byte,
	unbondingTxFee btcutil.Amount,
	unbondingTime uint16,
	slashingFee btcutil.Amount,
	slashingRate sdkmath.LegacyDec,
	btcNetwork *chaincfg.Params,
) (*UnbondingSlashingDesc, error) {
	stakingTxHash := storedTx.StakingTx.TxHash()

	stakingOutpout := storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex]

	unbondingOutputValue := stakingOutpout.Value - int64(unbondingTxFee)

	if unbondingOutputValue <= 0 {
		return nil, fmt.Errorf(
			"staking output value:%d sats. Unbonding tx fee:%d sats", stakingOutpout.Value, int64(unbondingTxFee),
		)
	}

	if unbondingOutputValue <= int64(slashingFee) {
		return nil, fmt.Errorf(
			"unbonding output value %d sats. Slashing tx fee: %d sats", unbondingOutputValue, int64(slashingFee),
		)
	}

	unbondingInfo, err := staking.BuildUnbondingInfo(
		stakerPubKey,
		storedTx.FinalityProvidersBtcPks,
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
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, storedTx.StakingOutputIndex), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		slashingPkScript,
		stakerPubKey,
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

// buildUnbondingSpendInfo
func buildUnbondingSpendInfo(
	stakerPubKey *btcec.PublicKey,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData,
	params *cl.StakingParams,
	net *chaincfg.Params,
) (*staking.SpendInfo, error) {
	if storedTx.State < proto.TransactionState_DELEGATION_ACTIVE {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Staking transaction is in invalid state: %s", storedTx.State)
	}

	if unbondingData.UnbondingTx == nil {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain unbonding transaction")
	}

	if len(unbondingData.CovenantSignatures) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain all necessary signatures. Required: %d, received: %d", params.CovenantQuruomThreshold, len(unbondingData.CovenantSignatures))
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		storedTx.FinalityProvidersBtcPks,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		storedTx.StakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		net,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: %w", err)
	}

	unbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding path info: %w", err)
	}

	return unbondingPathInfo, nil
}

func parseWatchStakingRequest(
	stakingTx *wire.MsgTx,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpBtcPks []*btcec.PublicKey,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonAddr sdk.AccAddress,
	stakerBtcPk *btcec.PublicKey,
	stakerAddress btcutil.Address,
	pop *cl.BabylonPop,
	unbondingTx *wire.MsgTx,
	slashUnbondingTx *wire.MsgTx,
	slashUnbondingTxSig *schnorr.Signature,
	unbondingTime uint16,
	currentParams *cl.StakingParams,
	network *chaincfg.Params,
) (*stakingRequestCmd, error) {
	// TODO(https://github.com/babylonlabs-io/btc-staker/issues/32):
	// This check re-implements whole babylon validation logic. We should
	// refactor this to use babylon validation utilities.
	if stakingTime < currentParams.MinStakingTime || stakingTime > currentParams.MaxStakingTime {
		return nil, fmt.Errorf("staking time %d is not in range [%d, %d]",
			stakingTime, currentParams.MinStakingTime, currentParams.MaxStakingTime)
	}

	if stakingValue < currentParams.MinStakingValue || stakingValue > currentParams.MaxStakingValue {
		return nil, fmt.Errorf("staking amount %d is not in range [%d, %d]",
			stakingValue, currentParams.MinStakingValue, currentParams.MaxStakingValue)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerBtcPk,
		fpBtcPks,
		currentParams.CovenantPks,
		currentParams.CovenantQuruomThreshold,
		stakingTime,
		stakingValue,
		network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx due to invalid staking info: %w", err)
	}

	stakingOutputIdx, err := bbn.GetOutputIdxInBTCTx(stakingTx, stakingInfo.StakingOutput)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx due to tx not matching current data: %w", err)
	}

	if unbondingTime != currentParams.UnbondingTime {
		return nil, fmt.Errorf("failed to watch staking tx. Unbonding time must be equal to unbonding time in babylon. Unbonding time: %d, unbonding time in babylon: %d", unbondingTime, currentParams.UnbondingTime)
	}

	// 2. Check whether slashing tx match staking tx
	err = staking.CheckSlashingTxMatchFundingTx(
		slashingTx,
		stakingTx,
		stakingOutputIdx,
		int64(currentParams.MinSlashingTxFeeSat),
		currentParams.SlashingRate,
		currentParams.SlashingPkScript,
		stakerBtcPk,
		unbondingTime,
		network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid transactions: %w", err)
	}

	stakingTxSlashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid staking path info: %w", err)
	}

	// 4. Check slashig tx sig is good. It implicitly verify staker pubkey, as script
	// contain it.
	err = staking.VerifyTransactionSigWithOutput(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx],
		stakingTxSlashingPathInfo.RevealedLeaf.Script,
		stakerBtcPk,
		slashingTxSig.Serialize(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx sig: %w", err)
	}

	// 5. Validate pop
	if err = pop.ValidatePop(stakerBabylonAddr, stakerBtcPk, network); err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid pop: %w", err)
	}

	// 6. Validate unbonding related data
	if err := staking.IsSimpleTransfer(unbondingTx); err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid unbonding tx: %w", err)
	}

	unbondingTxValue := unbondingTx.TxOut[0].Value
	unbondingTxPkScript := unbondingTx.TxOut[0].PkScript

	unbondingValue := btcutil.Amount(unbondingTxValue)

	unbondingInfo, err := staking.BuildUnbondingInfo(
		stakerBtcPk,
		fpBtcPks,
		currentParams.CovenantPks,
		currentParams.CovenantQuruomThreshold,
		unbondingTime,
		unbondingValue,
		network,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Failed to build unbonding scripts: %w", err)
	}

	if unbondingInfo.UnbondingOutput.Value != unbondingTxValue || !bytes.Equal(unbondingInfo.UnbondingOutput.PkScript, unbondingTxPkScript) {
		return nil, fmt.Errorf("failed to watch staking tx. Unbonding output does not match output produced from provided values")
	}

	err = staking.CheckSlashingTxMatchFundingTx(
		slashUnbondingTx,
		unbondingTx,
		0,
		int64(currentParams.MinSlashingTxFeeSat),
		currentParams.SlashingRate,
		currentParams.SlashingPkScript,
		stakerBtcPk,
		unbondingTime,
		network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slash-unbonding transaction: %w", err)
	}

	unbondingSlashingInfo, err := unbondingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid unbonding slashing path info: %w", err)
	}

	err = staking.VerifyTransactionSigWithOutput(
		slashUnbondingTx,
		unbondingTx.TxOut[0],
		unbondingSlashingInfo.RevealedLeaf.Script,
		stakerBtcPk,
		slashUnbondingTxSig.Serialize(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx sig: %w", err)
	}

	if unbondingTx.TxOut[0].Value >= stakingTx.TxOut[stakingOutputIdx].Value {
		return nil, fmt.Errorf("failed to watch staking tx. Unbonding tx value must be less than staking output value")
	}

	if stakingTx.TxOut[stakingOutputIdx].Value-unbondingTx.TxOut[0].Value != int64(currentParams.UnbondingFee) {
		return nil, fmt.Errorf("failed to watch staking tx. unbonding tx fee must be equal to %d, and it is equal to %d",
			currentParams.UnbondingFee,
			unbondingTx.TxOut[0].Value-stakingTx.TxOut[stakingOutputIdx].Value)
	}

	stakingTxHash := stakingTx.TxHash()
	unbondingTxPointsToStakingTxHash := unbondingTx.TxIn[0].PreviousOutPoint.Hash.IsEqual(&stakingTxHash)
	unbondingTxPointsToStakingOutputIdx := unbondingTx.TxIn[0].PreviousOutPoint.Index == stakingOutputIdx

	if !unbondingTxPointsToStakingTxHash || !unbondingTxPointsToStakingOutputIdx {
		return nil, fmt.Errorf("failed to watch staking tx. Unbonding tx do not point to staking tx")
	}

	req := newWatchedStakingCmd(
		stakerAddress,
		stakingTx,
		stakingOutputIdx,
		stakingTx.TxOut[stakingOutputIdx].PkScript,
		stakingTime,
		stakingValue,
		fpBtcPks,
		currentParams.ConfirmationTimeBlocks,
		pop,
		slashingTx,
		slashingTxSig,
		stakerBabylonAddr,
		stakerBtcPk,
		unbondingTx,
		slashUnbondingTx,
		slashUnbondingTxSig,
		unbondingTime,
	)

	return req, nil
}

func haveDuplicates(btcPKs []*btcec.PublicKey) bool {
	seen := make(map[string]struct{})

	for _, btcPK := range btcPKs {
		pkStr := hex.EncodeToString(schnorr.SerializePubKey(btcPK))

		if _, found := seen[pkStr]; found {
			return true
		}
		seen[pkStr] = struct{}{}
	}

	return false
}
