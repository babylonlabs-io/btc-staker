package staker

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	sdkmath "cosmossdk.io/math"
	staking "github.com/babylonlabs-io/babylon/v4/btcstaking"
	"github.com/babylonlabs-io/babylon/v4/types"

	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/utils"
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

// pubKeyToString converts a public key to a string
func pubKeyToString(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(pubKey))
}

// createWitnessSignaturesForPubKeys creates a witness script for a given covenant
func createWitnessSignaturesForPubKeys(
	covenantPubKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	receivedSignaturePairs []cl.CovenantSignatureInfo,
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

// slashingTxForStakingTx creates a slapping transaction for a given staking transaction
func slashingTxForStakingTx(
	slashingFee btcutil.Amount,
	delegationData *externalDelegationData,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	fpBtcPubkeys []*btcec.PublicKey,
	net *chaincfg.Params,
) (*wire.MsgTx, *staking.SpendInfo, error) {
	stakerPubKey := delegationData.stakerPublicKey
	lockSlashTxLockTime := delegationData.babylonParams.UnbondingTime

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		storedTx.StakingTx,
		stakingOutputIndex,
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
		fpBtcPubkeys,
		delegationData.babylonParams.CovenantPks,
		delegationData.babylonParams.CovenantQuruomThreshold,
		stakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[stakingOutputIndex].Value),
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

// createDelegationData creates a delegation data from a send delegation request
func createDelegationData(
	req *sendDelegationRequest,
	stakerBtcPk *btcec.PublicKey,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	babylonStakerAddr sdk.AccAddress,
	undelegationData *cl.UndelegationData,
) *cl.DelegationData {
	var incInfo *cl.StakingTransactionInclusionInfo

	inclusionInfo := req.inclusionInfo
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
		StakingTime:                     stakingTime,
		StakingValue:                    btcutil.Amount(storedTx.StakingTx.TxOut[stakingOutputIndex].Value),
		FinalityProvidersBtcPks:         req.fpBtcPubkeys,
		StakerBtcPk:                     stakerBtcPk,
		SlashingTransaction:             slashingTx,
		SlashingTransactionSig:          slashingTxSignature,
		BabylonStakerAddr:               babylonStakerAddr,
		BabylonPop:                      req.pop,
		Ud:                              undelegationData,
	}

	// Add expansion data if this is a stake expansion
	if req.prevActiveStkTxHash != nil {
		dg.StakeExpansion = &cl.StakeExpansionData{
			PreviousStakingTxHash: req.prevActiveStkTxHash,
			FundingTx:             req.fundingTx,
		}
	}

	return &dg
}

func createDelegationDataMultisig(
	req *sendDelegationRequest,
	mainStakerBtcPk *btcec.PublicKey,
	extraStakerBtcPks []*btcec.PublicKey,
	stakerQuorum uint32,
	extraStakingSlashingSigs []*schnorr.Signature,
	extraUnbondingSlashingSigs []*schnorr.Signature,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	mainSlashingTxSignature *schnorr.Signature,
	babylonStakerAddr sdk.AccAddress,
	undelegationData *cl.UndelegationData,
) *cl.DelegationData {
	dg := createDelegationData(
		req,
		mainStakerBtcPk,
		stakingOutputIndex,
		stakingTime,
		storedTx,
		slashingTx,
		mainSlashingTxSignature,
		babylonStakerAddr,
		undelegationData,
	)

	dg.MultisigInfo = &cl.MultisigStakerInfo{
		StakerBtcPks:                   extraStakerBtcPks,
		StakerQuorum:                   stakerQuorum,
		DelegatorSlashingSigs:          extraStakingSlashingSigs,
		DelegatorUnbondingSlashingSigs: extraUnbondingSlashingSigs,
	}

	return dg
}

// createSpendStakeTx creates a spend stake transaction.
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

	// sanity check that transaction is standard
	if err := utils.CheckTransaction(spendTx); err != nil {
		return nil, nil, fmt.Errorf("failed to build spend stake tx: %w", err)
	}

	return spendTx, &fee, nil
}

// createSpendStakeTxUnbondingConfirmed creates a spend stake transaction
// that is already confirmed on the Bitcoin network.
func createSpendStakeTxUnbondingConfirmed(
	stakerBtcPk *btcec.PublicKey,
	fpBtcPubkeys []*btcec.PublicKey,
	covenantPublicKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	destinationScript []byte,
	feeRate chainfee.SatPerKVByte,
	undelegationInfo *cl.UndelegationInfo,
	net *chaincfg.Params,
) (*spendStakeTxInfo, error) {
	unbondingInfo, err := staking.BuildUnbondingInfo(
		stakerBtcPk,
		fpBtcPubkeys,
		covenantPublicKeys,
		covenantThreshold,
		undelegationInfo.UnbondingTime,
		btcutil.Amount(undelegationInfo.UnbondingTransaction.TxOut[0].Value),
		net,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build staking info while spending unbonding transaction: %w", err)
	}

	unbondingTimeLockPathInfo, err := unbondingInfo.TimeLockPathSpendInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to build time lock path info while spending unbonding transaction: %w", err)
	}

	unbondingTxHash := undelegationInfo.UnbondingTransaction.TxHash()
	spendTx, calculatedFee, err := createSpendStakeTx(
		destinationScript,
		// unbonding tx has only one output
		undelegationInfo.UnbondingTransaction.TxOut[0],
		0,
		&unbondingTxHash,
		undelegationInfo.UnbondingTime,
		feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create spend stake tx while spending unbonding transaction: %w", err)
	}

	return &spendStakeTxInfo{
		spendStakeTx:           spendTx,
		fundingOutput:          undelegationInfo.UnbondingTransaction.TxOut[0],
		fundingOutputSpendInfo: unbondingTimeLockPathInfo,
		calculatedFee:          *calculatedFee,
	}, nil
}

// createSpendStakeTxUnbondingNotConfirmed creates a spend stake transaction
// that is not confirmed yet.
func createSpendStakeTxUnbondingNotConfirmed(
	stakerBtcPk *btcec.PublicKey,
	stakingOutputIndex uint32,
	stakingTime uint16,
	fpBtcPubkeys []*btcec.PublicKey,
	covenantPublicKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	storedtx *stakerdb.StoredTransaction,
	destinationScript []byte,
	feeRate chainfee.SatPerKVByte,
	net *chaincfg.Params,
) (*spendStakeTxInfo, error) {
	stakingInfo, err := staking.BuildStakingInfo(
		stakerBtcPk,
		fpBtcPubkeys,
		covenantPublicKeys,
		covenantThreshold,
		stakingTime,
		btcutil.Amount(storedtx.StakingTx.TxOut[stakingOutputIndex].Value),
		net,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build staking info while spending staking transaction: %w", err)
	}

	stakingTimeLockPathInfo, err := stakingInfo.TimeLockPathSpendInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to build time lock path info while spending staking transaction: %w", err)
	}

	// transaction is only in sent to babylon state we try to spend staking output directly
	stakingTxHash := storedtx.StakingTx.TxHash()
	spendTx, calculatedFee, err := createSpendStakeTx(
		destinationScript,
		storedtx.StakingTx.TxOut[stakingOutputIndex],
		stakingOutputIndex,
		&stakingTxHash,
		stakingTime,
		feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create spend stake tx while spending staking transaction: %w", err)
	}

	return &spendStakeTxInfo{
		spendStakeTx:           spendTx,
		fundingOutputSpendInfo: stakingTimeLockPathInfo,
		fundingOutput:          storedtx.StakingTx.TxOut[stakingOutputIndex],
		calculatedFee:          *calculatedFee,
	}, nil
}

// UnbondingSlashingDesc contains all data needed to build and sign unbonding
// and slashing transactions for a delegation.
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
	fpBtcPubkeys []*btcec.PublicKey,
	stakingOutputIndex uint32,
	btcNetwork *chaincfg.Params,
) (*UnbondingSlashingDesc, error) {
	stakingTxHash := storedTx.StakingTx.TxHash()

	stakingOutpout := storedTx.StakingTx.TxOut[stakingOutputIndex]

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
	fpBtcPubkeys []*btcec.PublicKey,
	storedTx *stakerdb.StoredTransaction,
	stakingOutputIndex uint32,
	stakingTime uint16,
	undelegationInfo *cl.UndelegationInfo,
	params *cl.StakingParams,
	net *chaincfg.Params,
) (*staking.SpendInfo, error) {
	if undelegationInfo.UnbondingTransaction == nil {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain unbonding transaction")
	}

	if len(undelegationInfo.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain all necessary signatures. Required: %d, received: %d", params.CovenantQuruomThreshold, len(undelegationInfo.CovenantUnbondingSignatures))
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		fpBtcPubkeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		stakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[stakingOutputIndex].Value),
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

// haveDuplicates checks if there are any duplicates in a slice of public keys
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

// convertFpBtcPkToBtcPk converts a slice of finality provider btc pks to a slice of btc pks
func convertFpBtcPkToBtcPk(fpBtcPKs []types.BIP340PubKey) ([]*btcec.PublicKey, error) {
	fpPubkeys := make([]*btcec.PublicKey, len(fpBtcPKs))
	for i, pk := range fpBtcPKs {
		fpPubkey, err := schnorr.ParsePubKey(pk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse finality provider btc pk: %w", err)
		}
		fpPubkeys[i] = fpPubkey
	}
	return fpPubkeys, nil
}
