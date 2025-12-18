// Package babylonclient provides helpers for communicating with the Babylon chain.
package babylonclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	sdkErr "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/avast/retry-go/v4"
	bct "github.com/babylonlabs-io/babylon/v4/client/babylonclient"
	bbnclient "github.com/babylonlabs-io/babylon/v4/client/client"
	bbntypes "github.com/babylonlabs-io/babylon/v4/types"
	btcctypes "github.com/babylonlabs-io/babylon/v4/x/btccheckpoint/types"
	btclctypes "github.com/babylonlabs-io/babylon/v4/x/btclightclient/types"
	btcstypes "github.com/babylonlabs-io/babylon/v4/x/btcstaking/types"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	bq "github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

var (
	// RtyAttNum controls how many times Babylon RPC calls are retried.
	RtyAttNum = uint(5)
	// RtyAtt configures the retry attempts for the retry-go helper.
	RtyAtt = retry.Attempts(RtyAttNum)
	// RtyDel defines the delay between retry attempts when querying Babylon.
	RtyDel = retry.Delay(time.Millisecond * 600)
	// RtyErr instructs retry-go to return only the last error.
	RtyErr = retry.LastErrorOnly(true)
)

var (
	// ErrInvalidBabylonExecution indicates Babylon executed a message with an error code.
	ErrInvalidBabylonExecution = errors.New("message send to babylon was executed with error")
	// ErrHeaderNotKnownToBabylon indicates the queried BTC header is unknown to Babylon.
	ErrHeaderNotKnownToBabylon = errors.New("btc header not known to babylon")
	// ErrHeaderOnBabylonLCFork marks headers that belong to a stale LC fork.
	ErrHeaderOnBabylonLCFork = errors.New("btc header is on babylon btc light client fork")
	// ErrFinalityProviderDoesNotExist indicates the provider was not registered on Babylon.
	ErrFinalityProviderDoesNotExist = errors.New("finality provider does not exist")
	// ErrFinalityProviderIsSlashed indicates the provider has been slashed.
	ErrFinalityProviderIsSlashed = errors.New("finality provider is slashed")
	// ErrDelegationNotFound indicates Babylon has no record of the delegation.
	ErrDelegationNotFound = errors.New("delegation not found")
	// ErrInvalidValueReceivedFromBabylonNode indicates Babylon returned malformed data.
	ErrInvalidValueReceivedFromBabylonNode = errors.New("invalid value received from babylon node")
)

// BabylonController is a controller for Babylon client.
type BabylonController struct {
	bbnClient *bbnclient.Client
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
	logger    *logrus.Logger
}

var _ BabylonClient = (*BabylonController)(nil)

// NewBabylonController creates a new BabylonController instance
func NewBabylonController(
	cfg *stakercfg.BBNConfig,
	btcParams *chaincfg.Params,
	logger *logrus.Logger,
	clientLogger *zap.Logger,
) (*BabylonController, error) {
	babylonConfig := stakercfg.BBNConfigToBabylonConfig(cfg)

	// TODO should be validated earlier
	if err := babylonConfig.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate babylon config: %w", err)
	}

	bc, err := bbnclient.New(
		&babylonConfig,
		clientLogger,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create babylon client: %w", err)
	}

	// wrap to our type
	client := &BabylonController{
		bc,
		cfg,
		btcParams,
		logger,
	}

	return client, nil
}

// StakingTrackerResponse is a response from the staking tracker
type StakingTrackerResponse struct {
	SlashingPkScript          []byte
	SlashingRate              sdkmath.LegacyDec
	MinComissionRate          sdkmath.LegacyDec
	CovenantPks               []*btcec.PublicKey
	CovenantQuruomThreshold   uint32
	MinSlashingFee            btcutil.Amount
	UnbondingTime             uint16
	UnbondingFee              btcutil.Amount
	MinStakingTime            uint16
	MaxStakingTime            uint16
	MinStakingValue           btcutil.Amount
	MaxStakingValue           btcutil.Amount
	AllowListExpirationHeight uint64
}

// FinalityProviderInfo is a response from the finality provider tracker
type FinalityProviderInfo struct {
	BabylonAddr sdk.AccAddress
	BtcPk       btcec.PublicKey
}

// FinalityProvidersClientResponse is a response from the finality providers tracker
type FinalityProvidersClientResponse struct {
	FinalityProviders []FinalityProviderInfo
	Total             uint64
}

// FinalityProviderClientResponse is a response from the finality provider tracker
type FinalityProviderClientResponse struct {
	FinalityProvider FinalityProviderInfo
}

// Stop shuts down the underlying Babylon client.
func (bc *BabylonController) Stop() error {
	return bc.bbnClient.Stop()
}

// btccheckpointParamsWithRetry is a helper function to query the babylon client for the btc checkpoint parameters
func (bc *BabylonController) btccheckpointParamsWithRetry() (*BTCCheckpointParams, error) {
	var bccParams *BTCCheckpointParams
	if err := retry.Do(func() error {
		response, err := bc.bbnClient.BTCCheckpointParams()
		if err != nil {
			return fmt.Errorf("failed to get btc checkpoint params: %w", err)
		}

		bccParams = &BTCCheckpointParams{
			ConfirmationTimeBlocks:    response.Params.BtcConfirmationDepth,
			FinalizationTimeoutBlocks: response.Params.CheckpointFinalizationTimeout,
		}

		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for btc checkpoint params")
	})); err != nil {
		return nil, fmt.Errorf("failed to get btc checkpoint params after multiple retries: %w", err)
	}

	return bccParams, nil
}

// BTCCheckpointParams is a helper function to query the babylon client for the btc checkpoint parameters
func (bc *BabylonController) BTCCheckpointParams() (*BTCCheckpointParams, error) {
	return bc.btccheckpointParamsWithRetry()
}

// QueryStakingTrackerWithRetries is a helper function to query the babylon client for the staking tracker parameters
func (bc *BabylonController) queryStakingTrackerWithRetries() (*StakingTrackerResponse, error) {
	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTracker()
		if err != nil {
			return fmt.Errorf("failed to get staking tracker params: %w", err)
		}
		stakingTrackerParams = trackerParams
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for staking tracker params")
	})); err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params after multiple retries: %w", err)
	}

	return stakingTrackerParams, nil
}

// Params is a helper function to query the babylon client for the staking parameters
func (bc *BabylonController) Params() (*StakingParams, error) {
	bccParams, err := bc.btccheckpointParamsWithRetry()

	if err != nil {
		return nil, fmt.Errorf("failed to get btc checkpoint params: %w", err)
	}

	stakingTrackerParams, err := bc.queryStakingTrackerWithRetries()

	if err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params: %w", err)
	}

	return &StakingParams{
		BTCCheckpointParams: *bccParams,
		BtcStakingParams:    BtcStakingParamsFromStakingTracker(stakingTrackerParams),
	}, nil
}

// queryStakingTrackerByBtcHeightWithRetries is a helper function to query the babylon client for the staking tracker parameters by btc height
func (bc *BabylonController) queryStakingTrackerByBtcHeightWithRetries(
	btcHeight uint32,
) (*StakingTrackerResponse, error) {
	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTrackerByBtcHeight(btcHeight)
		if err != nil {
			return fmt.Errorf("failed to get staking tracker params by btc height: %w", err)
		}
		stakingTrackerParams = trackerParams
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for staking tracker params")
	})); err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params by btc height after multiple retries: %w", err)
	}

	return stakingTrackerParams, nil
}

// queryStakingTrackerByVersionWithRetries is a helper function to query the babylon client for the staking tracker parameters by version
func (bc *BabylonController) queryStakingTrackerByVersionWithRetries(
	version uint32,
) (*StakingTrackerResponse, error) {
	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTrackerByVersion(version)
		if err != nil {
			return fmt.Errorf("failed to get staking tracker params by version: %w", err)
		}
		stakingTrackerParams = trackerParams
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for staking tracker params")
	})); err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params by version after multiple retries: %w", err)
	}

	return stakingTrackerParams, nil
}

// ParamsByBtcHeight is a helper function to query the babylon client for the staking parameters by btc height
func (bc *BabylonController) ParamsByBtcHeight(btcHeight uint32) (*StakingParams, error) {
	bccParams, err := bc.btccheckpointParamsWithRetry()

	if err != nil {
		return nil, fmt.Errorf("failed to get btc checkpoint params: %w", err)
	}

	stakingTrackerParams, err := bc.queryStakingTrackerByBtcHeightWithRetries(btcHeight)

	if err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params by btc height with retries: %w", err)
	}

	return &StakingParams{
		BTCCheckpointParams: *bccParams,
		BtcStakingParams:    BtcStakingParamsFromStakingTracker(stakingTrackerParams),
	}, nil
}

// ParamsByVersion is a helper function to query the babylon client for the staking parameters by version
func (bc *BabylonController) ParamsByVersion(version uint32) (*BtcStakingParams, error) {
	stakingTrackerParams, err := bc.queryStakingTrackerByVersionWithRetries(version)
	if err != nil {
		return nil, fmt.Errorf("failed to get staking tracker params by version with retries: %w", err)
	}
	p := BtcStakingParamsFromStakingTracker(stakingTrackerParams)

	return &p, nil
}

// GetKeyAddress is a helper function to get the key address
func (bc *BabylonController) GetKeyAddress() sdk.AccAddress {
	// get key address, retrieves address based on key name which is configured in
	// cfg *stakercfg.BBNConfig. If this fails, it means we have misconfiguration problem
	// and we should panic.
	// This is checked at the start of BabylonController, so if it fails something is really wrong

	keyRec, err := bc.bbnClient.GetKeyring().Key(bc.cfg.Key)

	if err != nil {
		panic(fmt.Sprintf("Failed to get key address: %s", err))
	}

	addr, err := keyRec.GetAddress()

	if err != nil {
		panic(fmt.Sprintf("Failed to get key address: %s", err))
	}

	return addr
}

// GetLatestBlockHeight is a helper function to get the latest block height
func (bc *BabylonController) GetLatestBlockHeight() (uint64, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	status, err := bc.bbnClient.RPCClient.Status(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block height: %w", err)
	}

	return uint64(status.SyncInfo.LatestBlockHeight), nil
}

// getTxSigner is a helper function to get the transaction signer
func (bc *BabylonController) getTxSigner() string {
	signer := bc.GetKeyAddress()
	prefix := bc.cfg.AccountPrefix
	return sdk.MustBech32ifyAddressBytes(prefix, signer)
}

// getPubKeyInternal is a helper function to get the public key
func (bc *BabylonController) getPubKeyInternal() (*secp256k1.PubKey, error) {
	record, err := bc.bbnClient.GetKeyring().KeyByAddress(bc.GetKeyAddress())

	if err != nil {
		return nil, fmt.Errorf("failed to get key record: %w", err)
	}

	pubKey, err := record.GetPubKey()

	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	switch v := pubKey.(type) {
	case *secp256k1.PubKey:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported key type in keyring")
	}
}

// GetPubKey is a helper function to get the public key
func (bc *BabylonController) GetPubKey() *secp256k1.PubKey {
	pubKey, err := bc.getPubKeyInternal()

	if err != nil {
		panic(fmt.Sprintf("Failed to get public key: %v", err))
	}

	return pubKey
}

// Sign is a helper function to sign a message
func (bc *BabylonController) Sign(msg []byte) ([]byte, error) {
	sign, kt, err := bc.bbnClient.GetKeyring().SignByAddress(bc.GetKeyAddress(), msg, signing.SignMode_SIGN_MODE_DIRECT)

	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	switch v := kt.(type) {
	case *secp256k1.PubKey:
		return sign, nil
	default:
		panic(fmt.Sprintf("Unsupported key type in keyring: %s", v.Type()))
	}
}

// StakingTransactionInclusionInfo is a helper struct to hold the staking transaction
type StakingTransactionInclusionInfo struct {
	StakingTransactionIdx                uint32
	StakingTransactionInclusionProof     []byte
	StakingTransactionInclusionBlockHash *chainhash.Hash
}

// DelegationData is a helper struct to hold the delegation data
type DelegationData struct {
	StakingTransaction *wire.MsgTx
	// Optional field, if not provided, delegation will be send to Babylon without
	// the inclusion proof
	StakingTransactionInclusionInfo *StakingTransactionInclusionInfo
	StakingTime                     uint16
	StakingValue                    btcutil.Amount
	FinalityProvidersBtcPks         []*btcec.PublicKey
	SlashingTransaction             *wire.MsgTx
	SlashingTransactionSig          *schnorr.Signature
	BabylonStakerAddr               sdk.AccAddress
	StakerBtcPk                     *btcec.PublicKey
	BabylonPop                      *BabylonPop
	Ud                              *UndelegationData
	StakeExpansion                  *StakeExpansionData
	MultisigInfo                    *MultisigStakerInfo
}

// MultisigStakerInfo holds additional staker information for M-of-N multisig
// BTC delegations. It intentionally excludes the "main" staker pubkey/signatures
// which are carried in the top-level fields of MsgCreateBTCDelegation.
type MultisigStakerInfo struct {
	StakerBtcPks                   []*btcec.PublicKey
	StakerQuorum                   uint32
	DelegatorSlashingSigs          []*schnorr.Signature
	DelegatorUnbondingSlashingSigs []*schnorr.Signature
}

// StakeExpansionData holds data specific to stake expansion transactions
type StakeExpansionData struct {
	PreviousStakingTxHash *chainhash.Hash
	FundingTx             *wire.MsgTx
}

// UndelegationData is a helper struct to hold the undelegation data
type UndelegationData struct {
	UnbondingTransaction         *wire.MsgTx
	UnbondingTxValue             btcutil.Amount
	UnbondingTxUnbondingTime     uint16
	SlashUnbondingTransaction    *wire.MsgTx
	SlashUnbondingTransactionSig *schnorr.Signature
}

// UndelegationRequest is a helper struct to hold the undelegation request
type UndelegationRequest struct {
	StakingTxHash      chainhash.Hash
	StakerUnbondingSig *schnorr.Signature
}

// CovenantSignatureInfo is a helper struct to hold the covenant signature info
type CovenantSignatureInfo struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

// UndelegationInfo is a helper struct to hold the undelegation info
type UndelegationInfo struct {
	CovenantUnbondingSignatures []CovenantSignatureInfo
	UnbondingTransaction        *wire.MsgTx
	UnbondingTime               uint16
}

// DelegationInfo is a helper struct to hold the delegation info
type DelegationInfo struct {
	Status           string
	UndelegationInfo *UndelegationInfo
}

// delegationDataToMsg is a helper function to convert delegation data to message
func delegationDataToMsg(dg *DelegationData) (*btcstypes.MsgCreateBTCDelegation, error) {
	if dg == nil {
		return nil, fmt.Errorf("nil delegation data")
	}

	if dg.Ud == nil {
		return nil, fmt.Errorf("nil undelegation data")
	}

	serizalizedStakingTransaction, err := utils.SerializeBtcTransaction(dg.StakingTransaction)

	if err != nil {
		return nil, fmt.Errorf("failed to serialize btc transaction: %w", err)
	}

	slashingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.SlashingTransaction)

	if err != nil {
		return nil, fmt.Errorf("failed to create slashing tx from msg tx: %w", err)
	}

	slashingTxSig := bbntypes.NewBIP340SignatureFromBTCSig(dg.SlashingTransactionSig)

	if len(dg.FinalityProvidersBtcPks) == 0 {
		return nil, fmt.Errorf("received delegation data with no finality providers")
	}

	fpPksList := make([]bbntypes.BIP340PubKey, len(dg.FinalityProvidersBtcPks))

	for i, fpPk := range dg.FinalityProvidersBtcPks {
		fpPksList[i] = *bbntypes.NewBIP340PubKeyFromBTCPK(fpPk)
	}

	// Prepare undelegation data to be sent in message
	if dg.Ud.SlashUnbondingTransaction == nil ||
		dg.Ud.SlashUnbondingTransactionSig == nil ||
		dg.Ud.UnbondingTransaction == nil {
		return nil, fmt.Errorf("received unbonding data with nil field")
	}

	serializedUnbondingTransaction, err := utils.SerializeBtcTransaction(dg.Ud.UnbondingTransaction)

	if err != nil {
		return nil, fmt.Errorf("failed to serialize btc transaction: %w", err)
	}

	slashUnbondingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.Ud.SlashUnbondingTransaction)

	if err != nil {
		return nil, fmt.Errorf("failed to create slashing tx from msg tx: %w", err)
	}

	slashUnbondingTxSig := bbntypes.NewBIP340SignatureFromBTCSig(dg.Ud.SlashUnbondingTransactionSig)

	var stakingTransactionInclusionProof *btcstypes.InclusionProof

	if dg.StakingTransactionInclusionInfo != nil {
		inclusionBlockHash := bbntypes.NewBTCHeaderHashBytesFromChainhash(
			dg.StakingTransactionInclusionInfo.StakingTransactionInclusionBlockHash,
		)
		txKey := &btcctypes.TransactionKey{
			Index: dg.StakingTransactionInclusionInfo.StakingTransactionIdx,
			Hash:  &inclusionBlockHash,
		}
		stakingTransactionInclusionProof = btcstypes.NewInclusionProof(
			txKey,
			dg.StakingTransactionInclusionInfo.StakingTransactionInclusionProof,
		)
	}

	msg := &btcstypes.MsgCreateBTCDelegation{
		// Note: this should be always safe conversion as we received data from our db
		StakerAddr: dg.BabylonStakerAddr.String(),
		Pop: &btcstypes.ProofOfPossessionBTC{
			BtcSigType: btcstypes.BTCSigType(dg.BabylonPop.popType),
			BtcSig:     dg.BabylonPop.BtcSig,
		},
		BtcPk:                   bbntypes.NewBIP340PubKeyFromBTCPK(dg.StakerBtcPk),
		FpBtcPkList:             fpPksList,
		StakingTime:             uint32(dg.StakingTime),
		StakingValue:            int64(dg.StakingValue),
		StakingTx:               serizalizedStakingTransaction,
		StakingTxInclusionProof: stakingTransactionInclusionProof,
		SlashingTx:              slashingTx,
		// Data related to unbonding
		DelegatorSlashingSig:          slashingTxSig,
		UnbondingTx:                   serializedUnbondingTransaction,
		UnbondingTime:                 uint32(dg.Ud.UnbondingTxUnbondingTime),
		UnbondingValue:                int64(dg.Ud.UnbondingTxValue),
		UnbondingSlashingTx:           slashUnbondingTx,
		DelegatorUnbondingSlashingSig: slashUnbondingTxSig,
	}

	// in case of multisig btc delegation, it populates DelegationData and adds to MsgCreateBTCDelegation
	if dg.MultisigInfo != nil {
		if len(dg.MultisigInfo.StakerBtcPks) != len(dg.MultisigInfo.DelegatorSlashingSigs) ||
			len(dg.MultisigInfo.StakerBtcPks) != len(dg.MultisigInfo.DelegatorUnbondingSlashingSigs) {
			return nil, fmt.Errorf("invalid multisig info: pubkey/sig list lengths mismatch")
		}

		stakerPkList := make([]bbntypes.BIP340PubKey, 0, len(dg.MultisigInfo.StakerBtcPks))
		slashingSigs := make([]*btcstypes.SignatureInfo, 0, len(dg.MultisigInfo.StakerBtcPks))
		unbondingSigs := make([]*btcstypes.SignatureInfo, 0, len(dg.MultisigInfo.StakerBtcPks))

		for i, pk := range dg.MultisigInfo.StakerBtcPks {
			if pk == nil || dg.MultisigInfo.DelegatorSlashingSigs[i] == nil || dg.MultisigInfo.DelegatorUnbondingSlashingSigs[i] == nil {
				return nil, fmt.Errorf("invalid multisig info: nil key or signature")
			}

			bip340Pk := bbntypes.NewBIP340PubKeyFromBTCPK(pk)
			stakerPkList = append(stakerPkList, *bip340Pk)

			slashingSigs = append(slashingSigs, &btcstypes.SignatureInfo{
				Pk:  bip340Pk,
				Sig: bbntypes.NewBIP340SignatureFromBTCSig(dg.MultisigInfo.DelegatorSlashingSigs[i]),
			})
			unbondingSigs = append(unbondingSigs, &btcstypes.SignatureInfo{
				Pk:  bip340Pk,
				Sig: bbntypes.NewBIP340SignatureFromBTCSig(dg.MultisigInfo.DelegatorUnbondingSlashingSigs[i]),
			})
		}

		msg.MultisigInfo = &btcstypes.AdditionalStakerInfo{
			StakerBtcPkList:                stakerPkList,
			StakerQuorum:                   dg.MultisigInfo.StakerQuorum,
			DelegatorSlashingSigs:          slashingSigs,
			DelegatorUnbondingSlashingSigs: unbondingSigs,
		}
	}

	return msg, nil
}

// delegationDataToMsgBtcStakeExpand is a helper function to convert delegation data to stake expansion message
func delegationDataToMsgBtcStakeExpand(dg *DelegationData) (*btcstypes.MsgBtcStakeExpand, error) {
	if dg == nil {
		return nil, fmt.Errorf("nil delegation data")
	}

	if dg.StakeExpansion == nil {
		return nil, fmt.Errorf("nil stake expansion data")
	}

	// First get the common delegation message
	commonMsg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, fmt.Errorf("failed to create common delegation message: %w", err)
	}

	// Serialize the funding transaction
	serializedFundingTx, err := utils.SerializeBtcTransaction(dg.StakeExpansion.FundingTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize funding transaction: %w", err)
	}

	// Create the stake expansion message with all fields from common delegation
	return &btcstypes.MsgBtcStakeExpand{
		StakerAddr:                    commonMsg.StakerAddr,
		Pop:                           commonMsg.Pop,
		BtcPk:                         commonMsg.BtcPk,
		FpBtcPkList:                   commonMsg.FpBtcPkList,
		StakingTime:                   commonMsg.StakingTime,
		StakingValue:                  commonMsg.StakingValue,
		StakingTx:                     commonMsg.StakingTx,
		SlashingTx:                    commonMsg.SlashingTx,
		DelegatorSlashingSig:          commonMsg.DelegatorSlashingSig,
		UnbondingTx:                   commonMsg.UnbondingTx,
		UnbondingTime:                 commonMsg.UnbondingTime,
		UnbondingValue:                commonMsg.UnbondingValue,
		UnbondingSlashingTx:           commonMsg.UnbondingSlashingTx,
		DelegatorUnbondingSlashingSig: commonMsg.DelegatorUnbondingSlashingSig,
		PreviousStakingTxHash:         dg.StakeExpansion.PreviousStakingTxHash.String(),
		FundingTx:                     serializedFundingTx,
	}, nil
}

// ReliablySendMsgs sends a batch of messages to the Babylon node
func (bc *BabylonController) reliablySendMsgs(
	msgs []sdk.Msg,
) (*bct.RelayerTxResponse, error) {
	// TODO Empty errors ??
	resp, err := bc.bbnClient.ReliablySendMsgs(context.Background(), msgs, []*sdkErr.Error{}, []*sdkErr.Error{})
	if err != nil {
		return nil, fmt.Errorf("failed to reliably send messages to babylon node: %w", err)
	}
	return resp, nil
}

// Delegate sends a delegation message to the Babylon node
// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	delegateMsg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert delegation data to message: %w", err)
	}

	return bc.reliablySendMsgs([]sdk.Msg{delegateMsg})
}

// ExpandDelegation sends a stake expansion delegation message to the Babylon node
func (bc *BabylonController) ExpandDelegation(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	stkExpandMsg, err := delegationDataToMsgBtcStakeExpand(dg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert delegation data to expansion message: %w", err)
	}

	return bc.reliablySendMsgs([]sdk.Msg{stkExpandMsg})
}

// getQueryContext returns context with timeout
func getQueryContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel
}

// parseParams parses the Babylon node's params
func parseParams(params *btcstypes.Params) (*StakingTrackerResponse, error) {
	// check early that the covenant config makes sense, so that rest of the
	// code can assume that:
	// 1. covenant quorum is less or equal to number of covenant pks
	// 2. covenant pks are not empty
	if len(params.CovenantPks) == 0 {
		return nil, fmt.Errorf("empty list of covenant pks: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	if int(params.CovenantQuorum) > len(params.CovenantPks) {
		return nil, fmt.Errorf("covenant quorum is bigger than number of covenant pks: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	var covenantPks []*btcec.PublicKey

	for _, covenantPk := range params.CovenantPks {
		covenantBtcPk, err := covenantPk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("failed to convert covenant public key to BTC public key: %w", err)
		}
		covenantPks = append(covenantPks, covenantBtcPk)
	}

	unbondingTime := params.UnbondingTimeBlocks
	if unbondingTime > math.MaxUint16 {
		return nil, fmt.Errorf("unbonding time is bigger than uint16: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	minStakingTimeBlocksU32 := params.MinStakingTimeBlocks
	if minStakingTimeBlocksU32 > math.MaxUint16 {
		return nil, fmt.Errorf("min staking time is bigger than uint16: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	maxStakingTimeBlocksU32 := params.MaxStakingTimeBlocks
	if maxStakingTimeBlocksU32 > math.MaxUint16 {
		return nil, fmt.Errorf("max staking time is bigger than uint16: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	if params.MinStakingValueSat < 0 {
		return nil, fmt.Errorf("min staking value is negative: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	if params.MaxStakingValueSat < 0 {
		return nil, fmt.Errorf("max staking value is negative: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	if params.UnbondingFeeSat < 0 {
		return nil, fmt.Errorf("unbonding fee is negative: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	return &StakingTrackerResponse{
		SlashingPkScript:          params.SlashingPkScript,
		SlashingRate:              params.SlashingRate,
		MinComissionRate:          params.MinCommissionRate,
		CovenantPks:               covenantPks,
		MinSlashingFee:            btcutil.Amount(params.MinSlashingTxFeeSat),
		CovenantQuruomThreshold:   params.CovenantQuorum,
		UnbondingTime:             uint16(unbondingTime),
		UnbondingFee:              btcutil.Amount(params.UnbondingFeeSat),
		MinStakingTime:            uint16(minStakingTimeBlocksU32),
		MaxStakingTime:            uint16(maxStakingTimeBlocksU32),
		MinStakingValue:           btcutil.Amount(params.MinStakingValueSat),
		MaxStakingValue:           btcutil.Amount(params.MaxStakingValueSat),
		AllowListExpirationHeight: params.AllowListExpirationHeight,
	}, nil
}

// QueryStakingTracker queries the staking tracker from the Babylon node
func (bc *BabylonController) QueryStakingTracker() (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.Params(ctx, &btcstypes.QueryParamsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to query babylon params: %w", err)
	}

	return parseParams(&response.Params)
}

// QueryStakingTrackerByBtcHeight queries the staking tracker from the Babylon node
func (bc *BabylonController) QueryStakingTrackerByBtcHeight(btcHeight uint32) (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.ParamsByBTCHeight(ctx, &btcstypes.QueryParamsByBTCHeightRequest{
		BtcHeight: btcHeight,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to query babylon params by btc height: %w", err)
	}

	return parseParams(&response.Params)
}

// QueryStakingTrackerByVersion queries the staking tracker from the Babylon node
func (bc *BabylonController) QueryStakingTrackerByVersion(version uint32) (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.ParamsByVersion(ctx, &btcstypes.QueryParamsByVersionRequest{
		Version: version,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to query babylon params by version: %w", err)
	}

	return parseParams(&response.Params)
}

// QueryFinalityProviders queries the finality providers from the Babylon node
func (bc *BabylonController) QueryFinalityProviders(
	limit uint64,
	offset uint64) (*FinalityProvidersClientResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	var response *btcstypes.QueryFinalityProvidersResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.FinalityProviders(
			ctx,
			&btcstypes.QueryFinalityProvidersRequest{
				Pagination: &bq.PageRequest{
					Offset:     offset,
					Limit:      limit,
					CountTotal: true,
				},
			},
		)
		if err != nil {
			return fmt.Errorf("failed to query babylon for the list of registered finality providers: %w", err)
		}
		response = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the list of registered finality providers")
	})); err != nil {
		return nil, fmt.Errorf("failed to query babylon for the list of registered finality providers after multiple retries: %w", err)
	}

	var finalityProviders []FinalityProviderInfo
	for _, finalityProvider := range response.FinalityProviders {
		// TODO: We actually need to use a query for ActiveFinalityProviders
		// instead of checking for the slashing condition
		if finalityProvider.SlashedBabylonHeight > 0 {
			continue
		}
		fpBtcKey, err := finalityProvider.BtcPk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("query finality providers error: %w", err)
		}

		fpAddr, err := sdk.AccAddressFromBech32(finalityProvider.Addr)
		if err != nil {
			return nil, fmt.Errorf("query finality providers error transform address: %s - %w", finalityProvider.Addr, err)
		}

		fpInfo := FinalityProviderInfo{
			BabylonAddr: fpAddr,
			BtcPk:       *fpBtcKey,
		}

		finalityProviders = append(finalityProviders, fpInfo)
	}

	return &FinalityProvidersClientResponse{
		FinalityProviders: finalityProviders,
		Total:             response.Pagination.Total,
	}, nil
}

// QueryFinalityProvider queries the finality provider from the Babylon node
func (bc *BabylonController) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if btcPubKey == nil {
		return nil, fmt.Errorf("cannot query finality provider with nil btc public key")
	}

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	hexPubKey := hex.EncodeToString(schnorr.SerializePubKey(btcPubKey))

	var (
		slashedHeight uint64
		pk            *bbntypes.BIP340PubKey
		addr          string
	)
	if err := retry.Do(func() error {
		// check if the finality provider exists
		resp, err := queryClient.FinalityProvider(
			ctx,
			&btcstypes.QueryFinalityProviderRequest{
				FpBtcPkHex: hexPubKey,
			},
		)
		if err == nil {
			slashedHeight = resp.FinalityProvider.SlashedBabylonHeight
			pk = resp.FinalityProvider.BtcPk
			addr = resp.FinalityProvider.Addr
			return nil
		}

		// the finality provider cannot be found
		if strings.Contains(err.Error(), btcstypes.ErrFpNotFound.Error()) {
			// if there is no finality provider with such key, we return unrecoverable error, as we not need to retry any more
			return retry.Unrecoverable(fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderDoesNotExist))
		}
		return err
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"fpKey":        hexPubKey,
			"error":        err,
		}).Error("Failed to query babylon for the finality provider")
	})); err != nil {
		return nil, fmt.Errorf("failed to get finality provider with key: %s after multiple retries: %w", hexPubKey, err)
	}

	if slashedHeight > 0 {
		return nil, fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderIsSlashed)
	}

	return &FinalityProviderClientResponse{
		FinalityProvider: FinalityProviderInfo{
			BabylonAddr: sdk.MustAccAddressFromBech32(addr),
			BtcPk:       *pk.MustToBTCPK(),
		},
	}, nil
}

// QueryHeaderDepth queries the header depth from the Babylon node
func (bc *BabylonController) QueryHeaderDepth(headerHash *chainhash.Hash) (uint32, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btclctypes.NewQueryClient(clientCtx)

	var response *btclctypes.QueryHeaderDepthResponse
	if err := retry.Do(func() error {
		depthResponse, err := queryClient.HeaderDepth(ctx, &btclctypes.QueryHeaderDepthRequest{Hash: headerHash.String()})
		if err != nil {
			return fmt.Errorf("failed to query babylon for the depth of the header: %w", err)
		}
		response = depthResponse
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the depth of the header")
	})); err != nil {
		// translate errors to locally handable ones
		if strings.Contains(err.Error(), btclctypes.ErrHeaderDoesNotExist.Error()) {
			return 0, fmt.Errorf("%s: %w", err.Error(), ErrHeaderNotKnownToBabylon)
		}

		// got unexpected error, return it
		return 0, fmt.Errorf("failed to query babylon for the depth of the header after multiple retries: %w", err)
	}

	return response.Depth, nil
}

// InsertBtcBlockHeaders Insert BTC block header using rpc client
func (bc *BabylonController) InsertBtcBlockHeaders(headers []*wire.BlockHeader) (*bct.RelayerTxResponse, error) {
	msg := &btclctypes.MsgInsertHeaders{
		Signer:  bc.getTxSigner(),
		Headers: chainToChainBytes(headers),
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

// chainToChainBytes converts []*wire.BlockHeader to []bbntypes.BTCHeaderBytes
func chainToChainBytes(chain []*wire.BlockHeader) []bbntypes.BTCHeaderBytes {
	chainBytes := make([]bbntypes.BTCHeaderBytes, len(chain))
	for i, header := range chain {
		chainBytes[i] = bbntypes.NewBTCHeaderBytesFromBlockHeader(header)
	}
	return chainBytes
}

// RegisterFinalityProvider is a helpers used in tests to register a finality provider on Babylon.
func (bc *BabylonController) RegisterFinalityProvider(
	fpAddr sdk.AccAddress,
	fpPrivKeyBBN *secp256k1.PrivKey,
	btcPubKey *bbntypes.BIP340PubKey,
	commission *sdkmath.LegacyDec,
	description *sttypes.Description,
	pop *btcstypes.ProofOfPossessionBTC,
) error {
	registerMsg := &btcstypes.MsgCreateFinalityProvider{
		Addr: fpAddr.String(),
		Commission: btcstypes.CommissionRates{
			Rate:          *commission,
			MaxRate:       *commission,
			MaxChangeRate: *commission,
		},
		BtcPk:       btcPubKey,
		Description: description,
		Pop:         pop,
	}

	relayerMsgs := bbnclient.ToProviderMsgs([]sdk.Msg{registerMsg})

	_, err := bc.bbnClient.SendMessageWithSigner(context.Background(), fpAddr, fpPrivKeyBBN, relayerMsgs)
	if err != nil {
		return fmt.Errorf("failed to send message with signer: %w", err)
	}
	return nil
}

// QueryBTCDelegation queries the delegation info of a staking transaction
func (bc *BabylonController) QueryBTCDelegation(stakingTxHash *chainhash.Hash) (*btcstypes.QueryBTCDelegationResponse, error) {
	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	var di *btcstypes.QueryBTCDelegationResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.BTCDelegation(ctx, &btcstypes.QueryBTCDelegationRequest{
			StakingTxHashHex: stakingTxHash.String(),
		})
		if err != nil {
			if strings.Contains(err.Error(), btcstypes.ErrBTCDelegationNotFound.Error()) {
				// delegation is not found on babylon, do not retry further
				return retry.Unrecoverable(ErrDelegationNotFound)
			}
			return fmt.Errorf("failed to get delegation info: %w", err)
		}
		di = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the staking transaction")
	})); err != nil {
		return nil, fmt.Errorf("failed to get delegation info after multiple retries: %w", err)
	}
	return di, nil
}

// GetUndelegationInfo returns the undelegation info from the response
func (bc *BabylonController) GetUndelegationInfo(resp *btcstypes.QueryBTCDelegationResponse) (*UndelegationInfo, error) {
	if resp.BtcDelegation.GetUndelegationResponse() == nil {
		return nil, fmt.Errorf("failed to get undelegation info from empty response")
	}

	var coventSigInfos []CovenantSignatureInfo
	for _, covenantSigInfo := range resp.BtcDelegation.UndelegationResponse.CovenantUnbondingSigList {
		covSig := covenantSigInfo
		sig, err := covSig.Sig.ToBTCSig()
		if err != nil {
			return nil, fmt.Errorf("failed to get covenant signature: %w", err)
		}

		pk, err := covSig.Pk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("failed to get covenant public key: %w", err)
		}

		sigInfo := CovenantSignatureInfo{
			Signature: sig,
			PubKey:    pk,
		}
		coventSigInfos = append(coventSigInfos, sigInfo)
	}

	tx, _, err := bbntypes.NewBTCTxFromHex(resp.BtcDelegation.UndelegationResponse.UnbondingTxHex)
	if err != nil {
		return nil, fmt.Errorf("failed to get unbonding transaction from response: %w", err)
	}

	unbondingTimeU32 := resp.BtcDelegation.UnbondingTime
	if unbondingTimeU32 > math.MaxUint16 {
		return nil, fmt.Errorf("unbonding time is too big: %d", unbondingTimeU32)
	}

	return &UndelegationInfo{
		UnbondingTransaction:        tx,
		CovenantUnbondingSignatures: coventSigInfos,
		UnbondingTime:               uint16(unbondingTimeU32),
	}, nil
}

// IsTxAlreadyPartOfDelegation checks if a staking transaction is already part of a delegation
func (bc *BabylonController) IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error) {
	_, err := bc.QueryBTCDelegation(stakingTxHash)

	if err != nil {
		if errors.Is(err, ErrDelegationNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get delegation info: %w", err)
	}

	return true, nil
}

// CreateCovenantMessage creates a covenant message
// This method is for e2e testing
func (bc *BabylonController) CreateCovenantMessage(
	covPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	slashStakingAdaptorSigs [][]byte,
	unbondindgSig *bbntypes.BIP340Signature,
	slashUnbondingAdaptorSigs [][]byte,
	stakeExpTxSig *bbntypes.BIP340Signature,
) *btcstypes.MsgAddCovenantSigs {
	msg := &btcstypes.MsgAddCovenantSigs{
		Signer:                  bc.getTxSigner(),
		Pk:                      covPubKey,
		StakingTxHash:           stakingTxHash,
		SlashingTxSigs:          slashStakingAdaptorSigs,
		UnbondingTxSig:          unbondindgSig,
		SlashingUnbondingTxSigs: slashUnbondingAdaptorSigs,
		StakeExpansionTxSig:     stakeExpTxSig,
	}

	return msg
}

// SubmitMultipleCovenantMessages submits multiple covenant messages
// This method is for e2e testing
func (bc *BabylonController) SubmitMultipleCovenantMessages(
	covenantMsgs []*btcstypes.MsgAddCovenantSigs,
) (*bct.RelayerTxResponse, error) {
	var msgs []sdk.Msg

	for _, covenantMsg := range covenantMsgs {
		msgs = append(msgs, covenantMsg)
	}

	return bc.reliablySendMsgs(msgs)
}

// QueryPendingBTCDelegations queries for pending BTC delegations
// Test methods for e2e testing
func (bc *BabylonController) QueryPendingBTCDelegations() ([]*btcstypes.BTCDelegationResponse, error) {
	return bc.QueryBTCDelegationsWithStatus(btcstypes.BTCDelegationStatus_PENDING)
}

// QueryVerifiedBTCDelegations queries for verified BTC delegations
// Test methods for e2e testing
func (bc *BabylonController) QueryVerifiedBTCDelegations() ([]*btcstypes.BTCDelegationResponse, error) {
	return bc.QueryBTCDelegationsWithStatus(btcstypes.BTCDelegationStatus_VERIFIED)
}

// QueryBTCDelegationsWithStatus queries for BTC delegations in the specified status
// Test methods for e2e testing
func (bc *BabylonController) QueryBTCDelegationsWithStatus(status btcstypes.BTCDelegationStatus) ([]*btcstypes.BTCDelegationResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	// query all the unsigned delegations
	queryRequest := btcstypes.QueryBTCDelegationsRequest{
		Status: status,
	}

	res, err := queryClient.BTCDelegations(ctx, &queryRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to query BTC delegations: %w", err)
	}

	return res.BtcDelegations, nil
}

// GetBBNClient returns the Babylon client
// Test methods for e2e testing
func (bc *BabylonController) GetBBNClient() *bbnclient.Client {
	return bc.bbnClient
}

// InsertSpvProofs inserts SPV proofs into the Babylon node
// Test methods for e2e testing
func (bc *BabylonController) InsertSpvProofs(submitter string, proofs []*btcctypes.BTCSpvProof) (*bct.RelayerTxResponse, error) {
	msg := &btcctypes.MsgInsertBTCSpvProof{
		Submitter: submitter,
		Proofs:    proofs,
	}

	res, err := bc.reliablySendMsgs([]sdk.Msg{msg})
	if err != nil {
		return nil, fmt.Errorf("failed to insert spv proofs: %w", err)
	}

	return res, nil
}

// QueryBtcLightClientTipHeight queries the height of the BTC light client
func (bc *BabylonController) QueryBtcLightClientTipHeight() (uint32, error) {
	res, err := bc.bbnClient.BTCHeaderChainTip()
	if err != nil {
		return 0, fmt.Errorf("failed to query BTC tip: %w", err)
	}

	return res.Header.Height, nil
}

// ActivateDelegation activates a delegation
// Test methods for e2e testing
func (bc *BabylonController) ActivateDelegation(
	stakingTxHash chainhash.Hash,
	proof *btcctypes.BTCSpvProof) (*bct.RelayerTxResponse, error) {
	msg := &btcstypes.MsgAddBTCDelegationInclusionProof{
		Signer:                  bc.getTxSigner(),
		StakingTxHash:           stakingTxHash.String(),
		StakingTxInclusionProof: btcstypes.NewInclusionProofFromSpvProof(proof),
	}

	res, err := bc.reliablySendMsgs([]sdk.Msg{msg})
	if err != nil {
		return nil, fmt.Errorf("failed to activate delegation: %w", err)
	}

	return res, nil
}

// ReportUnbonding sends unbonding message for a delegation
// Test methods for e2e testing
func (bc *BabylonController) ReportUnbonding(
	stakingTxHash chainhash.Hash,
	stakeSpendingTx *wire.MsgTx,
	proof *btcctypes.BTCSpvProof,
	fundingTxs [][]byte,
) error {
	stakeSpendingBytes, err := bbntypes.SerializeBTCTx(stakeSpendingTx)
	if err != nil {
		return err
	}

	msg := &btcstypes.MsgBTCUndelegate{
		Signer:                        bc.getTxSigner(),
		StakingTxHash:                 stakingTxHash.String(),
		StakeSpendingTx:               stakeSpendingBytes,
		StakeSpendingTxInclusionProof: btcstypes.NewInclusionProofFromSpvProof(proof),
		FundingTransactions:           fundingTxs,
	}

	resp, err := bc.reliablySendMsgs([]sdk.Msg{msg})
	if err != nil && resp != nil {
		return fmt.Errorf("msg MsgBTCUndelegate failed exeuction with code %d and error %w", resp.Code, err)
	}

	if err != nil {
		return fmt.Errorf("failed to report unbonding: %w", err)
	}

	return nil
}
