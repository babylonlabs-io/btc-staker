package babylonclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	bct "github.com/babylonlabs-io/babylon/client/babylonclient"
	btcctypes "github.com/babylonlabs-io/babylon/x/btccheckpoint/types"

	sdkErr "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/avast/retry-go/v4"
	bbnclient "github.com/babylonlabs-io/babylon/client/client"
	bbntypes "github.com/babylonlabs-io/babylon/types"
	btclctypes "github.com/babylonlabs-io/babylon/x/btclightclient/types"
	btcstypes "github.com/babylonlabs-io/babylon/x/btcstaking/types"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
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
	// TODO: Maybe configurable?
	RtyAttNum = uint(5)
	RtyAtt    = retry.Attempts(RtyAttNum)
	RtyDel    = retry.Delay(time.Millisecond * 600)
	RtyErr    = retry.LastErrorOnly(true)
)

var (
	ErrInvalidBabylonExecution             = errors.New("message send to babylon was executed with error")
	ErrHeaderNotKnownToBabylon             = errors.New("btc header not known to babylon")
	ErrHeaderOnBabylonLCFork               = errors.New("btc header is on babylon btc light client fork")
	ErrFinalityProviderDoesNotExist        = errors.New("finality provider does not exist")
	ErrFinalityProviderIsSlashed           = errors.New("finality provider is slashed")
	ErrDelegationNotFound                  = errors.New("delegation not found")
	ErrInvalidValueReceivedFromBabylonNode = errors.New("invalid value received from babylon node")
)

type BabylonController struct {
	bbnClient *bbnclient.Client
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
	logger    *logrus.Logger
}

var _ BabylonClient = (*BabylonController)(nil)

func NewBabylonController(
	cfg *stakercfg.BBNConfig,
	btcParams *chaincfg.Params,
	logger *logrus.Logger,
	clientLogger *zap.Logger,
) (*BabylonController, error) {
	babylonConfig := stakercfg.BBNConfigToBabylonConfig(cfg)

	// TODO should be validated earlier
	if err := babylonConfig.Validate(); err != nil {
		return nil, err
	}

	bc, err := bbnclient.New(
		&babylonConfig,
		clientLogger,
	)

	if err != nil {
		return nil, err
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

type FinalityProviderInfo struct {
	BabylonAddr sdk.AccAddress
	BtcPk       btcec.PublicKey
}

type FinalityProvidersClientResponse struct {
	FinalityProviders []FinalityProviderInfo
	Total             uint64
}

type FinalityProviderClientResponse struct {
	FinalityProvider FinalityProviderInfo
}

// Copied from vigilante. Weirdly, there is only Stop function (no Start function ?)
func (bc *BabylonController) Stop() error {
	return bc.bbnClient.Stop()
}

func (bc *BabylonController) btccheckpointParamsWithRetry() (*BTCCheckpointParams, error) {
	var bccParams *BTCCheckpointParams
	if err := retry.Do(func() error {
		response, err := bc.bbnClient.BTCCheckpointParams()
		if err != nil {
			return err
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
		return nil, err
	}

	return bccParams, nil
}

func (bc *BabylonController) BTCCheckpointParams() (*BTCCheckpointParams, error) {
	return bc.btccheckpointParamsWithRetry()
}

func (bc *BabylonController) queryStakingTrackerWithRetries() (*StakingTrackerResponse, error) {
	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTracker()
		if err != nil {
			return err
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
		return nil, err
	}

	return stakingTrackerParams, nil
}

func (bc *BabylonController) Params() (*StakingParams, error) {
	bccParams, err := bc.btccheckpointParamsWithRetry()

	if err != nil {
		return nil, err
	}

	stakingTrackerParams, err := bc.queryStakingTrackerWithRetries()

	if err != nil {
		return nil, err
	}

	return &StakingParams{
		ConfirmationTimeBlocks:    bccParams.ConfirmationTimeBlocks,
		FinalizationTimeoutBlocks: bccParams.FinalizationTimeoutBlocks,
		SlashingPkScript:          stakingTrackerParams.SlashingPkScript,
		CovenantPks:               stakingTrackerParams.CovenantPks,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
		CovenantQuruomThreshold:   stakingTrackerParams.CovenantQuruomThreshold,
		UnbondingTime:             stakingTrackerParams.UnbondingTime,
		UnbondingFee:              stakingTrackerParams.UnbondingFee,
		MinStakingTime:            stakingTrackerParams.MinStakingTime,
		MaxStakingTime:            stakingTrackerParams.MaxStakingTime,
		MinStakingValue:           stakingTrackerParams.MinStakingValue,
		MaxStakingValue:           stakingTrackerParams.MaxStakingValue,
		AllowListExpirationHeight: stakingTrackerParams.AllowListExpirationHeight,
	}, nil
}

func (bc *BabylonController) queryStakingTrackerByBtcHeightWithRetries(
	btcHeight uint32,
) (*StakingTrackerResponse, error) {
	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTrackerByBtcHeight(btcHeight)
		if err != nil {
			return err
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
		return nil, err
	}

	return stakingTrackerParams, nil
}

func (bc *BabylonController) ParamsByBtcHeight(btcHeight uint32) (*StakingParams, error) {
	bccParams, err := bc.btccheckpointParamsWithRetry()

	if err != nil {
		return nil, err
	}

	stakingTrackerParams, err := bc.queryStakingTrackerByBtcHeightWithRetries(btcHeight)

	if err != nil {
		return nil, err
	}

	return &StakingParams{
		ConfirmationTimeBlocks:    bccParams.ConfirmationTimeBlocks,
		FinalizationTimeoutBlocks: bccParams.FinalizationTimeoutBlocks,
		SlashingPkScript:          stakingTrackerParams.SlashingPkScript,
		CovenantPks:               stakingTrackerParams.CovenantPks,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
		CovenantQuruomThreshold:   stakingTrackerParams.CovenantQuruomThreshold,
		UnbondingTime:             stakingTrackerParams.UnbondingTime,
		UnbondingFee:              stakingTrackerParams.UnbondingFee,
		MinStakingTime:            stakingTrackerParams.MinStakingTime,
		MaxStakingTime:            stakingTrackerParams.MaxStakingTime,
		MinStakingValue:           stakingTrackerParams.MinStakingValue,
		MaxStakingValue:           stakingTrackerParams.MaxStakingValue,
		AllowListExpirationHeight: stakingTrackerParams.AllowListExpirationHeight,
	}, nil
}

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

func (bc *BabylonController) GetLatestBlockHeight() (uint64, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	status, err := bc.bbnClient.RPCClient.Status(ctx)
	if err != nil {
		return 0, err
	}

	return uint64(status.SyncInfo.LatestBlockHeight), nil
}

func (bc *BabylonController) getTxSigner() string {
	signer := bc.GetKeyAddress()
	prefix := bc.cfg.AccountPrefix
	return sdk.MustBech32ifyAddressBytes(prefix, signer)
}

func (bc *BabylonController) getPubKeyInternal() (*secp256k1.PubKey, error) {
	record, err := bc.bbnClient.GetKeyring().KeyByAddress(bc.GetKeyAddress())

	if err != nil {
		return nil, err
	}

	pubKey, err := record.GetPubKey()

	if err != nil {
		return nil, err
	}

	switch v := pubKey.(type) {
	case *secp256k1.PubKey:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported key type in keyring")
	}
}

func (bc *BabylonController) GetPubKey() *secp256k1.PubKey {
	pubKey, err := bc.getPubKeyInternal()

	if err != nil {
		panic(fmt.Sprintf("Failed to get public key: %v", err))
	}

	return pubKey
}

func (bc *BabylonController) Sign(msg []byte) ([]byte, error) {
	sign, kt, err := bc.bbnClient.GetKeyring().SignByAddress(bc.GetKeyAddress(), msg, signing.SignMode_SIGN_MODE_DIRECT)

	if err != nil {
		return nil, err
	}

	switch v := kt.(type) {
	case *secp256k1.PubKey:
		return sign, nil
	default:
		panic(fmt.Sprintf("Unsupported key type in keyring: %s", v.Type()))
	}
}

type StakingTransactionInclusionInfo struct {
	StakingTransactionIdx                uint32
	StakingTransactionInclusionProof     []byte
	StakingTransactionInclusionBlockHash *chainhash.Hash
}

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
	BabylonPop                      *stakerdb.ProofOfPossession
	Ud                              *UndelegationData
}

type UndelegationData struct {
	UnbondingTransaction         *wire.MsgTx
	UnbondingTxValue             btcutil.Amount
	UnbondingTxUnbondingTime     uint16
	SlashUnbondingTransaction    *wire.MsgTx
	SlashUnbondingTransactionSig *schnorr.Signature
}

type UndelegationRequest struct {
	StakingTxHash      chainhash.Hash
	StakerUnbondingSig *schnorr.Signature
}

type CovenantSignatureInfo struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

type UndelegationInfo struct {
	CovenantUnbondingSignatures []CovenantSignatureInfo
	UnbondingTransaction        *wire.MsgTx
	UnbondingTime               uint16
}

type DelegationInfo struct {
	Active           bool
	UndelegationInfo *UndelegationInfo
}

func delegationDataToMsg(dg *DelegationData) (*btcstypes.MsgCreateBTCDelegation, error) {
	if dg == nil {
		return nil, fmt.Errorf("nil delegation data")
	}

	if dg.Ud == nil {
		return nil, fmt.Errorf("nil undelegation data")
	}

	serizalizedStakingTransaction, err := utils.SerializeBtcTransaction(dg.StakingTransaction)

	if err != nil {
		return nil, err
	}

	slashingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.SlashingTransaction)

	if err != nil {
		return nil, err
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
		return nil, err
	}

	slashUnbondingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.Ud.SlashUnbondingTransaction)

	if err != nil {
		return nil, err
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

	return &btcstypes.MsgCreateBTCDelegation{
		// Note: this should be always safe conversion as we received data from our db
		StakerAddr: dg.BabylonStakerAddr.String(),
		Pop: &btcstypes.ProofOfPossessionBTC{
			BtcSigType: btcstypes.BTCSigType(dg.BabylonPop.BtcSigType),
			BtcSig:     dg.BabylonPop.BtcSigOverBabylonAddr,
		},
		BtcPk:        bbntypes.NewBIP340PubKeyFromBTCPK(dg.StakerBtcPk),
		FpBtcPkList:  fpPksList,
		StakingTime:  uint32(dg.StakingTime),
		StakingValue: int64(dg.StakingValue),
		// TODO: It is super bad that this thing (TransactionInfo) spread over whole babylon codebase, and it
		// is used in all modules, rpc, database etc.
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
	}, nil
}

func (bc *BabylonController) reliablySendMsgs(
	msgs []sdk.Msg,
) (*bct.RelayerTxResponse, error) {
	// TODO Empty errors ??
	return bc.bbnClient.ReliablySendMsgs(context.Background(), msgs, []*sdkErr.Error{}, []*sdkErr.Error{})
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	delegateMsg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, err
	}

	return bc.reliablySendMsgs([]sdk.Msg{delegateMsg})
}

func getQueryContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel
}

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
			return nil, err
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

func (bc *BabylonController) QueryStakingTracker() (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.Params(ctx, &btcstypes.QueryParamsRequest{})
	if err != nil {
		return nil, err
	}

	return parseParams(&response.Params)
}

func (bc *BabylonController) QueryStakingTrackerByBtcHeight(btcHeight uint32) (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.ParamsByBTCHeight(ctx, &btcstypes.QueryParamsByBTCHeightRequest{
		BtcHeight: btcHeight,
	})

	if err != nil {
		return nil, err
	}

	return parseParams(&response.Params)
}

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
			return err
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
		return nil, err
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

func (bc *BabylonController) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if btcPubKey == nil {
		return nil, fmt.Errorf("cannot query finality provider with nil btc public key")
	}

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	hexPubKey := hex.EncodeToString(schnorr.SerializePubKey(btcPubKey))

	var response *btcstypes.QueryFinalityProviderResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.FinalityProvider(
			ctx,
			&btcstypes.QueryFinalityProviderRequest{
				FpBtcPkHex: hexPubKey,
			},
		)
		if err != nil {
			if strings.Contains(err.Error(), btcstypes.ErrFpNotFound.Error()) {
				// if there is no finality provider with such key, we return unrecoverable error, as we not need to retry any more
				return retry.Unrecoverable(fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderDoesNotExist))
			}

			return err
		}
		response = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"fpKey":        hexPubKey,
			"error":        err,
		}).Error("Failed to query babylon for the finality provider")
	})); err != nil {
		return nil, err
	}

	if response.FinalityProvider.SlashedBabylonHeight > 0 {
		return nil, fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderIsSlashed)
	}

	btcPk, err := response.FinalityProvider.BtcPk.ToBTCPK()
	if err != nil {
		return nil, fmt.Errorf("received malformed btc pk in babylon response: %w", err)
	}

	fpAddr, err := sdk.AccAddressFromBech32(response.FinalityProvider.Addr)
	if err != nil {
		return nil, fmt.Errorf("received malformed fp addr in babylon response: %s - %w", response.FinalityProvider.Addr, err)
	}

	return &FinalityProviderClientResponse{
		FinalityProvider: FinalityProviderInfo{
			BabylonAddr: fpAddr,
			BtcPk:       *btcPk,
		},
	}, nil
}

func (bc *BabylonController) QueryHeaderDepth(headerHash *chainhash.Hash) (uint32, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btclctypes.NewQueryClient(clientCtx)

	var response *btclctypes.QueryHeaderDepthResponse
	if err := retry.Do(func() error {
		depthResponse, err := queryClient.HeaderDepth(ctx, &btclctypes.QueryHeaderDepthRequest{Hash: headerHash.String()})
		if err != nil {
			return err
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
		return 0, err
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

func chainToChainBytes(chain []*wire.BlockHeader) []bbntypes.BTCHeaderBytes {
	chainBytes := make([]bbntypes.BTCHeaderBytes, len(chain))
	for i, header := range chain {
		chainBytes[i] = bbntypes.NewBTCHeaderBytesFromBlockHeader(header)
	}
	return chainBytes
}

// RegisterFinalityProvider registers a BTC finality provider via a MsgCreateFinalityProvider to Babylon
// it returns tx hash and error
func (bc *BabylonController) RegisterFinalityProvider(
	fpAddr sdk.AccAddress,
	fpPrivKeyBBN *secp256k1.PrivKey,
	btcPubKey *bbntypes.BIP340PubKey,
	commission *sdkmath.LegacyDec,
	description *sttypes.Description,
	pop *btcstypes.ProofOfPossessionBTC,
) error {
	registerMsg := &btcstypes.MsgCreateFinalityProvider{
		Addr:        fpAddr.String(),
		Commission:  commission,
		BtcPk:       btcPubKey,
		Description: description,
		Pop:         pop,
	}

	relayerMsgs := bbnclient.ToProviderMsgs([]sdk.Msg{registerMsg})

	_, err := bc.bbnClient.SendMessageWithSigner(context.Background(), fpAddr, fpPrivKeyBBN, relayerMsgs)
	return err
}

func (bc *BabylonController) QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error) {
	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	var di *DelegationInfo
	if err := retry.Do(func() error {
		resp, err := queryClient.BTCDelegation(ctx, &btcstypes.QueryBTCDelegationRequest{
			StakingTxHashHex: stakingTxHash.String(),
		})
		if err != nil {
			if strings.Contains(err.Error(), btcstypes.ErrBTCDelegationNotFound.Error()) {
				// delegation is not found on babylon, do not retry further
				return retry.Unrecoverable(ErrDelegationNotFound)
			}

			return err
		}

		var udi *UndelegationInfo

		if resp.BtcDelegation.UndelegationResponse != nil {
			var coventSigInfos []CovenantSignatureInfo

			for _, covenantSigInfo := range resp.BtcDelegation.UndelegationResponse.CovenantUnbondingSigList {
				covSig := covenantSigInfo
				sig, err := covSig.Sig.ToBTCSig()

				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed covenant sig: %s : %w", err.Error(),
						ErrInvalidValueReceivedFromBabylonNode))
				}

				pk, err := covSig.Pk.ToBTCPK()

				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed covenant pk: %s : %w", err.Error(),
						ErrInvalidValueReceivedFromBabylonNode))
				}

				sigInfo := CovenantSignatureInfo{
					Signature: sig,
					PubKey:    pk,
				}

				coventSigInfos = append(coventSigInfos, sigInfo)
			}

			tx, _, err := bbntypes.NewBTCTxFromHex(resp.BtcDelegation.UndelegationResponse.UnbondingTxHex)

			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding transaction: %s: %w", err.Error(), ErrInvalidValueReceivedFromBabylonNode))
			}

			unbondingTimeU32 := resp.BtcDelegation.UnbondingTime
			if unbondingTimeU32 > math.MaxUint16 {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding time: %d: %w", resp.BtcDelegation.UnbondingTime, ErrInvalidValueReceivedFromBabylonNode))
			}

			udi = &UndelegationInfo{
				UnbondingTransaction:        tx,
				CovenantUnbondingSignatures: coventSigInfos,
				UnbondingTime:               uint16(unbondingTimeU32),
			}
		}

		di = &DelegationInfo{
			Active:           resp.BtcDelegation.Active,
			UndelegationInfo: udi,
		}
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the staking transaction")
	})); err != nil {
		return nil, err
	}

	return di, nil
}

func (bc *BabylonController) IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error) {
	_, err := bc.QueryDelegationInfo(stakingTxHash)

	if err != nil {
		if errors.Is(err, ErrDelegationNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Test methods for e2e testing
// Different babylon sig methods to support e2e testing
func (bc *BabylonController) CreateCovenantMessage(
	covPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	slashStakingAdaptorSigs [][]byte,
	unbondindgSig *bbntypes.BIP340Signature,
	slashUnbondingAdaptorSigs [][]byte,
) *btcstypes.MsgAddCovenantSigs {
	msg := &btcstypes.MsgAddCovenantSigs{
		Signer:                  bc.getTxSigner(),
		Pk:                      covPubKey,
		StakingTxHash:           stakingTxHash,
		SlashingTxSigs:          slashStakingAdaptorSigs,
		UnbondingTxSig:          unbondindgSig,
		SlashingUnbondingTxSigs: slashUnbondingAdaptorSigs,
	}

	return msg
}

func (bc *BabylonController) SubmitMultipleCovenantMessages(
	covenantMsgs []*btcstypes.MsgAddCovenantSigs,
) (*bct.RelayerTxResponse, error) {
	var msgs []sdk.Msg

	for _, covenantMsg := range covenantMsgs {
		msgs = append(msgs, covenantMsg)
	}

	return bc.reliablySendMsgs(msgs)
}

func (bc *BabylonController) QueryPendingBTCDelegations() ([]*btcstypes.BTCDelegationResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	// query all the unsigned delegations
	queryRequest := btcstypes.QueryBTCDelegationsRequest{
		Status: btcstypes.BTCDelegationStatus_PENDING,
	}

	res, err := queryClient.BTCDelegations(ctx, &queryRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to query BTC delegations: %w", err)
	}

	return res.BtcDelegations, nil
}

func (bc *BabylonController) GetBBNClient() *bbnclient.Client {
	return bc.bbnClient
}

func (bc *BabylonController) InsertSpvProofs(submitter string, proofs []*btcctypes.BTCSpvProof) (*bct.RelayerTxResponse, error) {
	msg := &btcctypes.MsgInsertBTCSpvProof{
		Submitter: submitter,
		Proofs:    proofs,
	}

	res, err := bc.reliablySendMsgs([]sdk.Msg{msg})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (bc *BabylonController) QueryBtcLightClientTipHeight() (uint32, error) {
	res, err := bc.bbnClient.QueryClient.BTCHeaderChainTip()
	if err != nil {
		return 0, fmt.Errorf("failed to query BTC tip: %w", err)
	}

	return res.Header.Height, nil
}

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
		return nil, err
	}

	return res, nil
}
