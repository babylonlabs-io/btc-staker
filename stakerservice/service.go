package stakerservice

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/babylonlabs-io/btc-staker/metrics"
	str "github.com/babylonlabs-io/btc-staker/staker"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/jsonrpc/server"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"go.uber.org/zap"

	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/sirupsen/logrus"
)

const (
	defaultOffset = 0
	defaultLimit  = 50
	maxLimit      = 100
	// EnvRouteAuthUser contains the env var name for daemon route usernames.
	EnvRouteAuthUser = "BTCSTAKER_USERNAME"
	// EnvRouteAuthPwd contains the env var name for daemon route passwords.
	EnvRouteAuthPwd = "BTCSTAKER_PASSWORD"
)

// RoutesMap maps route names to their RPC metadata.
type RoutesMap map[string]*RPCFunc

// StakerService wraps the RPC server exposing staker functionality.
type StakerService struct {
	started int32

	config *scfg.Config
	staker *str.App
	logger *logrus.Logger
	db     kvdb.Backend
}

// NewStakerServiceFromConfig creates a new staker service instance from config
func NewStakerServiceFromConfig(
	c *scfg.Config,
	l *logrus.Logger,
	z *zap.Logger,
	db kvdb.Backend,
	m *metrics.StakerMetrics,
) (*StakerService, error) {
	s, err := str.NewStakerAppFromConfig(c, l, z, db, m)
	if err != nil {
		return nil, fmt.Errorf("failed to create staker app: %w", err)
	}
	return NewStakerService(c, s, l, db), nil
}

// NewStakerService creates a new staker service instance.
func NewStakerService(
	c *scfg.Config,
	s *str.App,
	l *logrus.Logger,
	db kvdb.Backend,
) *StakerService {
	return &StakerService{
		config: c,
		staker: s,
		logger: l,
		db:     db,
	}
}

// stakingDetails converts a stakerdb.StoredTransaction to a StakingDetails
func storedTxToStakingDetails(storedTx *stakerdb.StoredTransaction, state string) StakingDetails {
	return StakingDetails{
		StakingTxHash:  storedTx.StakingTx.TxHash().String(),
		StakerAddress:  storedTx.StakerAddress,
		StakingState:   state,
		TransactionIdx: strconv.FormatUint(storedTx.StoredTransactionIdx, 10),
	}
}

// health returns a health check response
func (s *StakerService) health(_ *rpctypes.Context) (*ResultHealth, error) {
	return &ResultHealth{}, nil
}

// stake stakes staker's requested amount of BTC
func (s *StakerService) stake(_ *rpctypes.Context,
	stakerAddress string,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
) (*ResultStake, error) {
	amount, stakerAddr, fpPubKeys, stakingTime, err := parseStkParams(stakerAddress, &s.config.ActiveNetParams, stakingAmount, fpBtcPks, stakingTimeBlocks)
	if err != nil {
		return nil, err
	}

	stakingTxHash, err := s.staker.StakeFunds(stakerAddr, amount, fpPubKeys, stakingTime)
	if err != nil {
		return nil, fmt.Errorf("error staking funds: %w", err)
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

// stakeMultisig stakes staker's requested amount of BTC using multisig staker keys loaded in stakerd.
func (s *StakerService) stakeMultisig(_ *rpctypes.Context,
	fundingAddress string,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
) (*ResultStake, error) {
	amount, fundingAddr, fpPubKeys, stakingTime, err := parseStkParams(fundingAddress, &s.config.ActiveNetParams, stakingAmount, fpBtcPks, stakingTimeBlocks)
	if err != nil {
		return nil, err
	}

	stakingTxHash, err := s.staker.StakeFundsMultisig(fundingAddr, amount, fpPubKeys, stakingTime)
	if err != nil {
		return nil, fmt.Errorf("error staking funds (multisig): %w", err)
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

// stakeExpand stakes staker's requested amount of BTC
func (s *StakerService) stakeExpand(_ *rpctypes.Context,
	stakerAddress string,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
	prevActiveStkTxHashHex string,
) (*ResultStake, error) {
	amount, stakerAddr, fpPubKeys, stakingTime, err := parseStkParams(stakerAddress, &s.config.ActiveNetParams, stakingAmount, fpBtcPks, stakingTimeBlocks)
	if err != nil {
		return nil, err
	}

	prevActiveStkTxHash, err := chainhash.NewHashFromStr(prevActiveStkTxHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous staking transaction hash hex %s: %w", prevActiveStkTxHashHex, err)
	}

	stakingTxHash, err := s.staker.StakeExpand(stakerAddr, amount, fpPubKeys, stakingTime, prevActiveStkTxHash)
	if err != nil {
		return nil, fmt.Errorf("error stake expand funds: %w", err)
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

// stakeExpandMultisig stakes staker's requested amount of BTC using multisig staker keys and a previous active staking tx as input
func (s *StakerService) stakeExpandMultisig(_ *rpctypes.Context,
	fundingAddress string,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
	prevActiveStkTxHashHex string,
) (*ResultStake, error) {
	amount, fundingAddr, fpPubKeys, stakingTime, err := parseStkParams(fundingAddress, &s.config.ActiveNetParams, stakingAmount, fpBtcPks, stakingTimeBlocks)
	if err != nil {
		return nil, err
	}

	prevActiveStkTxHash, err := chainhash.NewHashFromStr(prevActiveStkTxHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous staking transaction hash hex %s: %w", prevActiveStkTxHashHex, err)
	}

	stakingTxHash, err := s.staker.StakeExpandMultisig(fundingAddr, amount, fpPubKeys, stakingTime, prevActiveStkTxHash)
	if err != nil {
		return nil, fmt.Errorf("error stake expand funds (multisig): %w", err)
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

// consolidateUTXOs consolidates UTXOs into a single larger UTXO
func (s *StakerService) consolidateUTXOs(_ *rpctypes.Context,
	stakerAddress string,
	targetAmount int64,
) (*ResultStake, error) {
	if targetAmount <= 0 {
		return nil, fmt.Errorf("target amount must be positive")
	}

	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)
	if err != nil {
		return nil, fmt.Errorf("error decoding staker address: %w", err)
	}

	consolidationTxHash, err := s.staker.ConsolidateUTXOs(stakerAddr, targetAmount)
	if err != nil {
		return nil, fmt.Errorf("error consolidating UTXOs: %w", err)
	}

	return &ResultStake{
		TxHash: consolidationTxHash.String(),
	}, nil
}

func parseStkParams(
	stakerAddress string,
	btcCfg *chaincfg.Params,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
) (
	amount btcutil.Amount,
	stakerAddr btcutil.Address,
	fpPubKeys []*btcec.PublicKey,
	stakingTime uint16,
	err error,
) {
	if stakingAmount <= 0 {
		return amount, nil, nil, 0, fmt.Errorf("staking amount must be positive")
	}

	amount = btcutil.Amount(stakingAmount)

	stakerAddr, err = btcutil.DecodeAddress(stakerAddress, btcCfg)
	if err != nil {
		return amount, nil, nil, 0, fmt.Errorf("error decoding staker address: %w", err)
	}

	fpPubKeys = make([]*btcec.PublicKey, 0)

	for _, fpPk := range fpBtcPks {
		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return amount, nil, nil, 0, fmt.Errorf("error decoding finality provider public key: %w", err)
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return amount, nil, nil, 0, fmt.Errorf("error parsing finality provider public key: %w", err)
		}

		fpPubKeys = append(fpPubKeys, fpSchnorrKey)
	}

	if stakingTimeBlocks <= 0 || stakingTimeBlocks > math.MaxUint16 {
		return amount, nil, nil, 0, fmt.Errorf("staking time must be positive and lower than %d", math.MaxUint16)
	}

	return amount, stakerAddr, fpPubKeys, uint16(stakingTimeBlocks), nil
}

// btcDelegationFromBtcStakingTx returns a btc delegation from a btc staking transaction
func (s *StakerService) btcDelegationFromBtcStakingTx(
	_ *rpctypes.Context,
	stakerAddress string,
	btcStkTxHash string,
	covenantPksHex []string,
	covenantQuorum uint32,
) (*ResultBtcDelegationFromBtcStakingTx, error) {
	stkTxHash, err := chainhash.NewHashFromStr(btcStkTxHash)
	if err != nil {
		s.logger.WithError(err).Info("err parse tx hash")
		return nil, fmt.Errorf("error parsing tx hash: %w", err)
	}

	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)
	if err != nil {
		s.logger.WithError(err).Info("err decode staker addr")
		return nil, fmt.Errorf("error decoding staker address: %w", err)
	}

	covenantPks, err := parseCovenantsPubKeyFromHex(covenantPksHex...)
	if err != nil {
		s.logger.WithError(err).Infof("err decode covenant pks %s", covenantPksHex)
		return nil, fmt.Errorf("error decoding covenant public keys: %w", err)
	}

	babylonBTCDelegationTxHash, err := s.staker.SendPhase1Transaction(stakerAddr, stkTxHash, covenantPks, covenantQuorum)
	if err != nil {
		s.logger.WithError(err).Info("err to send phase 1 tx")
		return nil, fmt.Errorf("error sending phase 1 transaction: %w", err)
	}

	return &ResultBtcDelegationFromBtcStakingTx{
		BabylonBTCDelegationTxHash: babylonBTCDelegationTxHash,
	}, nil
}

// parseCovenantsPubKeyFromHex parses a slice of covenant public keys from hex strings
func parseCovenantsPubKeyFromHex(covenantPksHex ...string) ([]*btcec.PublicKey, error) {
	covenantPks := make([]*btcec.PublicKey, len(covenantPksHex))
	for i, covenantPkHex := range covenantPksHex {
		covPk, err := parseCovenantPubKeyFromHex(covenantPkHex)
		if err != nil {
			return nil, fmt.Errorf("error parsing covenant public key: %w", err)
		}
		covenantPks[i] = covPk
	}

	return covenantPks, nil
}

// parseCovenantPubKeyFromHex parses public key string to btc public key
// the input should be 33 bytes
func parseCovenantPubKeyFromHex(pkStr string) (*btcec.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkStr)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key: %w", err)
	}

	pk, err := btcec.ParsePubKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	return pk, nil
}

// btcTxBlkDetails returns a btc transaction and block
func (s *StakerService) btcTxBlkDetails(
	_ *rpctypes.Context,
	txHashStr string,
) (*BtcTxAndBlockResponse, error) {
	txHash, err := chainhash.NewHashFromStr(txHashStr)
	if err != nil {
		return nil, fmt.Errorf("error decoding transaction hash: %w", err)
	}

	tx, blk, err := s.staker.BtcTxAndBlock(txHash)
	if err != nil {
		return nil, fmt.Errorf("error getting transaction and block: %w", err)
	}

	return &BtcTxAndBlockResponse{
		Tx:  tx,
		Blk: blk,
	}, nil
}

// stakingDetails returns a staking details
func (s *StakerService) stakingDetails(
	_ *rpctypes.Context,
	stakingTxHash string,
) (*StakingDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse string type of hash to chainhash.Hash: %w", err)
	}

	storedTx, err := s.staker.GetStoredTransaction(txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get stored transaction from hash %s: %w", stakingTxHash, err)
	}

	di, err := s.staker.BabylonController().QueryBTCDelegation(txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to query delegation info from babylon: %w", err)
	}

	details := storedTxToStakingDetails(storedTx, di.BtcDelegation.GetStatusDesc())
	return &details, nil
}

// spendStake initiates a spend stake transaction
func (s *StakerService) spendStake(_ *rpctypes.Context,
	stakingTxHash string) (*SpendTxDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("failed to parse string type of hash to chainhash.Hash: %w", err)
	}

	spendTxHash, value, err := s.staker.SpendStake(txHash)

	if err != nil {
		return nil, fmt.Errorf("failed to spend stake: %w", err)
	}

	txValue := strconv.FormatInt(int64(*value), 10)

	return &SpendTxDetails{
		TxHash:  spendTxHash.String(),
		TxValue: txValue,
	}, nil
}

// spendStakeMultisig initiates a spend stake transaction using multisig staker keys configured in stakerd.
func (s *StakerService) spendStakeMultisig(_ *rpctypes.Context,
	stakingTxHash string) (*SpendTxDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("failed to parse string type of hash to chainhash.Hash: %w", err)
	}

	spendTxHash, value, err := s.staker.SpendStakeMultisig(txHash)

	if err != nil {
		return nil, fmt.Errorf("failed to spend stake (multisig): %w", err)
	}

	txValue := strconv.FormatInt(int64(*value), 10)

	return &SpendTxDetails{
		TxHash:  spendTxHash.String(),
		TxValue: txValue,
	}, nil
}

// listOutputs returns a list of outputs
func (s *StakerService) listOutputs(_ *rpctypes.Context) (*OutputsResponse, error) {
	outputs, err := s.staker.ListUnspentOutputs()

	if err != nil {
		return nil, fmt.Errorf("failed to list unspent outputs: %w", err)
	}

	var outputDetails []OutputDetail

	for _, output := range outputs {
		outputDetails = append(outputDetails, OutputDetail{
			Address: output.Address,
			Amount:  output.Amount.String(),
		})
	}

	return &OutputsResponse{
		Outputs: outputDetails,
	}, nil
}

// PageParams is a page params
type PageParams struct {
	Offset uint64
	Limit  uint64
}

// getPageParams returns a page params
func getPageParams(offsetPtr *int, limitPtr *int) (*PageParams, error) {
	var limit uint64
	switch {
	case limitPtr == nil:
		limit = defaultLimit
	case *limitPtr < 0:
		return nil, fmt.Errorf("limit cannot be negative")
	default:
		limit = uint64(*limitPtr)
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	var offset uint64
	switch {
	case offsetPtr == nil:
		offset = defaultOffset
	case *offsetPtr >= 0:
		offset = uint64(*offsetPtr)
	default:
		return nil, fmt.Errorf("offset cannot be negative")
	}

	return &PageParams{
		Offset: offset,
		Limit:  limit,
	}, nil
}

// providers returns a list of finality providers
func (s *StakerService) providers(_ *rpctypes.Context, offset, limit *int) (*FinalityProvidersResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get page params: %w", err)
	}

	providersResp, err := s.staker.ListActiveFinalityProviders(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, fmt.Errorf("failed to get active finality providers: %w", err)
	}

	var providerInfos []FinalityProviderInfoResponse

	for _, provider := range providersResp.FinalityProviders {
		v := FinalityProviderInfoResponse{
			BabylonAddress: provider.BabylonAddr.String(),
			BtcPublicKey:   hex.EncodeToString(schnorr.SerializePubKey(&provider.BtcPk)),
		}

		providerInfos = append(providerInfos, v)
	}

	totalCount := strconv.FormatUint(providersResp.Total, 10)

	return &FinalityProvidersResponse{
		FinalityProviders:           providerInfos,
		TotalFinalityProvidersCount: totalCount,
	}, nil
}

// listStakingTransactions returns a list of staking transactions
func (s *StakerService) listStakingTransactions(_ *rpctypes.Context, offset, limit *int) (*ListStakingTransactionsResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get page params: %w", err)
	}

	txResult, err := s.staker.StoredTransactions(pageParams.Limit, pageParams.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get stored transactions: %w", err)
	}

	var stakingDetails []StakingDetails
	bc := s.staker.BabylonController()

	for _, tx := range txResult.Transactions {
		tx := tx
		stakingTxHash := tx.StakingTx.TxHash()
		di, err := bc.QueryBTCDelegation(&stakingTxHash)
		if err != nil {
			return nil, fmt.Errorf("failed to query delegation info from babylon: %w", err)
		}
		stakingDetails = append(stakingDetails, storedTxToStakingDetails(&tx, di.BtcDelegation.GetStatusDesc()))
	}

	totalCount := strconv.FormatUint(txResult.Total, 10)

	return &ListStakingTransactionsResponse{
		Transactions:          stakingDetails,
		TotalTransactionCount: totalCount,
	}, nil
}

// withdrawableTransactions returns a list of staking transactions that are not yet confirmed in btc
func (s *StakerService) withdrawableTransactions(_ *rpctypes.Context, offset, limit *int) (*WithdrawableTransactionsResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, err
	}

	txResult, err := s.staker.WithdrawableTransactions(pageParams.Limit, pageParams.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get withdrawable transactions: %w", err)
	}

	var stakingDetails []StakingDetails

	for _, tx := range txResult.Transactions {
		// Since withdrawable transactions are always confirmed in btc and activated in babylon,
		// no need to query babylon for delegation info
		stakingDetails = append(stakingDetails, storedTxToStakingDetails(&tx, str.BabylonActiveStatus))
	}

	lastIdx := "0"
	if len(stakingDetails) > 0 {
		// this should ease up pagination i.e in case when whe have 1000 transactions, and we limit query to 50
		// due to filetring we can retrun  response with 50 transactions when last one have index 400,
		// then caller can specify offset=400 and get next withdrawable transactions.
		lastIdx = stakingDetails[len(stakingDetails)-1].TransactionIdx
	}

	totalCount := strconv.FormatUint(txResult.Total, 10)

	return &WithdrawableTransactionsResponse{
		Transactions:                     stakingDetails,
		LastWithdrawableTransactionIndex: lastIdx,
		TotalTransactionCount:            totalCount,
	}, nil
}

// unbondStaking unbonds a staking transaction
func (s *StakerService) unbondStaking(_ *rpctypes.Context, stakingTxHash string) (*UnbondingResponse, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("failed to parse staking tx hash: %w", err)
	}

	unbondingTxHash, err := s.staker.UnbondStaking(*txHash)

	if err != nil {
		return nil, fmt.Errorf("failed to unbond staking: %w", err)
	}

	return &UnbondingResponse{
		UnbondingTxHash: unbondingTxHash.String(),
	}, nil
}

// unbondStakingMultisig unbonds a staking transaction using multisig staker keys
func (s *StakerService) unbondStakingMultisig(_ *rpctypes.Context, stakingTxHash string) (*UnbondingResponse, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("failed to parse staking tx hash: %w", err)
	}

	unbondingTxHash, err := s.staker.UnbondStakingMultisig(*txHash)

	if err != nil {
		return nil, fmt.Errorf("failed to unbond staking (multisig): %w", err)
	}

	return &UnbondingResponse{
		UnbondingTxHash: unbondingTxHash.String(),
	}, nil
}

// btcStakingParamsByBtcHeight loads the BTC staking params for the BTC block height from babylon
func (s *StakerService) btcStakingParamsByBtcHeight(_ *rpctypes.Context, btcHeight uint32) (*BtcStakingParamsByBtcHeightResponse, error) {
	stakingParams, err := s.staker.BabylonController().ParamsByBtcHeight(btcHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to load all the btc staking params by BTC height: %w", err)
	}

	return &BtcStakingParamsByBtcHeightResponse{
		StakingParams: BtcStakingParams{
			CovenantPkHex:  ParseCovenantsPubKeyToHex(stakingParams.CovenantPks...),
			CovenantQuorum: stakingParams.CovenantQuruomThreshold,
		},
	}, nil
}

// GetRoutes returns a list of routes this service handles
func (s *StakerService) GetRoutes() RoutesMap {
	return RoutesMap{
		// info AP
		"health": NewRPCFunc(s.health, ""),
		// staking API
		"stake":                              NewRPCFunc(s.stake, "stakerAddress,stakingAmount,fpBtcPks,stakingTimeBlocks"),
		"stake_multisig":                     NewRPCFunc(s.stakeMultisig, "fundingAddress,stakingAmount,fpBtcPks,stakingTimeBlocks"),
		"stake_expand":                       NewRPCFunc(s.stakeExpand, "stakerAddress,stakingAmount,fpBtcPks,stakingTimeBlocks,prevActiveStkTxHashHex"),
		"stake_expand_multisig":              NewRPCFunc(s.stakeExpandMultisig, "fundingAddress,stakingAmount,fpBtcPks,stakingTimeBlocks,prevActiveStkTxHashHex"),
		"consolidate_utxos":                  NewRPCFunc(s.consolidateUTXOs, "stakerAddress,targetAmount"),
		"btc_delegation_from_btc_staking_tx": NewRPCFunc(s.btcDelegationFromBtcStakingTx, "stakerAddress,btcStkTxHash,covenantPksHex,covenantQuorum"),
		"staking_details":                    NewRPCFunc(s.stakingDetails, "stakingTxHash"),
		"spend_stake":                        NewRPCFunc(s.spendStake, "stakingTxHash"),
		"spend_stake_multisig":               NewRPCFunc(s.spendStakeMultisig, "stakingTxHash"),
		"list_staking_transactions":          NewRPCFunc(s.listStakingTransactions, "offset,limit"),
		"unbond_staking":                     NewRPCFunc(s.unbondStaking, "stakingTxHash"),
		"unbond_staking_multisig":            NewRPCFunc(s.unbondStakingMultisig, "stakingTxHash"),
		"btc_staking_param_by_btc_height":    NewRPCFunc(s.btcStakingParamsByBtcHeight, "btcHeight"),
		"withdrawable_transactions":          NewRPCFunc(s.withdrawableTransactions, "offset,limit"),
		"btc_tx_blk_details":                 NewRPCFunc(s.btcTxBlkDetails, "txHashStr"),

		// Wallet api
		"list_outputs": NewRPCFunc(s.listOutputs, ""),

		// Babylon api
		"babylon_finality_providers": NewRPCFunc(s.providers, "offset,limit"),
	}
}

// RunUntilShutdown runs the service until the context is canceled
func (s *StakerService) RunUntilShutdown(ctx context.Context, expUser, expPwd string) error {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return nil
	}

	defer func() {
		s.logger.Info("Shutdown complete")
	}()

	defer func() {
		s.logger.Info("Closing database...")
		if err := s.db.Close(); err != nil {
			s.logger.Errorf("Error closing database: %v", err)
		} else {
			s.logger.Info("Database closed")
		}
	}()

	mkErr := func(format string, args ...interface{}) error {
		logFormat := strings.ReplaceAll(format, "%w", "%v")
		s.logger.Errorf("Shutting down because error in main "+
			"method: "+logFormat, args...)
		return fmt.Errorf(format, args...)
	}

	//nolint:contextcheck
	if err := s.staker.Start(); err != nil {
		return mkErr("error starting staker: %w", err)
	}

	defer func() {
		err := s.staker.Stop()
		if err != nil {
			s.logger.WithError(err).Info("staker stop with error")
		}
		s.logger.Info("staker stop complete")
	}()

	routes := s.GetRoutes()
	// This way logger will log to stdout and file
	// TODO: investigate if we can use logrus directly to pass it to rpcserver
	rpcLogger := log.NewTMLogger(s.logger.Writer())

	listeners := make([]net.Listener, len(s.config.RPCListeners))
	for i, listenAddr := range s.config.RPCListeners {
		listenAddressStr := listenAddr.Network() + "://" + listenAddr.String()
		mux := http.NewServeMux()

		authMiddleware := BasicAuthMiddleware(expUser, expPwd)
		RegisterRPCFuncs(mux, routes, rpcLogger, authMiddleware)

		listener, err := rpc.Listen(
			listenAddressStr,
			s.config.JSONRPCServerConfig.MaxOpenConnections,
		)

		if err != nil {
			return mkErr("unable to listen on %s: %v",
				listenAddressStr, err)
		}

		defer func() {
			err := listener.Close()
			if err != nil {
				s.logger.Error("Error closing listener", "err", err)
			}
		}()

		// Start standard HTTP server serving json-rpc
		// TODO: Add additional middleware, like CORS, TLS, etc.
		// TODO: Consider we need some websockets for some notications
		go func() {
			s.logger.Debug("Starting Json RPC HTTP server ", "address: ", listenAddressStr)

			if err := rpc.Serve(
				listener,
				mux,
				rpcLogger,
				s.config.JSONRPCServerConfig.Config(),
			); err != nil {
				s.logger.WithError(err).Error("problem at JSON RPC HTTP server")
			}
			s.logger.Info("Json RPC HTTP server stopped ")
		}()

		listeners[i] = listener
	}

	s.logger.Info("Staker Service fully started")

	// Wait for shutdown signal from either a graceful service stop or from cancel()
	<-ctx.Done()

	s.logger.Info("Received shutdown signal. Stopping...")

	return nil
}

// BasicAuthMiddleware handles the authentication of username and password
// of this router
func BasicAuthMiddleware(expUsername, expPwd string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || !strings.EqualFold(user, expUsername) || !strings.EqualFold(pass, expPwd) {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
}

// ParseCovenantsPubKeyToHex parses public keys into serialized compressed
func ParseCovenantsPubKeyToHex(pks ...*btcec.PublicKey) []string {
	pksHex := make([]string, len(pks))
	for i, pk := range pks {
		pksHex[i] = ParseCovenantPubKeyToHex(pk)
	}
	return pksHex
}

// ParseCovenantPubKeyToHex serializes a covenant pubkey into compressed hex.
func ParseCovenantPubKeyToHex(pk *btcec.PublicKey) string {
	return hex.EncodeToString(pk.SerializeCompressed())
}
