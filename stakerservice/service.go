package stakerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/babylonlabs-io/btc-staker/babylonclient"
	str "github.com/babylonlabs-io/btc-staker/staker"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/jsonrpc/server"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/sirupsen/logrus"
)

const (
	defaultOffset = 0
	defaultLimit  = 50
	maxLimit      = 100
)

type RoutesMap map[string]*rpc.RPCFunc

type StakerService struct {
	started int32

	config *scfg.Config
	staker *str.App
	logger *logrus.Logger
	db     kvdb.Backend
}

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

func storedTxToStakingDetails(storedTx *stakerdb.StoredTransaction) StakingDetails {
	return StakingDetails{
		StakingTxHash:  storedTx.StakingTx.TxHash().String(),
		StakerAddress:  storedTx.StakerAddress,
		StakingState:   storedTx.State.String(),
		Watched:        storedTx.Watched,
		TransactionIdx: strconv.FormatUint(storedTx.StoredTransactionIdx, 10),
	}
}

func (s *StakerService) health(_ *rpctypes.Context) (*ResultHealth, error) {
	return &ResultHealth{}, nil
}

func (s *StakerService) stake(_ *rpctypes.Context,
	stakerAddress string,
	stakingAmount int64,
	fpBtcPks []string,
	stakingTimeBlocks int64,
	sendToBabylonFirst bool,
) (*ResultStake, error) {
	if stakingAmount <= 0 {
		return nil, fmt.Errorf("staking amount must be positive")
	}

	amount := btcutil.Amount(stakingAmount)

	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)
	if err != nil {
		return nil, err
	}

	fpPubKeys := make([]*btcec.PublicKey, 0)

	for _, fpPk := range fpBtcPks {
		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return nil, err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return nil, err
		}

		fpPubKeys = append(fpPubKeys, fpSchnorrKey)
	}

	if stakingTimeBlocks <= 0 || stakingTimeBlocks > math.MaxUint16 {
		return nil, fmt.Errorf("staking time must be positive and lower than %d", math.MaxUint16)
	}

	stakingTimeUint16 := uint16(stakingTimeBlocks)

	stakingTxHash, err := s.staker.StakeFunds(stakerAddr, amount, fpPubKeys, stakingTimeUint16, sendToBabylonFirst)
	if err != nil {
		return nil, err
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

func (s *StakerService) btcDelegationFromBtcStakingTx(
	_ *rpctypes.Context,
	stakerAddress string,
	btcStkTxHash string,
	tag []byte,
	covenantPksHex []string,
	covenantQuorum uint32,
) (*ResultBtcDelegationFromBtcStakingTx, error) {
	stkTxHash, err := chainhash.NewHashFromStr(btcStkTxHash)
	if err != nil {
		s.logger.WithError(err).Info("err parse tx hash")
		return nil, err
	}

	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)
	if err != nil {
		s.logger.WithError(err).Info("err decode staker addr")
		return nil, err
	}

	covenantPks, err := parseCovenantsPubKeyFromHex(covenantPksHex...)
	if err != nil {
		s.logger.WithError(err).Infof("err decode covenant pks %s", covenantPksHex)
		return nil, err
	}

	babylonBTCDelegationTxHash, err := s.staker.SendPhase1Transaction(stakerAddr, stkTxHash, tag, covenantPks, covenantQuorum)
	if err != nil {
		s.logger.WithError(err).Info("err to send phase 1 tx")
		return nil, err
	}

	return &ResultBtcDelegationFromBtcStakingTx{
		BabylonBTCDelegationTxHash: babylonBTCDelegationTxHash,
	}, nil
}

func parseCovenantsPubKeyFromHex(covenantPksHex ...string) ([]*btcec.PublicKey, error) {
	covenantPks := make([]*btcec.PublicKey, len(covenantPksHex))
	for i, covenantPkHex := range covenantPksHex {
		covPk, err := parseCovenantPubKeyFromHex(covenantPkHex)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	pk, err := btcec.ParsePubKey(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func (s *StakerService) btcTxBlkDetails(
	_ *rpctypes.Context,
	txHashStr string,
) (*BtcTxAndBlockResponse, error) {
	txHash, err := chainhash.NewHashFromStr(txHashStr)
	if err != nil {
		return nil, err
	}

	tx, blk, err := s.staker.BtcTxAndBlock(txHash)
	if err != nil {
		return nil, err
	}

	return &BtcTxAndBlockResponse{
		Tx:  tx,
		Blk: blk,
	}, nil
}

func (s *StakerService) stakingDetails(
	_ *rpctypes.Context,
	stakingTxHash string,
) (*StakingDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)
	if err != nil {
		return nil, err
	}

	storedTx, err := s.staker.GetStoredTransaction(txHash)
	if err != nil {
		return nil, err
	}

	details := storedTxToStakingDetails(storedTx)
	return &details, nil
}

func (s *StakerService) spendStake(_ *rpctypes.Context,
	stakingTxHash string) (*SpendTxDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, err
	}

	spendTxHash, value, err := s.staker.SpendStake(txHash)

	if err != nil {
		return nil, err
	}

	txValue := strconv.FormatInt(int64(*value), 10)

	return &SpendTxDetails{
		TxHash:  spendTxHash.String(),
		TxValue: txValue,
	}, nil
}

func (s *StakerService) listOutputs(_ *rpctypes.Context) (*OutputsResponse, error) {
	outputs, err := s.staker.ListUnspentOutputs()

	if err != nil {
		return nil, err
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

type PageParams struct {
	Offset uint64
	Limit  uint64
}

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

func (s *StakerService) providers(_ *rpctypes.Context, offset, limit *int) (*FinalityProvidersResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, err
	}

	providersResp, err := s.staker.ListActiveFinalityProviders(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, err
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

func (s *StakerService) listStakingTransactions(_ *rpctypes.Context, offset, limit *int) (*ListStakingTransactionsResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, err
	}

	txResult, err := s.staker.StoredTransactions(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, err
	}

	var stakingDetails []StakingDetails

	for _, tx := range txResult.Transactions {
		tx := tx
		stakingDetails = append(stakingDetails, storedTxToStakingDetails(&tx))
	}

	totalCount := strconv.FormatUint(txResult.Total, 10)

	return &ListStakingTransactionsResponse{
		Transactions:          stakingDetails,
		TotalTransactionCount: totalCount,
	}, nil
}

func (s *StakerService) withdrawableTransactions(_ *rpctypes.Context, offset, limit *int) (*WithdrawableTransactionsResponse, error) {
	pageParams, err := getPageParams(offset, limit)
	if err != nil {
		return nil, err
	}

	txResult, err := s.staker.WithdrawableTransactions(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, err
	}

	var stakingDetails []StakingDetails

	for _, tx := range txResult.Transactions {
		stakingDetails = append(stakingDetails, storedTxToStakingDetails(&tx))
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

func decodeBtcTx(txHex string) (*wire.MsgTx, error) {
	txBytes, err := hex.DecodeString(txHex)

	if err != nil {
		return nil, err
	}

	var txMsg wire.MsgTx

	err = txMsg.Deserialize(bytes.NewReader(txBytes))

	if err != nil {
		return nil, err
	}

	return &txMsg, nil
}

func decodeBtcPk(pkHex string) (*btcec.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkHex)

	if err != nil {
		return nil, err
	}

	pk, err := schnorr.ParsePubKey(pkBytes)

	if err != nil {
		return nil, err
	}

	return pk, nil
}

func parseTimeBtcLock(timelockTime int) (uint16, error) {
	if timelockTime <= 0 {
		return 0, fmt.Errorf("staking time must be positive")
	}

	if timelockTime > math.MaxUint16 {
		return 0, fmt.Errorf("staking time %d is too big", timelockTime)
	}

	return uint16(timelockTime), nil
}

func parseStakingValue(stakingValue int) (btcutil.Amount, error) {
	if stakingValue <= 0 {
		return 0, fmt.Errorf("staking value must be positive")
	}

	return btcutil.Amount(stakingValue), nil
}

func (s *StakerService) watchStaking(
	_ *rpctypes.Context,
	stakingTx string,
	stakingTime int,
	stakingValue int,
	stakerBtcPk string,
	fpBtcPks []string,
	slashingTx string,
	slashingTxSig string,
	stakerBabylonAddr string,
	stakerAddress string,
	stakerBtcSig string,
	unbondingTx string,
	slashUnbondingTx string,
	slashUnbondingTxSig string,
	unbondingTime int,
	popType int,
) (*ResultStake, error) {
	stkTx, err := decodeBtcTx(stakingTx)
	if err != nil {
		return nil, err
	}

	slshTx, err := decodeBtcTx(slashingTx)
	if err != nil {
		return nil, err
	}

	stakerBtcPkParsed, err := decodeBtcPk(stakerBtcPk)

	if err != nil {
		return nil, err
	}

	fpPubKeys := make([]*btcec.PublicKey, 0)

	for _, fpPk := range fpBtcPks {
		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return nil, err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return nil, err
		}

		fpPubKeys = append(fpPubKeys, fpSchnorrKey)
	}

	stakingTimeUint16, err := parseTimeBtcLock(stakingTime)

	if err != nil {
		return nil, err
	}

	stakingValueBtc, err := parseStakingValue(stakingValue)

	if err != nil {
		return nil, err
	}

	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)
	if err != nil {
		return nil, err
	}

	slashTxSigBytes, err := hex.DecodeString(slashingTxSig)
	if err != nil {
		return nil, err
	}

	slashingTxSchnorSig, err := schnorr.ParseSignature(slashTxSigBytes)
	if err != nil {
		return nil, err
	}

	stakerBtcSigBytes, err := hex.DecodeString(stakerBtcSig)
	if err != nil {
		return nil, err
	}

	btcPopType, err := babylonclient.IntToPopType(popType)
	if err != nil {
		return nil, err
	}

	proofOfPossesion, err := babylonclient.NewBabylonPop(btcPopType, stakerBtcSigBytes)
	if err != nil {
		return nil, err
	}

	// Unbonding related data
	unbTx, err := decodeBtcTx(unbondingTx)
	if err != nil {
		return nil, err
	}

	slshUnbTx, err := decodeBtcTx(slashUnbondingTx)
	if err != nil {
		return nil, err
	}

	slashUnbTxSigBytes, err := hex.DecodeString(slashUnbondingTxSig)
	if err != nil {
		return nil, err
	}

	slashUnbTxSig, err := schnorr.ParseSignature(slashUnbTxSigBytes)
	if err != nil {
		return nil, err
	}

	unbTime, err := parseTimeBtcLock(unbondingTime)
	if err != nil {
		return nil, err
	}

	bbnStakerAddr, err := sdk.AccAddressFromBech32(stakerBabylonAddr)
	if err != nil {
		return nil, err
	}

	bbnSignerAddrInConfig := s.staker.BabylonController().GetKeyAddress()
	if !bbnStakerAddr.Equals(bbnSignerAddrInConfig) {
		return nil, fmt.Errorf(
			"bbn staking address in config: %s must match with stakerBabylonAddr in parameters: %s",
			bbnSignerAddrInConfig.String(), bbnStakerAddr.String(),
		)
	}

	hash, err := s.staker.WatchStaking(
		stkTx,
		stakingTimeUint16,
		stakingValueBtc,
		fpPubKeys,
		slshTx,
		slashingTxSchnorSig,
		bbnStakerAddr,
		stakerBtcPkParsed,
		stakerAddr,
		proofOfPossesion,
		unbTx,
		slshUnbTx,
		slashUnbTxSig,
		unbTime,
	)
	if err != nil {
		return nil, err
	}

	return &ResultStake{
		TxHash: hash.String(),
	}, nil
}

func (s *StakerService) unbondStaking(_ *rpctypes.Context, stakingTxHash string) (*UnbondingResponse, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, err
	}

	unbondingTxHash, err := s.staker.UnbondStaking(*txHash)

	if err != nil {
		return nil, err
	}

	return &UnbondingResponse{
		UnbondingTxHash: unbondingTxHash.String(),
	}, nil
}

func (s *StakerService) GetRoutes() RoutesMap {
	return RoutesMap{
		// info AP
		"health": rpc.NewRPCFunc(s.health, ""),
		// staking API
		"stake":                              rpc.NewRPCFunc(s.stake, "stakerAddress,stakingAmount,fpBtcPks,stakingTimeBlocks,sendToBabylonFirst"),
		"btc_delegation_from_btc_staking_tx": rpc.NewRPCFunc(s.btcDelegationFromBtcStakingTx, "stakerAddress,btcStkTxHash,tag,covenantPksHex,covenantQuorum"),
		"staking_details":                    rpc.NewRPCFunc(s.stakingDetails, "stakingTxHash"),
		"spend_stake":                        rpc.NewRPCFunc(s.spendStake, "stakingTxHash"),
		"list_staking_transactions":          rpc.NewRPCFunc(s.listStakingTransactions, "offset,limit"),
		"unbond_staking":                     rpc.NewRPCFunc(s.unbondStaking, "stakingTxHash"),
		"withdrawable_transactions":          rpc.NewRPCFunc(s.withdrawableTransactions, "offset,limit"),
		"btc_tx_blk_details":                 rpc.NewRPCFunc(s.btcTxBlkDetails, "txHashStr"),
		// watch api
		"watch_staking_tx": rpc.NewRPCFunc(s.watchStaking, "stakingTx,stakingTime,stakingValue,stakerBtcPk,fpBtcPks,slashingTx,slashingTxSig,stakerBabylonAddr,stakerAddress,stakerBtcSig,unbondingTx,slashUnbondingTx,slashUnbondingTxSig,unbondingTime,popType"),

		// Wallet api
		"list_outputs": rpc.NewRPCFunc(s.listOutputs, ""),

		// Babylon api
		"babylon_finality_providers": rpc.NewRPCFunc(s.providers, "offset,limit"),
	}
}

func (s *StakerService) RunUntilShutdown(ctx context.Context) error {
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
	// TODO: Add staker service dedicated config to define those values
	config := rpc.DefaultConfig()
	// This way logger will log to stdout and file
	// TODO: investigate if we can use logrus directly to pass it to rpcserver
	rpcLogger := log.NewTMLogger(s.logger.Writer())

	listeners := make([]net.Listener, len(s.config.RPCListeners))
	for i, listenAddr := range s.config.RPCListeners {
		listenAddressStr := listenAddr.Network() + "://" + listenAddr.String()
		mux := http.NewServeMux()
		rpc.RegisterRPCFuncs(mux, routes, rpcLogger)

		listener, err := rpc.Listen(
			listenAddressStr,
			config.MaxOpenConnections,
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

			err := rpc.Serve(
				listener,
				mux,
				rpcLogger,
				config,
			)
			if err != nil {
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
