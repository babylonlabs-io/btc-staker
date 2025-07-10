package staker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	bct "github.com/babylonlabs-io/babylon/client/babylonclient"

	"github.com/avast/retry-go/v4"
	staking "github.com/babylonlabs-io/babylon/btcstaking"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/metrics"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"go.uber.org/zap"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/sirupsen/logrus"
)

type externalDelegationData struct {
	// babylonStakerAddr the bech32 bbn address to receive staking rewards.
	babylonStakerAddr sdk.AccAddress
	// stakerPublicKey the public key of the staker.
	stakerPublicKey *btcec.PublicKey
	// params retrieved from babylon
	babylonParams *cl.StakingParams
}

// TODO: stop-gap solution for long running retry operations. Ultimately we need to
// bound number of total pending bonding/unboning operation.
var (
	longRetryNum      = uint(30)
	longRetryAttempts = retry.Attempts(longRetryNum)
	RtyErr            = retry.LastErrorOnly(true)
)

func longRetryOps(ctx context.Context, fixedDelay time.Duration, onRetryFn retry.OnRetryFunc) []retry.Option {
	return []retry.Option{
		retry.Context(ctx),
		retry.DelayType(retry.FixedDelay),
		retry.Delay(fixedDelay),
		longRetryAttempts,
		retry.OnRetry(onRetryFn),
		RtyErr,
	}
}

func (app *App) onLongRetryFunc(stakingTxHash *chainhash.Hash, msg string) retry.OnRetryFunc {
	return func(n uint, err error) {
		app.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": longRetryNum,
			"error":        err,
			"txHash":       stakingTxHash,
		}).Error(msg)
	}
}

const (
	// Internal slashing fee to adjust to in case babylon provide too small fee
	// Slashing tx is around 113 bytes (depending on output address which we need to chose), with fee 8sats/b
	// this gives us 904 satoshi fee. Lets round it 1000 satoshi
	minSlashingFee = btcutil.Amount(1000)

	// after this many confirmations we consider transaction which spends staking tx as
	// confirmed on btc
	SpendStakeTxConfirmations = 3

	// 2 hours seems like a reasonable timeout waiting for spend tx confirmations given
	// probabilistic nature of bitcoin
	timeoutWaitingForSpendConfirmation = 2 * time.Hour

	defaultWalletUnlockTimeout = 15

	// If we fail to send unbonding tx to btc for any reason we will retry in this time
	unbondingSendRetryTimeout = 1 * time.Minute

	// after this many confirmations we treat unbonding transaction as confirmed on btc
	// TODO: needs to consolidate what is safe confirmation for different types of transaction
	// as currently we have different values for different types of transactions
	UnbondingTxConfirmations = 6
)

type App struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	babylonClient    cl.BabylonClient
	wc               walletcontroller.WalletController
	notifier         notifier.ChainNotifier
	feeEstimator     FeeEstimator
	network          *chaincfg.Params
	config           *scfg.Config
	logger           *logrus.Logger
	txTracker        *stakerdb.TrackedTransactionStore
	babylonMsgSender *cl.BabylonMsgSender
	m                *metrics.StakerMetrics

	stakingRequestedCmdChan                       chan *stakingRequestCmd
	migrateStakingCmd                             chan *migrateStakingCmd
	delegationActivatedEvChan                     chan *delegationActivatedEvent
	unbondingTxSignaturesConfirmedOnBabylonEvChan chan *unbondingTxSignaturesConfirmedOnBabylonEvent
	unbondingTxConfirmedOnBtcEvChan               chan *unbondingTxConfirmedOnBtcEvent
	spendStakeTxConfirmedOnBtcEvChan              chan *spendStakeTxConfirmedOnBtcEvent
	criticalErrorEvChan                           chan *criticalErrorEvent
	currentBestBlockHeight                        atomic.Uint32
}

// NewStakerAppFromConfig creates a new staker app instance from the given config
func NewStakerAppFromConfig(
	config *scfg.Config,
	logger *logrus.Logger,
	rpcClientLogger *zap.Logger,
	db kvdb.Backend,
	m *metrics.StakerMetrics,
) (*App, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRPCWalletController(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet controller: %w", err)
	}

	tracker, err := stakerdb.NewTrackedTransactionStore(db)

	if err != nil {
		return nil, fmt.Errorf("failed to create tracked transaction store: %w", err)
	}

	babylonClient, err := cl.NewBabylonController(config.BabylonConfig, &config.ActiveNetParams, logger, rpcClientLogger)

	if err != nil {
		return nil, fmt.Errorf("failed to create Babylon controller: %w", err)
	}

	hintCache, err := channeldb.NewHeightHintCache(
		channeldb.CacheConfig{
			// TODO: Investigate this option. Lighting docs mention that this is necessary for some edge case
			QueryDisable: false,
		}, db,
	)

	if err != nil {
		return nil, fmt.Errorf("unable to create height hint cache: %w", err)
	}

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams, hintCache)

	if err != nil {
		return nil, fmt.Errorf("failed to create node backend with notifier: %w", err)
	}

	var feeEstimator FeeEstimator
	switch config.BtcNodeBackendConfig.EstimationMode {
	case types.StaticFeeEstimation:
		feeEstimator = NewStaticBtcFeeEstimator(chainfee.SatPerKVByte(config.BtcNodeBackendConfig.MaxFeeRate * 1000))
	case types.DynamicFeeEstimation:
		feeEstimator, err = NewDynamicBtcFeeEstimator(config.BtcNodeBackendConfig, &config.ActiveNetParams, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create dynamic fee estimator: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown fee estimation mode: %d", config.BtcNodeBackendConfig.EstimationMode)
	}

	babylonMsgSender := cl.NewBabylonMsgSender(babylonClient, logger, config.StakerConfig.MaxConcurrentTransactions)

	return NewStakerAppFromDeps(
		config,
		logger,
		babylonClient,
		walletClient,
		nodeNotifier,
		feeEstimator,
		tracker,
		babylonMsgSender,
		m,
	)
}

// NewStakerAppFromDeps creates a new staker app instance from the given dependencies
func NewStakerAppFromDeps(
	config *scfg.Config,
	logger *logrus.Logger,
	cl cl.BabylonClient,
	walletClient walletcontroller.WalletController,
	nodeNotifier notifier.ChainNotifier,
	feeEestimator FeeEstimator,
	tracker *stakerdb.TrackedTransactionStore,
	babylonMsgSender *cl.BabylonMsgSender,
	metrics *metrics.StakerMetrics,
) (*App, error) {
	return &App{
		babylonClient:           cl,
		wc:                      walletClient,
		notifier:                nodeNotifier,
		feeEstimator:            feeEestimator,
		network:                 &config.ActiveNetParams,
		txTracker:               tracker,
		babylonMsgSender:        babylonMsgSender,
		m:                       metrics,
		config:                  config,
		logger:                  logger,
		quit:                    make(chan struct{}),
		stakingRequestedCmdChan: make(chan *stakingRequestCmd),
		// channel to receive requests of transition of BTC staking tx to consumer BTC delegation
		migrateStakingCmd: make(chan *migrateStakingCmd),
		// event for when delegation is active on babylon after going through pre approval flow
		delegationActivatedEvChan: make(chan *delegationActivatedEvent),
		// event emitte	d upon transaction which spends staking transaction is confirmed on BTC
		spendStakeTxConfirmedOnBtcEvChan: make(chan *spendStakeTxConfirmedOnBtcEvent),
		// channel which receives unbonding signatures from covenant for unbonding
		// transaction
		unbondingTxSignaturesConfirmedOnBabylonEvChan: make(chan *unbondingTxSignaturesConfirmedOnBabylonEvent),
		// channel which receives confirmation that unbonding transaction was confirmed on BTC
		unbondingTxConfirmedOnBtcEvChan: make(chan *unbondingTxConfirmedOnBtcEvent),
		// channel which receives critical errors, critical errors are errors which we do not know
		// how to handle, so we just log them. It is up to user to investigate what had happened
		// and report the situation
		criticalErrorEvChan: make(chan *criticalErrorEvent),
	}, nil
}

// Start starts the staker app
func (app *App) Start() error {
	var startErr error
	app.startOnce.Do(func() {
		app.logger.Infof("Starting App")

		// TODO: This can take a long time as it connects to node. Maybe make it cancellable?
		// although staker without node is not very useful

		app.logger.Infof("Connecting to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)
		if err := app.notifier.Start(); err != nil {
			startErr = err
			return
		}

		app.logger.Infof("Successfully connected to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)

		blockEventNotifier, err := app.notifier.RegisterBlockEpochNtfn(nil)

		if err != nil {
			startErr = err
			return
		}

		if err = app.feeEstimator.Start(); err != nil {
			startErr = err
			return
		}

		// we registered for notifications with `nil`  so we should receive best block
		// immediately
		select {
		case block := <-blockEventNotifier.Epochs:
			if block.Height < 0 {
				startErr = errors.New("block height is negative")
				return
			}
			app.currentBestBlockHeight.Store(uint32(block.Height))
		case <-app.quit:
			startErr = errors.New("staker app quit before finishing start")
			return
		}

		app.logger.Infof("Initial btc best block height is: %d", app.currentBestBlockHeight.Load())

		app.babylonMsgSender.Start()

		app.wg.Add(3)
		go app.handleNewBlocks(blockEventNotifier)
		go app.handleStakingEvents()
		go app.handleStakingCommands()

		if err := app.checkTransactionsStatus(); err != nil {
			startErr = err
			return
		}

		app.logger.Info("App started")
	})

	return startErr
}

// handleNewBlocks is a goroutine which handles notifications about new
// best block
func (app *App) handleNewBlocks(blockNotifier *notifier.BlockEpochEvent) {
	defer app.wg.Done()
	defer blockNotifier.Cancel()
	for {
		select {
		case block, ok := <-blockNotifier.Epochs:
			if !ok {
				return
			}
			app.m.CurrentBtcBlockHeight.Set(float64(block.Height))
			app.currentBestBlockHeight.Store(uint32(block.Height))

			app.logger.WithFields(logrus.Fields{
				"btcBlockHeight": block.Height,
				"btcBlockHash":   block.Hash.String(),
			}).Debug("Received new best btc block")
		case <-app.quit:
			return
		}
	}
}

// Stop stops the staker app
func (app *App) Stop() error {
	var stopErr error
	app.stopOnce.Do(func() {
		app.logger.Infof("Stopping App")
		close(app.quit)
		app.wg.Wait()

		app.babylonMsgSender.Stop()

		err := app.feeEstimator.Stop()

		if err != nil {
			stopErr = err
			return
		}

		err = app.notifier.Stop()
		if err != nil {
			stopErr = err
			return
		}
	})
	return stopErr
}

// reportCriticialError sends a critical error event to the criticalErrorEvChan
func (app *App) reportCriticialError(
	stakingTxHash chainhash.Hash,
	err error,
	additionalContext string,
) {
	ev := &criticalErrorEvent{
		stakingTxHash:     stakingTxHash,
		err:               err,
		additionalContext: additionalContext,
	}

	utils.PushOrQuit[*criticalErrorEvent](
		app.criticalErrorEvChan,
		ev,
		app.quit,
	)
}

// SendPhase1Transaction receives the BTC staking transaction hash that
// should be already in BTC and creates the necessary data to submit
// the BTC delegation into the consumer chain
func (app *App) SendPhase1Transaction(
	stakerAddr btcutil.Address,
	stkTxHash *chainhash.Hash,
	covenantPks []*secp256k1.PublicKey,
	covenantQuorum uint32,
) (babylonBTCDelegationTxHash string, err error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return "", nil
	default:
	}

	parsedStakingTx, notifierTx, status, err := walletcontroller.StkTxV0ParsedWithBlock(app.wc, app.network, stkTxHash, covenantPks, covenantQuorum)
	if err != nil {
		app.logger.WithError(err).Info("err getting tx details")
		return "", err
	}
	if status != walletcontroller.TxInChain {
		app.logger.WithError(err).Info("BTC tx not on chain")
		return "", err
	}

	pop, err := app.unlockAndCreatePop(stakerAddr)
	if err != nil {
		return "", err
	}

	req := newMigrateStakingCmd(stakerAddr, notifierTx, parsedStakingTx, pop)
	utils.PushOrQuit[*migrateStakingCmd](
		app.migrateStakingCmd,
		req,
		app.quit,
	)

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddr,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return "", reqErr
	case hash := <-req.successChanTxHash:
		return hash, nil
	case <-app.quit:
		return "", nil
	}
}

// checkTransactionsStatus checks the status of all transactions in the stored transaction database
func (app *App) checkTransactionsStatus() error {
	app.logger.Debug("Start checking transaction status from stored transaction database")

	var transactions []chainhash.Hash

	reset := func() {
		transactions = make([]chainhash.Hash, 0)
	}

	// add stored transactions to slice
	if err := app.txTracker.ScanTrackedTransactions(func(tx *stakerdb.StoredTransaction) error {
		txHash := tx.StakingTx.TxHash()
		transactions = append(transactions, txHash)
		return nil
	}, reset); err != nil {
		return fmt.Errorf("error while checking and handling stored transactions: %w", err)
	}

	for _, txHash := range transactions {
		di, err := app.babylonClient.QueryBTCDelegation(&txHash)
		if err != nil {
			return fmt.Errorf("failed to get transaction <%s> delegation info from babylon: %w", txHash.String(), err)
		}
		stakingOutputIndex := di.BtcDelegation.StakingOutputIdx

		// Check transaction status
		switch di.BtcDelegation.GetStatusDesc() {
		case BabylonPendingStatus:
			app.handlePendingTransaction(&txHash)
		case BabylonVerifiedStatus:
			app.handleVerifiedTransaction(&txHash, stakingOutputIndex)
		case BabylonActiveStatus:
			udi, err := app.babylonClient.GetUndelegationInfo(di)
			if err != nil {
				return fmt.Errorf("failed to get undelegation info: %w", err)
			}
			if err := app.handleActiveTransaction(&txHash, stakingOutputIndex, udi.UnbondingTransaction); err != nil {
				return fmt.Errorf("failed to handle active transaction <%s>: %w", txHash.String(), err)
			}
		}
	}

	return nil
}

// handlePendingTransaction handles transactions which status is PENDING in babylon node
func (app *App) handlePendingTransaction(stakingTxHash *chainhash.Hash) {
	// we crashed after successful send to babylon, restart checking for unbonding signatures
	app.wg.Add(1)
	go app.checkForUnbondingTxSignaturesOnBabylon(stakingTxHash)
}

// handleVerifiedTransaction handles transactions which status is VERIFIED in babylon node
func (app *App) handleVerifiedTransaction(stakingTxHash *chainhash.Hash, stakingOutputIndex uint32) {
	txHashCopy := *stakingTxHash
	storedTx, _ := app.mustGetTransactionAndStakerAddress(&txHashCopy)
	app.wg.Add(1)
	go app.activateVerifiedDelegation(
		storedTx.StakingTx,
		stakingOutputIndex,
		&txHashCopy,
	)
}

// handleActiveTransaction handles transactions which status is ACTIVE in babylon node
func (app *App) handleActiveTransaction(stakingTxHash *chainhash.Hash, stakingOutputIndex uint32, unbondingTx *wire.MsgTx) error {
	// In this status, delegation was sent to Babylon and activated by covenants.
	// check whether we:
	// - did not spend tx before restart
	// - did not send unbonding tx before restart
	// tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)

	// 1. First check if staking output is still unspent on BTC chain
	stakingOutputSpent, err := app.wc.OutputSpent(stakingTxHash, stakingOutputIndex)
	if err != nil {
		return fmt.Errorf("failed to check staking output spentness: %w", err)
	}

	if !stakingOutputSpent {
		// If the staking output is unspent, then it means that delegation is
		// sitll considered active. We can move forward without to next transaction
		// and leave the state as it is.
		return nil
	}

	// 2. Staking output has been spent, we need to check whether this is unbonding
	// or withdrawal transaction
	unbondingTxHash := unbondingTx.TxHash()
	pkScript := unbondingTx.TxOut[0].PkScript

	confirmationInfo, unbondingTxStatus, err := app.wc.TxDetails(
		&unbondingTxHash,
		// unbonding tx always have only one output
		pkScript,
	)
	if err != nil {
		return fmt.Errorf("failed to check unbonding tx status: %w", err)
	}

	if unbondingTxStatus == walletcontroller.TxNotFound {
		// no unbonding tx on chain and staking output already spent, most probably
		// staking transaction has been withdrawn, update state in db
		if err := app.txTracker.DeleteTransactionSentToBabylon(stakingTxHash); err != nil {
			return fmt.Errorf("failed to delete tx status from db: %w", err)
		}
		return nil
	}

	unbondingOutputSpent, err := app.wc.OutputSpent(&unbondingTxHash, 0)
	if err != nil {
		return fmt.Errorf("failed to check unbonding output spentness: %w", err)
	}

	// stakingTransaction is already spent on BTC
	if unbondingOutputSpent {
		if err := app.txTracker.DeleteTransactionSentToBabylon(stakingTxHash); err != nil {
			return fmt.Errorf("failed to delete tx status from db: %w", err)
		}
		return nil
	}

	// At this point:
	// - staking output is spent
	// - unbonding tx has been found in the btc chain
	// - unbonding output is not spent
	// we can start waiting for unbonding tx confirmation
	ev, err := app.notifier.RegisterConfirmationsNtfn(
		&unbondingTxHash,
		pkScript,
		UnbondingTxConfirmations,
		// unbonding transactions will for sure be included after staking tranasction
		// tx.StakingTxConfirmationInfo.Height,
		confirmationInfo.BlockHeight,
	)
	if err != nil {
		return fmt.Errorf("failed to register confirmations ntfn: %w", err)
	}

	// unbonding tx is in mempool, wait for confirmation and inform event
	// loop about it
	app.wg.Add(1)
	go app.waitForUnbondingTxConfirmation(
		ev,
		&unbondingTxHash,
		stakingTxHash,
	)
	return nil
}

// getSlashingFee returns the slashing fee to use
func (app *App) getSlashingFee(feeFromBabylon btcutil.Amount) btcutil.Amount {
	if feeFromBabylon < minSlashingFee {
		app.logger.WithFields(logrus.Fields{
			"babylonSlashingFee":  feeFromBabylon,
			"internalSlashingFee": minSlashingFee,
		}).Debug("Slashing fee received from Babylon is too small. Using internal minimum fee")
		return minSlashingFee
	}

	return feeFromBabylon
}

// helper to retrieve transaction when we are sure it must be in the store
func (app *App) mustGetTransactionAndStakerAddress(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, btcutil.Address) {
	ts, err := app.txTracker.GetTransaction(txHash)

	if err != nil {
		app.logger.Fatalf("Error getting transaction state for tx %s. Eff: %v", txHash, err)
	}

	stakerAddress, err := btcutil.DecodeAddress(ts.StakerAddress, app.network)

	if err != nil {
		app.logger.Fatalf("Error decoding staker address: %s. Err: %v", ts.StakerAddress, err)
	}

	return ts, stakerAddress
}

// mustBuildInclusionProof builds an inclusion proof for a given transaction
func (app *App) mustBuildInclusionProof(
	inclusionBlock *wire.MsgBlock,
	txIndex uint32,
) []byte {
	proof, err := cl.GenerateProof(inclusionBlock, txIndex)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"err": err,
		}).Fatalf("Failed to build inclusion proof for already confirmed transaction")
	}

	return proof
}

// newBtcInclusionInfo returns a new inclusionInfo
func (app *App) newBtcInclusionInfo(notifierTx *notifier.TxConfirmation) *inclusionInfo {
	return &inclusionInfo{
		txIndex:                 notifierTx.TxIndex,
		inclusionBlock:          notifierTx.Block,
		inclusionBlockBtcHeight: notifierTx.BlockHeight,
		inclusionProof: app.mustBuildInclusionProof(
			notifierTx.Block,
			notifierTx.TxIndex,
		),
	}
}

// retrieveExternalDelegationData retrieves the external delegation data for a given staker address and inclusion info
func (app *App) retrieveExternalDelegationData(
	stakerAddress btcutil.Address,
	inclusionInfo *inclusionInfo,
) (*externalDelegationData, error) {
	var params *cl.StakingParams

	if inclusionInfo == nil {
		// chose params as babylon would through tip of btc light client
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

	stakerPublicKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		return nil, fmt.Errorf("error getting staker public key: %w", err)
	}

	return &externalDelegationData{
		babylonStakerAddr: app.babylonClient.GetKeyAddress(),
		stakerPublicKey:   stakerPublicKey,
		babylonParams:     params,
	}, nil
}

// sendUnbondingTxToBtcWithWitness sends an unbonding tx to btc with witness
func (app *App) sendUnbondingTxToBtcWithWitness(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	fpBtcPubkeys []*btcec.PublicKey,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	undelegationInfo *cl.UndelegationInfo,
) error {
	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Failed to retrieve btc wallet private key send unbonding tx to btc")
		return fmt.Errorf("error getting staker public key: %w", err)
	}

	// TODO: As covenant committee is static, consider quering it once and storing in database
	params, err := app.babylonClient.Params()
	if err != nil {
		return fmt.Errorf("error getting params: %w", err)
	}

	unbondingSpendInfo, err := buildUnbondingSpendInfo(
		stakerPubKey,
		fpBtcPubkeys,
		storedTx,
		stakingOutputIndex,
		stakingTime,
		undelegationInfo,
		params,
		app.network,
	)

	if err != nil {
		// we panic here, as our data should be correct at this point
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("failed to create necessary spend info to send unbonding tx")
	}

	stakerUnbondingSig, err := app.signTaprootScriptSpendUsingWallet(
		undelegationInfo.UnbondingTransaction,
		storedTx.StakingTx.TxOut[stakingOutputIndex],
		stakerAddress,
		&unbondingSpendInfo.RevealedLeaf,
		&unbondingSpendInfo.ControlBlock,
	)

	if err != nil {
		return fmt.Errorf("failed to send unbondingtx. wallet signing error: %w", err)
	}

	if stakerUnbondingSig.Signature == nil {
		return fmt.Errorf("failed to receive stakerUnbondingSig.Signature")
	}

	covenantSigantures, err := createWitnessSignaturesForPubKeys(
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		undelegationInfo.CovenantUnbondingSignatures,
	)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("failed to create witness to send unbonding tx")
	}

	witness, err := unbondingSpendInfo.CreateUnbondingPathWitness(
		covenantSigantures,
		stakerUnbondingSig.Signature,
	)

	if err != nil {
		// we panic here, as our data should be correct at this point
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("failed to build witness from correct data")
	}

	unbondingTx := undelegationInfo.UnbondingTransaction

	unbondingTx.TxIn[0].Witness = witness

	_, err = app.wc.SendRawTransaction(unbondingTx, true)

	if err != nil {
		return fmt.Errorf("failed to send unbonding tx. wallet signing error: %w", err)
	}

	return nil
}

// sendUnbondingTxToBtc sends unbonding tx to btc and registers for inclusion notification.
// It retries until it successfully sends unbonding tx to btc and registers for notification.or until program finishes
// TODO: Investigate whether some of the errors should be treated as fatal and abort whole process
func (app *App) sendUnbondingTxToBtc(
	ctx context.Context,
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	undelegationInfo *cl.UndelegationInfo,
	fpBtcPubkeys []*btcec.PublicKey,
) (*notifier.ConfirmationEvent, error) {
	err := retry.Do(func() error {
		return app.sendUnbondingTxToBtcWithWitness(
			stakingTxHash,
			stakerAddress,
			fpBtcPubkeys,
			stakingOutputIndex,
			stakingTime,
			storedTx,
			undelegationInfo,
		)
	},
		longRetryOps(
			ctx,
			unbondingSendRetryTimeout,
			app.onLongRetryFunc(stakingTxHash, "failed to send unbonding tx to btc"),
		)...,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to send unbonding tx to btc: %w", err)
	}

	bestBlockAfterSend := app.currentBestBlockHeight.Load()
	unbondingTxHash := undelegationInfo.UnbondingTransaction.TxHash()

	var notificationEv *notifier.ConfirmationEvent
	err = retry.Do(func() error {
		ev, err := app.notifier.RegisterConfirmationsNtfn(
			&unbondingTxHash,
			undelegationInfo.UnbondingTransaction.TxOut[0].PkScript,
			UnbondingTxConfirmations,
			bestBlockAfterSend,
		)

		if err != nil {
			return fmt.Errorf("failed to register for unbonding tx confirmation notification: %w", err)
		}
		notificationEv = ev
		return nil
	},
		longRetryOps(
			ctx,
			unbondingSendRetryTimeout,
			app.onLongRetryFunc(stakingTxHash, "failed to register for unbonding tx confirmation notification"),
		)...,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to register for unbonding tx confirmation notification: %w", err)
	}
	return notificationEv, nil
}

// waitForUnbondingTxConfirmation blocks until unbonding tx is confirmed on btc chain.
func (app *App) waitForUnbondingTxConfirmation(
	waitEv *notifier.ConfirmationEvent,
	unbondingTxHash *chainhash.Hash,
	stakingTxHash *chainhash.Hash,
) {
	defer app.wg.Done()
	defer waitEv.Cancel()

	for {
		select {
		case conf := <-waitEv.Confirmed:
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash":   stakingTxHash,
				"unbondingTxHash": unbondingTxHash,
				"blockHash":       conf.BlockHash,
				"blockHeight":     conf.BlockHeight,
			}).Debug("Unbonding tx confirmed")

			req := &unbondingTxConfirmedOnBtcEvent{
				stakingTxHash: *stakingTxHash,
				blockHash:     *conf.BlockHash,
				blockHeight:   conf.BlockHeight,
			}

			utils.PushOrQuit[*unbondingTxConfirmedOnBtcEvent](
				app.unbondingTxConfirmedOnBtcEvChan,
				req,
				app.quit,
			)

			return
		case u := <-waitEv.Updates:
			app.logger.WithFields(logrus.Fields{
				"unbondingTxHash": unbondingTxHash,
				"confLeft":        u,
			}).Debugf("Unbonding transaction received confirmation")
		case <-app.quit:
			return
		}
	}
}

// sendUnbondingTxToBtcTask tries to send unbonding tx to btc and register for confirmation notification.
// it should be run in separate go routine.
func (app *App) sendUnbondingTxToBtcTask(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
	fpBtcPubkeys []*btcec.PublicKey,
	undelegationInfo *cl.UndelegationInfo,
) {
	defer app.wg.Done()
	quitCtx, cancel := app.appQuitContext()
	defer cancel()

	waitEv, err := app.sendUnbondingTxToBtc(
		quitCtx,
		stakingTxHash,
		stakerAddress,
		stakingOutputIndex,
		stakingTime,
		storedTx,
		undelegationInfo,
		fpBtcPubkeys,
	)

	if err != nil {
		app.reportCriticialError(*stakingTxHash, err, "Failed failed to send unbonding tx to btc")
		return
	}

	unbondingTxHash := undelegationInfo.UnbondingTransaction.TxHash()

	app.wg.Add(1)
	go app.waitForUnbondingTxConfirmation(
		waitEv,
		&unbondingTxHash,
		stakingTxHash,
	)
}

// context which will be cancelled when app is shutting down
func (app *App) appQuitContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	app.wg.Add(1)
	go func() {
		defer cancel()
		defer app.wg.Done()

		select {
		case <-app.quit:

		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// builds and sends a delegation
func (app *App) buildAndSendDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
) (*bct.RelayerTxResponse, *cl.DelegationData, error) {
	delegation, err := app.buildDelegation(req, stakerAddress, stakingOutputIndex, stakingTime, storedTx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build delegation: %w", err)
	}

	resp, err := app.babylonMsgSender.SendDelegation(delegation, req.requiredInclusionBlockDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send delegation: %w", err)
	}

	return resp, delegation, nil
}

// handles a send delegation request
func (app *App) handleSendDelegationRequest(
	stakerAddress btcutil.Address,
	stakingTime uint16,
	requiredDepthOnBtcChain uint32,
	fpBtcPks []*secp256k1.PublicKey,
	pop *cl.BabylonPop,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	inclusionInfo *inclusionInfo,
) (btcTxHash *chainhash.Hash, btcDelTxHash string, err error) {
	// check pop is not nil
	if pop == nil {
		return nil, btcDelTxHash, fmt.Errorf("cannot add transaction without proof of possession")
	}

	// just to pass to buildAndSendDelegation
	fakeStoredTx, err := stakerdb.CreateTrackedTransaction(
		stakingTx,
		stakerAddress,
	)
	if err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to create tracked transaction: %w", err)
	}

	stakingTxHash := stakingTx.TxHash()

	req := newSendDelegationRequest(&stakingTxHash, inclusionInfo, requiredDepthOnBtcChain, fpBtcPks, pop)
	// resp, delegationData, err := app.buildAndSendDelegation(
	resp, _, err := app.buildAndSendDelegation(
		req,
		stakerAddress,
		stakingOutputIdx,
		stakingTime,
		fakeStoredTx,
	)
	if err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to build and send delegation: %w", err)
	}

	if err := app.txTracker.AddTransactionSentToBabylon(
		stakingTx,
		// stakingTime,
		stakerAddress,
		// delegationData.Ud.UnbondingTxUnbondingTime,
	); err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to add transaction sent to babylon: %w", err)
	}

	app.wg.Add(1)
	go app.checkForUnbondingTxSignaturesOnBabylon(&stakingTxHash)

	return &stakingTxHash, resp.TxHash, nil
}

// handleSendStakeExpansionRequest handles a stake expansion delegation request
func (app *App) handleSendStakeExpansionRequest(
	stakerAddress btcutil.Address,
	stakingTime uint16,
	requiredDepthOnBtcChain uint32,
	fpBtcPks []*secp256k1.PublicKey,
	pop *cl.BabylonPop,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	prevActiveStkTxHash *chainhash.Hash,
	fundingTx *wire.MsgTx,
) (btcTxHash *chainhash.Hash, btcDelTxHash string, err error) {
	// check pop is not nil
	if pop == nil {
		return nil, btcDelTxHash, fmt.Errorf("cannot add transaction without proof of possession")
	}

	// just to pass to buildAndSendDelegation
	fakeStoredTx, err := stakerdb.CreateTrackedTransaction(
		stakingTx,
		stakerAddress,
	)
	if err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to create tracked transaction: %w", err)
	}

	stakingTxHash := stakingTx.TxHash()

	// Create expansion request with expansion-specific data
	req := newSendDelegationExpansionRequest(
		&stakingTxHash,
		requiredDepthOnBtcChain,
		fpBtcPks,
		pop,
		prevActiveStkTxHash,
		fundingTx,
	)

	// Use the same buildAndSendDelegation method - it already supports expansion via req.isExpansion
	resp, _, err := app.buildAndSendDelegation(
		req,
		stakerAddress,
		stakingOutputIdx,
		stakingTime,
		fakeStoredTx,
	)
	if err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to build and send stake expansion delegation: %w", err)
	}

	if err := app.txTracker.AddTransactionSentToBabylon(
		stakingTx,
		stakerAddress,
	); err != nil {
		return nil, btcDelTxHash, fmt.Errorf("failed to add transaction sent to babylon: %w", err)
	}

	app.wg.Add(1)
	go app.checkForUnbondingTxSignaturesOnBabylon(&stakingTxHash)

	return &stakingTxHash, resp.TxHash, nil
}

// handleStakingCmd handles a staking command (both regular and expansion)
func (app *App) handleStakingCmd(cmd *stakingRequestCmd) (*chainhash.Hash, error) {
	var stakingTx *wire.MsgTx
	var err error

	isStakeExpansion := cmd.prevActiveStkTxHash != nil
	if isStakeExpansion {
		// Create transaction with specific inputs (used for stake expansion)
		stakingTx, err = app.wc.CreateTransactionWithInputs(
			cmd.requiredInputs,
			[]*wire.TxOut{cmd.stakingOutput},
			btcutil.Amount(cmd.feeRate),
			cmd.stakerAddress,
			nil, // No additional inputs needed
		)
		if err != nil {
			return nil, fmt.Errorf("failed to build transaction with required inputs: %w", err)
		}

		// Send staking expansion transaction to Babylon node
		btcTxHash, _, err := app.handleSendStakeExpansionRequest(
			cmd.stakerAddress,
			cmd.stakingTime,
			cmd.requiredDepthOnBtcChain,
			cmd.fpBtcPks,
			cmd.pop,
			stakingTx,
			0,
			cmd.prevActiveStkTxHash,
			cmd.fundingTx,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to send stake expansion delegation request: %w", err)
		}

		return btcTxHash, nil
	}

	// Create regular staking transaction
	stakingTx, err = app.wc.CreateTransaction(
		[]*wire.TxOut{cmd.stakingOutput},
		btcutil.Amount(cmd.feeRate),
		cmd.stakerAddress,
		app.filterUtxoFnGen(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build staking transaction: %w", err)
	}

	// Send staking transaction to Babylon node
	btcTxHash, _, err := app.handleSendDelegationRequest(
		cmd.stakerAddress,
		cmd.stakingTime,
		cmd.requiredDepthOnBtcChain,
		cmd.fpBtcPks,
		cmd.pop,
		stakingTx,
		0,
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to send delegation request: %w", err)
	}

	return btcTxHash, nil
}

// handleStakingCommands handles staking commands
func (app *App) handleStakingCommands() {
	defer app.wg.Done()

	for {
		select {
		case cmd := <-app.stakingRequestedCmdChan:
			app.logStakingEventReceived(cmd)

			stakingTxHash, err := app.handleStakingCmd(cmd)
			if err != nil {
				utils.PushOrQuit(
					cmd.errChan,
					err,
					app.quit,
				)
			} else {
				utils.PushOrQuit(
					cmd.successChan,
					stakingTxHash,
					app.quit,
				)
			}
			app.logStakingEventProcessed(cmd)

		case cmd := <-app.migrateStakingCmd:
			stkTxHash := cmd.notifierTx.Tx.TxHash()

			btcCheckpointParams, err := app.babylonClient.BTCCheckpointParams()
			if err != nil {
				cmd.errChan <- err
				continue
			}

			bestBlockHeight := app.currentBestBlockHeight.Load()
			// check confirmation is deep enough
			if err := checkConfirmationDepth(bestBlockHeight, cmd.notifierTx.BlockHeight, btcCheckpointParams.ConfirmationTimeBlocks); err != nil {
				cmd.errChan <- err
				continue
			}

			_, btcDelTxHash, err := app.handleSendDelegationRequest(
				cmd.stakerAddr,
				cmd.parsedStakingTx.OpReturnData.StakingTime,
				btcCheckpointParams.ConfirmationTimeBlocks,
				[]*btcec.PublicKey{cmd.parsedStakingTx.OpReturnData.FinalityProviderPublicKey.PubKey},
				cmd.pop,
				cmd.notifierTx.Tx,
				uint32(cmd.parsedStakingTx.StakingOutputIdx),
				app.newBtcInclusionInfo(cmd.notifierTx),
			)
			if err != nil {
				utils.PushOrQuit(
					cmd.errChan,
					fmt.Errorf("sending tx to babylon failed: %w", err),
					app.quit,
				)
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stkTxHash,
				}).WithError(err).Error("BTC delegation transaction failed")
				return
			}

			utils.PushOrQuit(
				cmd.successChanTxHash,
				btcDelTxHash,
				app.quit,
			)
			app.logger.WithFields(logrus.Fields{
				"consumerBtcDelegationTxHash": btcDelTxHash,
			}).Debugf("Sending BTC delegation was a success")
		case <-app.quit:
			return
		}
	}
}

// main event loop for the staker app
func (app *App) handleStakingEvents() {
	defer app.wg.Done()

	for {
		select {
		case ev := <-app.unbondingTxSignaturesConfirmedOnBabylonEvChan:
			app.logStakingEventReceived(ev)
			storedTx, _ := app.mustGetTransactionAndStakerAddress(&ev.stakingTxHash)
			// if the delegation is not active here, it can only mean that statking
			// is going through pre-approval flow. Fire up task to send staking tx
			// to btc chain
			app.wg.Add(1)
			go app.activateVerifiedDelegation(
				storedTx.StakingTx,
				ev.stakingOutputIndex,
				&ev.stakingTxHash,
			)
			app.logStakingEventProcessed(ev)

		case ev := <-app.unbondingTxConfirmedOnBtcEvChan:
			app.logStakingEventReceived(ev)
			app.logStakingEventProcessed(ev)

		case ev := <-app.spendStakeTxConfirmedOnBtcEvChan:
			app.logStakingEventReceived(ev)
			if err := app.txTracker.DeleteTransactionSentToBabylon(&ev.stakingTxHash); err != nil {
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}
			app.logStakingEventProcessed(ev)

		case ev := <-app.delegationActivatedEvChan:
			app.logStakingEventReceived(ev)
			app.logStakingEventProcessed(ev)

		case ev := <-app.criticalErrorEvChan:
			// if error is context.Canceled, it means one of started child go-routines
			// received quit signal and is shutting down. We just ignore it.
			if errors.Is(ev.err, context.Canceled) {
				continue
			}
			app.m.NumberOfFatalErrors.Inc()

			// if app is configured to fail on critical error, just kill it, user then
			// can investigate and restart it, and delegation process should continue
			// from correct state
			if app.config.StakerConfig.ExitOnCriticalError {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": ev.stakingTxHash,
					"err":           ev.err,
					"info":          ev.additionalContext,
				}).Fatalf("Critical error received. Exiting...")
			}
			app.logStakingEventReceived(ev)

			// TODO for now we just log it and continue, another options would be to
			// save error info to db, and additional api to restart delegation/undelegation
			// procsess from latest state
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash": ev.stakingTxHash,
				"err":           ev.err,
				"info":          ev.additionalContext,
			}).Error("Critical error received")
			app.logStakingEventProcessed(ev)

		case <-app.quit:
			return
		}
	}
}

// Wallet returns the wallet controller
func (app *App) Wallet() walletcontroller.WalletController {
	return app.wc
}

// BabylonController returns the babylon controller
func (app *App) BabylonController() cl.BabylonClient {
	return app.babylonClient
}

// filterUtxoFnGen returns a walletcontroller.UseUtxoFn that can be used to filter
func (app *App) filterUtxoFnGen() walletcontroller.UseUtxoFn {
	return func(utxo walletcontroller.Utxo) bool {
		outpoint := utxo.OutPoint

		used, err := app.txTracker.OutpointUsed(&outpoint)

		if err != nil {
			return false
		}

		return !used
	}
}

// StakeFunds stakes funds to the staker address
func (app *App) StakeFunds(
	stakerAddress btcutil.Address,
	stakingAmount btcutil.Amount,
	fpPks []*btcec.PublicKey,
	stakingTimeBlocks uint16,
) (*chainhash.Hash, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	if len(fpPks) == 0 {
		return nil, fmt.Errorf("no finality providers public keys provided")
	}

	if haveDuplicates(fpPks) {
		return nil, fmt.Errorf("duplicate finality provider public keys provided")
	}

	for _, fpPk := range fpPks {
		if err := app.finalityProviderExists(fpPk); err != nil {
			return nil, fmt.Errorf("error checking if finality provider exists on babylon chain: %w", err)
		}
	}

	params, err := app.babylonClient.Params()
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	// Allow list is enabled, check if we are past the expiration height and we can
	// create new delegations
	if params.AllowListExpirationHeight > 0 {
		latestBlockHeight, err := app.babylonClient.GetLatestBlockHeight()

		if err != nil {
			return nil, fmt.Errorf("failed to get latest block height: %w", err)
		}
		// we add +1 to account for comet bft lazy execution
		if latestBlockHeight <= params.AllowListExpirationHeight+1 {
			return nil, fmt.Errorf("allow is enabled, cannot create new delegations. Latest block height %d is before allow list expiration height %d",
				latestBlockHeight, params.AllowListExpirationHeight)
		}
	}

	slashingFee := app.getSlashingFee(params.MinSlashingTxFeeSat)

	if stakingAmount <= slashingFee {
		return nil, fmt.Errorf("staking amount %d is less than minimum slashing fee %d",
			stakingAmount, slashingFee)
	}
	if stakingTimeBlocks < params.MinStakingTime || stakingTimeBlocks > params.MaxStakingTime {
		return nil, fmt.Errorf("staking time %d is not in range [%d, %d]",
			stakingTimeBlocks, params.MinStakingTime, params.MaxStakingTime)
	}

	if stakingAmount < params.MinStakingValue || stakingAmount > params.MaxStakingValue {
		return nil, fmt.Errorf("staking amount %d is not in range [%d, %d]",
			stakingAmount, params.MinStakingValue, params.MaxStakingValue)
	}

	pop, err := app.unlockAndCreatePop(stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock and create pop: %w", err)
	}

	// build proof of possession, no point moving forward if staker do not have all
	// the necessary keys
	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get staker public key: %w", err)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		fpPks,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build staking info: %w", err)
	}

	feeRate := app.feeEstimator.EstimateFeePerKb()

	app.logger.WithFields(logrus.Fields{
		"stakerAddress": stakerAddress,
		"stakingAmount": stakingInfo.StakingOutput,
		"fee":           feeRate,
	}).Info("Created and signed staking transaction")

	req := newOwnedStakingCommand(
		stakerAddress,
		stakingInfo.StakingOutput,
		feeRate,
		stakingTimeBlocks,
		stakingAmount,
		fpPks,
		params.ConfirmationTimeBlocks,
		pop,
	)

	utils.PushOrQuit[*stakingRequestCmd](
		app.stakingRequestedCmdChan,
		req,
		app.quit,
	)

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddress,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return nil, reqErr
	case hash := <-req.successChan:
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}

// StakeExpand expands an existing stake by consuming the previous staking UTXO
// and creating a new larger staking transaction with additional funding
func (app *App) StakeExpand(
	stakerAddress btcutil.Address,
	stakingAmount btcutil.Amount,
	fpPks []*btcec.PublicKey,
	stakingTimeBlocks uint16,
	prevActiveStkTxHash *chainhash.Hash,
) (*chainhash.Hash, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	if len(fpPks) == 0 {
		return nil, fmt.Errorf("no finality providers public keys provided")
	}

	if haveDuplicates(fpPks) {
		return nil, fmt.Errorf("duplicate finality provider public keys provided")
	}

	for _, fpPk := range fpPks {
		if err := app.finalityProviderExists(fpPk); err != nil {
			return nil, fmt.Errorf("error checking if finality provider exists on babylon chain: %w", err)
		}
	}

	params, err := app.babylonClient.Params()
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	// Allow list is enabled, check if we are past the expiration height and we can
	// create new delegations
	if params.AllowListExpirationHeight > 0 {
		latestBlockHeight, err := app.babylonClient.GetLatestBlockHeight()

		if err != nil {
			return nil, fmt.Errorf("failed to get latest block height: %w", err)
		}
		// we add +1 to account for comet bft lazy execution
		if latestBlockHeight <= params.AllowListExpirationHeight+1 {
			return nil, fmt.Errorf("allow is enabled, cannot create new delegations. Latest block height %d is before allow list expiration height %d",
				latestBlockHeight, params.AllowListExpirationHeight)
		}
	}

	slashingFee := app.getSlashingFee(params.MinSlashingTxFeeSat)

	if stakingAmount <= slashingFee {
		return nil, fmt.Errorf("staking amount %d is less than minimum slashing fee %d",
			stakingAmount, slashingFee)
	}
	if stakingTimeBlocks < params.MinStakingTime || stakingTimeBlocks > params.MaxStakingTime {
		return nil, fmt.Errorf("staking time %d is not in range [%d, %d]",
			stakingTimeBlocks, params.MinStakingTime, params.MaxStakingTime)
	}

	if stakingAmount < params.MinStakingValue || stakingAmount > params.MaxStakingValue {
		return nil, fmt.Errorf("staking amount %d is not in range [%d, %d]",
			stakingAmount, params.MinStakingValue, params.MaxStakingValue)
	}

	pop, err := app.unlockAndCreatePop(stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock and create pop: %w", err)
	}

	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get staker public key: %w", err)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		fpPks,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build staking info: %w", err)
	}

	feeRate := app.feeEstimator.EstimateFeePerKb()

	// Step 1: Create funding transaction with additional funds
	// This provides the extra amount needed to expand the stake
	fundingTx, err := app.wc.CreateTransaction(
		[]*wire.TxOut{stakingInfo.StakingOutput}, // Create output with full new staking amount
		btcutil.Amount(feeRate),
		stakerAddress,
		app.filterUtxoFnGen(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create funding transaction: %w", err)
	}

	// Prepare required inputs for staking transaction
	fundingTxHash := fundingTx.TxHash()
	requiredInputs := []wire.OutPoint{
		{Hash: *prevActiveStkTxHash, Index: 0}, // Previous stake
		{Hash: fundingTxHash, Index: 0},        // Funding
	}

	app.logger.WithFields(logrus.Fields{
		"stakerAddress":  stakerAddress,
		"stakingAmount":  stakingAmount,
		"fee":            feeRate,
		"prevStakingTx":  prevActiveStkTxHash,
		"fundingTxHash":  fundingTxHash,
		"requiredInputs": len(requiredInputs),
	}).Info("Created funding transaction for stake expansion")

	// Create expansion command using regular staking command with required inputs
	req := newOwnedStakingCommand(
		stakerAddress,
		stakingInfo.StakingOutput,
		feeRate,
		stakingTimeBlocks,
		stakingAmount,
		fpPks,
		params.ConfirmationTimeBlocks,
		pop,
	)

	// Set expansion-specific fields
	req.requiredInputs = requiredInputs
	req.prevActiveStkTxHash = prevActiveStkTxHash
	req.fundingTx = fundingTx

	utils.PushOrQuit[*stakingRequestCmd](
		app.stakingRequestedCmdChan,
		req,
		app.quit,
	)

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddress,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return nil, reqErr
	case hash := <-req.successChan:
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}

// StoredTransactions returns a slice of stakerdb.StoredTransaction
// that are stored in the tx tracker
func (app *App) StoredTransactions(limit, offset uint64) (*stakerdb.StoredTransactionQueryResult, error) {
	query := stakerdb.StoredTransactionQuery{
		IndexOffset:        offset,
		NumMaxTransactions: limit,
		Reversed:           false,
	}
	resp, err := app.txTracker.QueryStoredTransactions(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored transactions: %w", err)
	}

	return &resp, nil
}

// WithdrawableTransactions returns a slice of stakerdb.StoredTransaction
// that can be withdrawn
func (app *App) WithdrawableTransactions(limit, offset uint64) (*stakerdb.StoredTransactionQueryResult, error) {
	transactions, err := app.StoredTransactions(limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query stored transactions: %w", err)
	}

	withdrawableTransactions := make([]stakerdb.StoredTransaction, 0)

	for _, tx := range transactions.Transactions {
		stakingTxHash := tx.StakingTx.TxHash()
		di, err := app.babylonClient.QueryBTCDelegation(&stakingTxHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get delegation info: %w", err)
		}

		babylonStatus := di.BtcDelegation.GetStatusDesc()
		stakingConfirmation, _, err := app.Wallet().TxDetails(
			&stakingTxHash,
			tx.StakingTx.TxOut[di.BtcDelegation.StakingOutputIdx].PkScript,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to get staking tx details: %w", err)
		}

		var scriptTimeLock uint16
		var confirmationHeight uint32

		switch babylonStatus {
		case BabylonPendingStatus, BabylonVerifiedStatus:
			continue
		case BabylonExpiredStatus:
			withdrawableTransactions = append(withdrawableTransactions, tx)
			continue
		default:
			udi, err := app.babylonClient.GetUndelegationInfo(di)
			if err != nil {
				return nil, fmt.Errorf("failed to get undelegation info: %w", err)
			}

			unbondingTxHash := udi.UnbondingTransaction.TxHash()
			unbondingConfirmation, unbondingStatus, err := app.Wallet().TxDetails(
				&unbondingTxHash,
				udi.UnbondingTransaction.TxOut[0].PkScript,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to get unbonding tx details: %w", err)
			}

			switch {
			case unbondingStatus == walletcontroller.TxNotFound, unbondingConfirmation.BlockHash == nil || unbondingConfirmation.BlockHeight == 0:
				// unbonding transaction is not found
				scriptTimeLock = uint16(di.BtcDelegation.StakingTime)
				confirmationHeight = stakingConfirmation.BlockHeight
			default:
				// unbonding transaction is confirmed
				scriptTimeLock = udi.UnbondingTime
				confirmationHeight = unbondingConfirmation.BlockHeight
			}
		}

		isTimeLockExpired := func(confirmationBlockHeight uint32, lockTime uint16, currentBestBlockHeight uint32) bool {
			// transaction maybe included/executed only in next possible block
			nexBlockHeight := int64(currentBestBlockHeight) + 1
			pastLock := nexBlockHeight - int64(confirmationBlockHeight) - int64(lockTime)
			return pastLock >= 0
		}(confirmationHeight, scriptTimeLock, app.currentBestBlockHeight.Load())

		if isTimeLockExpired {
			withdrawableTransactions = append(withdrawableTransactions, tx)
		}
	}

	return &stakerdb.StoredTransactionQueryResult{
		Transactions: withdrawableTransactions,
		Total:        uint64(len(transactions.Transactions)),
	}, nil
}

// GetStoredTransaction returns a stakerdb.StoredTransaction
// that is stored in the tx tracker
func (app *App) GetStoredTransaction(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, error) {
	return app.txTracker.GetTransaction(txHash)
}

// ListUnspentOutputs returns a slice of walletcontroller.Utxo
func (app *App) ListUnspentOutputs() ([]walletcontroller.Utxo, error) {
	return app.wc.ListOutputs(false)
}

// waitForSpendConfirmation waits for the staking transaction to be confirmed
func (app *App) waitForSpendConfirmation(stakingTxHash chainhash.Hash, ev *notifier.ConfirmationEvent) {
	// check we are not shutting down
	select {
	case <-app.quit:
		ev.Cancel()
		return

	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutWaitingForSpendConfirmation)
	defer cancel()
	for {
		select {
		case <-ev.Confirmed:
			stakingEvent := &spendStakeTxConfirmedOnBtcEvent{
				stakingTxHash,
			}

			// transaction which spends staking transaction is confirmed on BTC inform
			// main loop about it
			utils.PushOrQuit[*spendStakeTxConfirmedOnBtcEvent](
				app.spendStakeTxConfirmedOnBtcEvChan,
				stakingEvent,
				app.quit,
			)

			ev.Cancel()
			return
		case <-ctx.Done():
			// we timed out waiting for confirmation, transaction is stuck in mempool
			return

		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		}
	}
}

// signTaprootScriptSpendUsingWallet signs a taproot script spend using the wallet
func (app *App) signTaprootScriptSpendUsingWallet(
	txToSign *wire.MsgTx,
	fundingOutput *wire.TxOut,
	signerAddress btcutil.Address,
	leaf *txscript.TapLeaf,
	controlBlock *txscript.ControlBlock,
) (*walletcontroller.TaprootSigningResult, error) {
	if err := app.wc.UnlockWallet(defaultWalletUnlockTimeout); err != nil {
		return nil, fmt.Errorf("failed to unlock wallet before signing: %w", err)
	}

	req := &walletcontroller.TaprootSigningRequest{
		FundingOutput: fundingOutput,
		TxToSign:      txToSign,
		SignerAddress: signerAddress,
		SpendDescription: &walletcontroller.SpendPathDescription{
			ScriptLeaf:   leaf,
			ControlBlock: controlBlock,
		},
	}

	resp, err := app.wc.SignOneInputTaprootSpendingTransaction(req)

	if err != nil {
		return nil, fmt.Errorf("failed to sign taproot spending transaction: %w", err)
	}

	return resp, nil
}

// SpendStake spends stake identified by stakingTxHash. Stake can be currently locked in
// two types of outputs:
// 1. Staking output - this is output which is created by staking transaction
// 2. Unbonding output - this is output which is created by unbonding transaction, if user requested
// unbonding of his stake.
// We find in which type of output stake is locked by checking state of staking transaction, and build
// proper spend transaction based on that state.
func (app *App) SpendStake(stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil, nil

	default:
	}

	tx, err := app.txTracker.GetTransaction(stakingTxHash)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting staking transaction: %w", err)
	}

	// this coud happen if we stared staker on wrong network.
	// TODO: consider storing data for different networks in different folders
	// to avoid this
	// Currently we spend funds from staking transaction to the same address. This
	// could be improved by allowing user to specify destination address, although
	// this destination address would need to control the expcted priv key to sign
	// transaction
	destAddress, err := btcutil.DecodeAddress(tx.StakerAddress, app.network)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error decoding staker address: %w", err)
	}

	destAddressScript, err := txscript.PayToAddrScript(destAddress)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Cannot built destination script: %w", err)
	}

	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting params: %w", err)
	}

	pubKey, err := app.wc.AddressPublicKey(destAddress)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting private key: %w", err)
	}

	currentFeeRate := app.feeEstimator.EstimateFeePerKb()

	di, err := app.babylonClient.QueryBTCDelegation(stakingTxHash)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting delegation info: %w", err)
	}

	udi, err := app.babylonClient.GetUndelegationInfo(di)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting undelegation info: %w", err)
	}

	fpBtcPubkeys, err := convertFpBtcPkToBtcPk(di.BtcDelegation.FpBtcPkList)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error converting fpBtcPkList to btcPkList: %w", err)
	}

	// Since we have already verified that the transaction is ACTIVE
	// on the Babylon chain, we can now be certain that it has been confirmed in Bitcoin.
	// Therefore, we only need to check whether the unbonding transaction has been confirmed.
	unbondingTxHash := udi.UnbondingTransaction.TxHash()
	confirmation, txStatus, err := app.Wallet().TxDetails(
		&unbondingTxHash,
		udi.UnbondingTransaction.TxOut[0].PkScript,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting confirmation info from btc: %w", err)
	}

	if confirmation == nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Tx status: %s", txStatus.String())
	}

	var spendStakeTxInfo *spendStakeTxInfo
	if confirmation.BlockHash != nil && confirmation.BlockHeight > 0 {
		unbondingConfirmedTxInfo, err := createSpendStakeTxUnbondingConfirmed(
			pubKey,
			fpBtcPubkeys,
			params.CovenantPks,
			params.CovenantQuruomThreshold,
			destAddressScript,
			currentFeeRate,
			udi,
			app.network,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot spend staking output. Error creating spend stake unbonding confirmed tx: %w", err)
		}
		spendStakeTxInfo = unbondingConfirmedTxInfo
	} else {
		unbondingNotConfirmedTxInfo, err := createSpendStakeTxUnbondingNotConfirmed(
			pubKey,
			di.BtcDelegation.StakingOutputIdx,
			uint16(di.BtcDelegation.StakingTime),
			fpBtcPubkeys,
			params.CovenantPks,
			params.CovenantQuruomThreshold,
			tx,
			destAddressScript,
			currentFeeRate,
			app.network,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot spend staking output. Error creating spend stake unbonding confirmed tx: %w", err)
		}
		spendStakeTxInfo = unbondingNotConfirmedTxInfo
	}

	stakerSig, err := app.signTaprootScriptSpendUsingWallet(
		spendStakeTxInfo.spendStakeTx,
		spendStakeTxInfo.fundingOutput,
		destAddress,
		&spendStakeTxInfo.fundingOutputSpendInfo.RevealedLeaf,
		&spendStakeTxInfo.fundingOutputSpendInfo.ControlBlock,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error building signature: %w", err)
	}

	if stakerSig.FullInputWitness == nil {
		return nil, nil, fmt.Errorf("failed to recevie full witness to spend staking transactions")
	}

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error building witness: %w", err)
	}

	spendStakeTxInfo.spendStakeTx.TxIn[0].Witness = stakerSig.FullInputWitness

	// We do not check if transaction is spendable i.e the staking time has passed
	// as this is validated in mempool so in of not meeting this time requirement
	// we will receive error here: `transaction's sequence locks on inputs not met`
	spendTxHash, err := app.wc.SendRawTransaction(spendStakeTxInfo.spendStakeTx, true)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error sending tx: %w", err)
	}

	spendTxValue := btcutil.Amount(spendStakeTxInfo.spendStakeTx.TxOut[0].Value)

	app.logger.WithFields(logrus.Fields{
		"stakeValue":    btcutil.Amount(spendStakeTxInfo.fundingOutput.Value),
		"spendTxHash":   spendTxHash,
		"spendTxValue":  spendTxValue,
		"fee":           spendStakeTxInfo.calculatedFee,
		"stakerAddress": destAddress,
		"destAddress":   destAddress,
	}).Infof("Successfully sent transaction spending staking output")

	confEvent, err := app.notifier.RegisterConfirmationsNtfn(
		spendTxHash,
		spendStakeTxInfo.spendStakeTx.TxOut[0].PkScript,
		SpendStakeTxConfirmations,
		app.currentBestBlockHeight.Load(),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("spend tx sent. Error registering confirmation notifcation: %w", err)
	}

	// We are gonna mark our staking transaction as spent on BTC network, only when
	// we receive enough confirmations on btc network. This means that btc staker can send another
	// tx which will spend this staking output concurrently. In that case the first one
	// confirmed on btc networks which will mark our staking transaction as spent on BTC network.
	// TODO: we can reconsider this approach in the future.
	go app.waitForSpendConfirmation(*stakingTxHash, confEvent)

	return spendTxHash, &spendTxValue, nil
}

func (app *App) ListActiveFinalityProviders(limit uint64, offset uint64) (*cl.FinalityProvidersClientResponse, error) {
	return app.babylonClient.QueryFinalityProviders(limit, offset)
}

// UnbondStaking initiates whole unbonding process. Whole process looks like this:
// 1. Unbonding data is build based on exsitng staking transaction data
// 2. Unbonding data is sent to babylon as part of undelegete request
// 3. If request is successful, unbonding transaction is registred in db and
// staking transaction is marked as unbonded
// 4. Staker program starts watching for unbodning transactions signatures from
// covenant and finality provider
// 5. After gathering all signatures, unbonding transaction is sent to bitcoin
// This function returns control to the caller after step 3. Later is up to the caller
// to check what is state of unbonding transaction
func (app *App) UnbondStaking(
	stakingTxHash chainhash.Hash) (*chainhash.Hash, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	// Check staking tx is managed by staker program
	tx, err := app.txTracker.GetTransaction(&stakingTxHash)
	if err != nil {
		return nil, fmt.Errorf("cannont unbond: %w", err)
	}

	di, err := app.babylonClient.QueryBTCDelegation(&stakingTxHash)
	if err != nil {
		return nil, fmt.Errorf("error getting delegation info: %w", err)
	}

	if !di.BtcDelegation.Active {
		return nil, fmt.Errorf("cannot unbond transaction which is not active")
	}

	stakerAddress, err := btcutil.DecodeAddress(tx.StakerAddress, app.network)
	if err != nil {
		return nil, fmt.Errorf("error decoding staker address: %s. Err: %w", tx.StakerAddress, err)
	}

	fpBtcPubkeys, err := convertFpBtcPkToBtcPk(di.BtcDelegation.FpBtcPkList)
	if err != nil {
		return nil, fmt.Errorf("error converting fpBtcPkList to btcPkList: %w", err)
	}

	undelegationInfo, err := app.babylonClient.GetUndelegationInfo(di)
	if err != nil {
		return nil, fmt.Errorf("failed to get undelegation info from babylon: %w", err)
	}

	// TODO: Move this to event handler to avoid somebody starting multiple unbonding routines
	app.wg.Add(1)
	go app.sendUnbondingTxToBtcTask(
		&stakingTxHash,
		stakerAddress,
		di.BtcDelegation.StakingOutputIdx,
		uint16(di.BtcDelegation.StakingTime),
		tx,
		fpBtcPubkeys,
		undelegationInfo,
	)

	unbondingTxHash := undelegationInfo.UnbondingTransaction.TxHash()
	return &unbondingTxHash, nil
}

// unlockAndCreatePop creates pop and locks wallet
func (app *App) unlockAndCreatePop(stakerAddress btcutil.Address) (*cl.BabylonPop, error) {
	// unlock wallet for the rest of the operations
	// TODO consider unlock/lock with defer
	err := app.wc.UnlockWallet(defaultWalletUnlockTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock wallet: %w", err)
	}

	msgToSign := []byte(app.babylonClient.GetKeyAddress().String())
	// pop only works for native segwit address and taproot bip86 addresses
	sig, err := app.wc.SignBip322Signature(msgToSign, stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to sign bip322 signature: %w", err)
	}

	return cl.NewBabylonBip322Pop(
		msgToSign,
		sig,
		stakerAddress,
	)
}

// BtcTxAndBlock retrieves a transaction and its block
func (app *App) BtcTxAndBlock(txHash *chainhash.Hash) (*btcjson.TxRawResult, *btcjson.GetBlockHeaderVerboseResult, error) {
	tx, err := app.wc.TxVerbose(txHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get transaction verbose: %w", err)
	}

	blockHash, err := chainhash.NewHashFromStr(tx.BlockHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse block hash: %w", err)
	}

	blk, err := app.wc.BlockHeaderVerbose(blockHash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block header verbose: %w", err)
	}

	return tx, blk, nil
}

// checkConfirmationDepth checks if the confirmation depth is enough
func checkConfirmationDepth(tipBlockHeight, txInclusionBlockHeight, confirmationTimeBlocks uint32) error {
	if txInclusionBlockHeight >= tipBlockHeight {
		return fmt.Errorf("inclusion block height: %d should be lower than current tip: %d", txInclusionBlockHeight, tipBlockHeight)
	}
	if (tipBlockHeight - txInclusionBlockHeight) < confirmationTimeBlocks {
		return fmt.Errorf(
			"BTC tx not deep enough, current tip: %d, tx inclusion height: %d, confirmations needed: %d",
			tipBlockHeight, txInclusionBlockHeight, confirmationTimeBlocks,
		)
	}
	return nil
}

// GetTxTracker returns the tx tracker
func (app *App) GetTxTracker() *stakerdb.TrackedTransactionStore {
	return app.txTracker
}
