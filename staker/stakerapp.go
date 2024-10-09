package staker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go/v4"
	staking "github.com/babylonlabs-io/babylon/btcstaking"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/metrics"
	"github.com/babylonlabs-io/btc-staker/proto"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	pv "github.com/cosmos/relayer/v2/relayer/provider"
	"go.uber.org/zap"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/cometbft/cometbft/crypto/tmhash"
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

type stakingDbInfo struct {
	stakingTxHash  *chainhash.Hash
	stakingTxState proto.TransactionState
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

func (app *StakerApp) onLongRetryFunc(stakingTxHash *chainhash.Hash, msg string) retry.OnRetryFunc {
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

	// Set minimum fee to 1 sat/byte, as in standard rules policy
	MinFeePerKb = txrules.DefaultRelayFeePerKb

	// If we fail to send unbonding tx to btc for any reason we will retry in this time
	unbondingSendRetryTimeout = 1 * time.Minute

	// after this many confirmations we treat unbonding transaction as confirmed on btc
	// TODO: needs to consolidate what is safe confirmation for different types of transaction
	// as currently we have different values for different types of transactions
	UnbondingTxConfirmations = 6
)

type StakerApp struct {
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

	stakingRequestedEvChan                        chan *stakingRequestedEvent
	sendStakingTxToBTCRequestedEvChan             chan *sendStakingTxToBTCRequestedEvent
	stakingTxBtcConfirmedEvChan                   chan *stakingTxBtcConfirmedEvent
	delegationSubmittedToBabylonEvChan            chan *delegationSubmittedToBabylonEvent
	unbondingTxSignaturesConfirmedOnBabylonEvChan chan *unbondingTxSignaturesConfirmedOnBabylonEvent
	unbondingTxConfirmedOnBtcEvChan               chan *unbondingTxConfirmedOnBtcEvent
	spendStakeTxConfirmedOnBtcEvChan              chan *spendStakeTxConfirmedOnBtcEvent
	criticalErrorEvChan                           chan *criticalErrorEvent
	currentBestBlockHeight                        atomic.Uint32
}

func NewStakerAppFromConfig(
	config *scfg.Config,
	logger *logrus.Logger,
	rpcClientLogger *zap.Logger,
	db kvdb.Backend,
	m *metrics.StakerMetrics,
) (*StakerApp, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, err
	}

	tracker, err := stakerdb.NewTrackedTransactionStore(db)

	if err != nil {
		return nil, err
	}

	babylonClient, err := cl.NewBabylonController(config.BabylonConfig, &config.ActiveNetParams, logger, rpcClientLogger)

	if err != nil {
		return nil, err
	}

	hintCache, err := channeldb.NewHeightHintCache(
		channeldb.CacheConfig{
			// TODO: Investigate this option. Lighting docs mention that this is necessary for some edge case
			QueryDisable: false,
		}, db,
	)

	if err != nil {
		return nil, fmt.Errorf("unable to create height hint cache: %v", err)
	}

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams, hintCache)

	if err != nil {
		return nil, err
	}

	var feeEstimator FeeEstimator
	switch config.BtcNodeBackendConfig.EstimationMode {
	case types.StaticFeeEstimation:
		feeEstimator = NewStaticBtcFeeEstimator(chainfee.SatPerKVByte(config.BtcNodeBackendConfig.MaxFeeRate * 1000))
	case types.DynamicFeeEstimation:
		feeEstimator, err = NewDynamicBtcFeeEstimator(config.BtcNodeBackendConfig, &config.ActiveNetParams, logger)
		if err != nil {
			return nil, err
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
) (*StakerApp, error) {
	return &StakerApp{
		babylonClient:          cl,
		wc:                     walletClient,
		notifier:               nodeNotifier,
		feeEstimator:           feeEestimator,
		network:                &config.ActiveNetParams,
		txTracker:              tracker,
		babylonMsgSender:       babylonMsgSender,
		m:                      metrics,
		config:                 config,
		logger:                 logger,
		quit:                   make(chan struct{}),
		stakingRequestedEvChan: make(chan *stakingRequestedEvent),

		sendStakingTxToBTCRequestedEvChan: make(chan *sendStakingTxToBTCRequestedEvent),

		// event for when transaction is confirmed on BTC
		stakingTxBtcConfirmedEvChan: make(chan *stakingTxBtcConfirmedEvent),

		// event for when delegation is sent to babylon and included in babylon
		delegationSubmittedToBabylonEvChan: make(chan *delegationSubmittedToBabylonEvent),

		// event emitted upon transaction which spends staking transaction is confirmed on BTC
		spendStakeTxConfirmedOnBtcEvChan: make(chan *spendStakeTxConfirmedOnBtcEvent),

		// channel which receives unbonding signatures from covenant for unbonding
		// transaction
		unbondingTxSignaturesConfirmedOnBabylonEvChan: make(chan *unbondingTxSignaturesConfirmedOnBabylonEvent),

		// channel which receives confirmation that unbonding transaction was confirmed on BTC
		unbondingTxConfirmedOnBtcEvChan: make(chan *unbondingTxConfirmedOnBtcEvent),

		// channel which receives critical errors, critical errors are errors which we do not know
		// how to handle, so we just log them. It is up to user to investigate, what had happend
		// and report the situation
		criticalErrorEvChan: make(chan *criticalErrorEvent),
	}, nil
}

func (app *StakerApp) Start() error {
	var startErr error
	app.startOnce.Do(func() {
		app.logger.Infof("Starting StakerApp")

		// TODO: This can take a long time as it connects to node. Maybe make it cancellable?
		// although staker without node is not very useful

		app.logger.Infof("Connecting to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)
		err := app.notifier.Start()
		if err != nil {
			startErr = err
			return
		}

		app.logger.Infof("Successfully connected to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)

		blockEventNotifier, err := app.notifier.RegisterBlockEpochNtfn(nil)

		if err != nil {
			startErr = err
			return
		}

		err = app.feeEstimator.Start()

		if err != nil {
			startErr = err
			return
		}

		// we registered for notifications with `nil`  so we should receive best block
		// immeadiatly
		select {
		case block := <-blockEventNotifier.Epochs:
			app.currentBestBlockHeight.Store(uint32(block.Height))
		case <-app.quit:
			startErr = errors.New("staker app quit before finishing start")
			return
		}

		app.logger.Infof("Initial btc best block height is: %d", app.currentBestBlockHeight.Load())

		app.babylonMsgSender.Start()

		app.wg.Add(2)
		go app.handleNewBlocks(blockEventNotifier)
		go app.handleStakingEvents()

		if err := app.checkTransactionsStatus(); err != nil {
			startErr = err
			return
		}
	})

	return startErr
}

func (app *StakerApp) handleNewBlocks(blockNotifier *notifier.BlockEpochEvent) {
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

func (app *StakerApp) Stop() error {
	var stopErr error
	app.stopOnce.Do(func() {
		app.logger.Infof("Stopping StakerApp")
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

func (app *StakerApp) reportCriticialError(
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

func (app *StakerApp) waitForStakingTransactionConfirmation(
	stakingTxHash *chainhash.Hash,
	stakingTxPkScript []byte,
	requiredBlockDepth uint32,
	currentBestBlockHeight uint32,
) error {
	app.logger.WithFields(logrus.Fields{
		"stakingTxHash": stakingTxHash.String(),
	}).Debug("Register waiting for tx confirmation")

	confEvent, err := app.notifier.RegisterConfirmationsNtfn(
		stakingTxHash,
		stakingTxPkScript,
		requiredBlockDepth+1,
		currentBestBlockHeight,
		notifier.WithIncludeBlock(),
	)
	if err != nil {
		return err
	}

	go app.waitForStakingTxConfirmation(*stakingTxHash, requiredBlockDepth, confEvent)
	return nil
}

func (app *StakerApp) handleBtcTxInfo(
	stakingTxHash *chainhash.Hash,
	txInfo *stakerdb.StoredTransaction,
	params *cl.StakingParams,
	currentBestBlockHeight uint32,
	txStatus walletcontroller.TxStatus,
	btcTxInfo *notifier.TxConfirmation) error {

	switch txStatus {
	case walletcontroller.TxNotFound:
		// Most probable reason this happened is transaction was included in btc chain (removed from mempool)
		// and wallet also lost data and is not synced far enough to see transaction.
		// Log it as error so that user can investigate.
		// TODO: Set tx to some new state, like `Unknown` and periodically check if it is in mempool or chain ?
		app.logger.WithFields(logrus.Fields{
			"btcTxHash": stakingTxHash,
		}).Error("Transaction from database not found in BTC mempool or chain")
	case walletcontroller.TxInMemPool:
		app.logger.WithFields(logrus.Fields{
			"btcTxHash": stakingTxHash,
		}).Debug("Transaction found in mempool. Stat waiting for confirmation")

		if err := app.waitForStakingTransactionConfirmation(
			stakingTxHash,
			txInfo.StakingTx.TxOut[txInfo.StakingOutputIndex].PkScript,
			params.ConfirmationTimeBlocks,
			currentBestBlockHeight,
		); err != nil {
			return err
		}

	case walletcontroller.TxInChain:
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":              stakingTxHash,
			"btcBlockHeight":         btcTxInfo.BlockHeight,
			"currentBestBlockHeight": currentBestBlockHeight,
		}).Debug("Transaction found in chain")

		if currentBestBlockHeight < btcTxInfo.BlockHeight {
			// This is wierd case, we retrieved transaction from btc wallet, even though wallet best height
			// is lower than block height of transaction.
			// Log it as error so that user can investigate.
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Error("Current best block height is lower than block height of transaction")

			return nil
		}

		blockDepth := currentBestBlockHeight - btcTxInfo.BlockHeight

		if blockDepth >= params.ConfirmationTimeBlocks {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Debug("Transaction deep enough in btc chain to be sent to Babylon")

			// block is deep enough to init sent to babylon
			ev := &stakingTxBtcConfirmedEvent{
				stakingTxHash: *stakingTxHash,
				txIndex:       btcTxInfo.TxIndex,
				blockDepth:    params.ConfirmationTimeBlocks,
				blockHash:     *btcTxInfo.BlockHash,
				blockHeight:   btcTxInfo.BlockHeight,
				tx:            txInfo.StakingTx,
				inlusionBlock: btcTxInfo.Block,
			}

			utils.PushOrQuit[*stakingTxBtcConfirmedEvent](
				app.stakingTxBtcConfirmedEvChan,
				ev,
				app.quit,
			)

		} else {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Debug("Transaction not deep enough in btc chain to be sent to Babylon. Waiting for confirmation")

			if err := app.waitForStakingTransactionConfirmation(
				stakingTxHash,
				txInfo.StakingTx.TxOut[txInfo.StakingOutputIndex].PkScript,
				params.ConfirmationTimeBlocks,
				currentBestBlockHeight,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (app *StakerApp) mustSetTxSpentOnBtc(hash *chainhash.Hash) {
	if err := app.txTracker.SetTxSpentOnBtc(hash); err != nil {
		app.logger.Fatalf("Error setting transaction spent on btc: %s", err)
	}
}

// TODO: We should also handle case when btc node or babylon node lost data and start from scratch
// i.e keep track what is last known block height on both chains and detect if after restart
// for some reason they are behind staker
// TODO: Refactor this functions after adding unit tests to stakerapp
func (app *StakerApp) checkTransactionsStatus() error {
	stakingParams, err := app.babylonClient.Params()

	if err != nil {
		return err
	}

	// Keep track of all staking transactions which need checking. chainhash.Hash objects are not relativly small
	// so it should not OOM even for larage database
	var transactionsSentToBtc []*chainhash.Hash
	var transactionConfirmedOnBtc []*chainhash.Hash
	var transactionsOnBabylon []*stakingDbInfo

	reset := func() {
		transactionsSentToBtc = make([]*chainhash.Hash, 0)
		transactionConfirmedOnBtc = make([]*chainhash.Hash, 0)
		transactionsOnBabylon = make([]*stakingDbInfo, 0)
	}

	// In our scan we only record transactions which state need to be checked, as`ScanTrackedTransactions`
	// is long running read transaction, it could dead lock with write transactions which we would need
	// to use to update transaction state.
	err = app.txTracker.ScanTrackedTransactions(func(tx *stakerdb.StoredTransaction) error {
		// TODO : We need to have another stare like UnstakeTransaction sent and store
		// info about transaction sent (hash) to check wheter it was confirmed after staker
		// restarts
		stakingTxHash := tx.StakingTx.TxHash()
		switch tx.State {
		case proto.TransactionState_SENT_TO_BTC:
			transactionsSentToBtc = append(transactionsSentToBtc, &stakingTxHash)
			return nil
		case proto.TransactionState_CONFIRMED_ON_BTC:
			transactionConfirmedOnBtc = append(transactionConfirmedOnBtc, &stakingTxHash)
			return nil
		// We need to check any transaction which was sent to babylon, as it could be
		// that we sent undelegation msg, but restart happened before we could update
		// database
		case proto.TransactionState_SENT_TO_BABYLON:
			// TODO: If we will have automatic unstaking, we should check wheter tx is expired
			// and proceed with sending unstake transaction
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_DELEGATION_ACTIVE:
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC:
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_SPENT_ON_BTC:
			// nothing to do, staking transaction is already spent
			return nil
		default:
			return fmt.Errorf("unknown transaction state: %d", tx.State)
		}
	}, reset)

	if err != nil {
		return err
	}

	for _, txHash := range transactionsSentToBtc {
		stakingTxHash := txHash
		tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)
		details, status, err := app.wc.TxDetails(stakingTxHash, tx.StakingTx.TxOut[tx.StakingOutputIndex].PkScript)

		if err != nil {
			// we got some communication err, return error and kill app startup
			return err
		}

		err = app.handleBtcTxInfo(stakingTxHash, tx, stakingParams, app.currentBestBlockHeight.Load(), status, details)

		if err != nil {
			return err
		}
	}

	for _, txHash := range transactionConfirmedOnBtc {
		stakingTxHash := txHash

		delegationInfo, err := app.babylonClient.QueryDelegationInfo(stakingTxHash)

		if err != nil && !errors.Is(cl.ErrDelegationNotFound, err) {
			return err
		}

		// delegation is already on babylon restart delegation process from this point
		if delegationInfo != nil {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": stakingTxHash,
			}).Debug("Already confirmed transaction found on Babylon as part of delegation. Fix db state")

			ev := &delegationSubmittedToBabylonEvent{
				stakingTxHash: *stakingTxHash,
				unbondingTx:   delegationInfo.UndelegationInfo.UnbondingTransaction,
				unbondingTime: delegationInfo.UndelegationInfo.UnbondingTime,
			}

			utils.PushOrQuit[*delegationSubmittedToBabylonEvent](
				app.delegationSubmittedToBabylonEvChan,
				ev,
				app.quit,
			)
		} else {
			// transaction which is not on babylon, is already confirmed on btc chain
			// get all necessary info and send it to babylon

			tx, stakerAddress := app.mustGetTransactionAndStakerAddress(stakingTxHash)
			details, status, err := app.wc.TxDetails(stakingTxHash, tx.StakingTx.TxOut[tx.StakingOutputIndex].PkScript)

			if err != nil {
				// we got some communication err, return error and kill app startup
				return err
			}

			if status != walletcontroller.TxInChain {
				// we have confirmed transaction which is not in chain. Most probably btc node
				// we are connected to lost data
				app.logger.WithFields(logrus.Fields{
					"btcTxHash": stakingTxHash,
				}).Error("Already confirmed transaction not found on btc chain.")
				continue
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":                    stakingTxHash,
				"btcTxConfirmationBlockHeight": details.BlockHeight,
			}).Debug("Already confirmed transaction not sent to babylon yet. Initiate sending")

			iclusionProof := app.mustBuildInclusionProof(
				details.Block,
				details.TxIndex,
			)

			req := &sendDelegationRequest{
				txHash: *stakingTxHash,
				inclusionInfo: &inclusionInfo{
					txIndex:        details.TxIndex,
					inclusionBlock: details.Block,
					inclusionProof: iclusionProof,
				},
				requiredInclusionBlockDepth: uint64(stakingParams.ConfirmationTimeBlocks),
			}

			app.wg.Add(1)
			go app.sendDelegationToBabylonTask(req, stakerAddress, tx)
		}
	}

	for _, localInfo := range transactionsOnBabylon {
		// we only can have one local states here
		if localInfo.stakingTxState == proto.TransactionState_SENT_TO_BABYLON {
			stakingTxHash := localInfo.stakingTxHash
			// we crashed after succesful send to babaylon, restart checking for unbonding signatures
			app.wg.Add(1)
			go app.checkForUnbondingTxSignaturesOnBabylon(stakingTxHash)
		} else if localInfo.stakingTxState == proto.TransactionState_DELEGATION_ACTIVE {
			// delegation was sent to Babylon and activated by covenants, check whether we:
			// - did not spend tx before restart
			// - did not send unbonding tx before restart
			stakingTxHash := localInfo.stakingTxHash
			tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)

			// 1. First check if staking output is still unspent on BTC chain
			stakingOutputSpent, err := app.wc.OutputSpent(stakingTxHash, tx.StakingOutputIndex)

			if err != nil {
				return err
			}

			if !stakingOutputSpent {
				// If the staking output is unspent, then it means that delegation is
				// sitll considered active. We can move forward without to next transaction
				// and leave the state as it is.
				continue
			}

			// 2. Staking output has been spent, we need to check whether this is unbonding
			// or withdrawal transaction
			unbondingTxHash := tx.UnbondingTxData.UnbondingTx.TxHash()

			_, unbondingTxStatus, err := app.wc.TxDetails(
				&unbondingTxHash,
				// unbonding tx always have only one output
				tx.UnbondingTxData.UnbondingTx.TxOut[0].PkScript,
			)

			if err != nil {
				return err
			}

			if unbondingTxStatus == walletcontroller.TxNotFound {
				// no unbonding tx on chain and staking output already spent, most probably
				// staking transaction has been withdrawn, update state in db
				app.mustSetTxSpentOnBtc(stakingTxHash)
				continue
			}

			unbondingOutputSpent, err := app.wc.OutputSpent(&unbondingTxHash, 0)

			if err != nil {
				return err
			}

			if unbondingOutputSpent {
				app.mustSetTxSpentOnBtc(stakingTxHash)
				continue
			}

			// At this point:
			// - staking output is spent
			// - unbonding tx has been found in the btc chain
			// - unbonding output is not spent
			// we can start waiting for unbonding tx confirmation
			ev, err := app.notifier.RegisterConfirmationsNtfn(
				&unbondingTxHash,
				tx.UnbondingTxData.UnbondingTx.TxOut[0].PkScript,
				UnbondingTxConfirmations,
				// unbonding transactions will for sure be included after staking tranasction
				tx.StakingTxConfirmationInfo.Height,
			)

			if err != nil {
				return err
			}

			// unbonding tx is in mempool, wait for confirmation and inform event
			// loop about it
			app.wg.Add(1)
			go app.waitForUnbondingTxConfirmation(
				ev,
				tx.UnbondingTxData,
				stakingTxHash,
			)
		} else if localInfo.stakingTxState == proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC {
			stakingTxHash := localInfo.stakingTxHash
			tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)
			unbondingTxHash := tx.UnbondingTxData.UnbondingTx.TxHash()

			unbondingOutputSpent, err := app.wc.OutputSpent(&unbondingTxHash, 0)

			if err != nil {
				return err
			}

			if unbondingOutputSpent {
				app.mustSetTxSpentOnBtc(stakingTxHash)
			}
		} else {
			// we should not have any other state here, so kill app
			return fmt.Errorf("unexpected local transaction state: %s, expected: %s", localInfo.stakingTxState, proto.TransactionState_SENT_TO_BABYLON)
		}
	}

	return nil
}

func (app *StakerApp) waitForStakingTxConfirmation(
	txHash chainhash.Hash,
	depthOnBtcChain uint32,
	ev *notifier.ConfirmationEvent) {
	// check we are not shutting down
	select {
	case <-app.quit:
		ev.Cancel()
		return

	default:
	}

	for {
		// TODO add handling of more events like ev.NegativeConf which signals that
		// transaction have beer reorged out of the chain
		select {
		case conf := <-ev.Confirmed:
			stakingEvent := &stakingTxBtcConfirmedEvent{
				stakingTxHash: conf.Tx.TxHash(),
				txIndex:       conf.TxIndex,
				blockDepth:    depthOnBtcChain,
				blockHash:     *conf.BlockHash,
				blockHeight:   conf.BlockHeight,
				tx:            conf.Tx,
				inlusionBlock: conf.Block,
			}

			utils.PushOrQuit[*stakingTxBtcConfirmedEvent](
				app.stakingTxBtcConfirmedEvChan,
				stakingEvent,
				app.quit,
			)
			ev.Cancel()
			return
		case u := <-ev.Updates:
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": txHash,
				"confLeft":  u,
			}).Debugf("Staking transaction received confirmation")
		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		}
	}
}

func (app *StakerApp) getSlashingFee(feeFromBabylon btcutil.Amount) btcutil.Amount {
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
func (app *StakerApp) mustGetTransactionAndStakerAddress(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, btcutil.Address) {
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

func (app *StakerApp) mustBuildInclusionProof(
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

func (app *StakerApp) retrieveExternalDelegationData(stakerAddress btcutil.Address) (*externalDelegationData, error) {
	params, err := app.babylonClient.Params()
	if err != nil {
		return nil, err
	}

	stakerPublicKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	return &externalDelegationData{
		babylonStakerAddr: app.babylonClient.GetKeyAddress(),
		stakerPublicKey:   stakerPublicKey,
		babylonParams:     params,
	}, nil
}

func (app *StakerApp) sendUnbondingTxToBtcWithWitness(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData,
) error {

	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Failed to retrieve btc wallet private key send unbonding tx to btc")
		return err
	}

	// TODO: As covenant committee is static, consider quering it once and storing in database
	params, err := app.babylonClient.Params()

	if err != nil {
		return err
	}

	unbondingSpendInfo, err := buildUnbondingSpendInfo(
		stakerPubKey,
		storedTx,
		unbondingData,
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
		unbondingData.UnbondingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
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

	covenantSigantures := createWitnessSignaturesForPubKeys(
		params.CovenantPks,
		unbondingData.CovenantSignatures,
	)

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

	unbondingTx := unbondingData.UnbondingTx

	unbondingTx.TxIn[0].Witness = witness

	_, err = app.wc.SendRawTransaction(unbondingTx, true)

	if err != nil {
		return err
	}

	return nil
}

// sendUnbondingTxToBtc sends unbonding tx to btc and registers for inclusion notification.
// It retries until it successfully sends unbonding tx to btc and registers for notification.or until program finishes
// TODO: Investigate wheter some of the errors should be treated as fatal and abort whole process
func (app *StakerApp) sendUnbondingTxToBtc(
	ctx context.Context,
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData) (*notifier.ConfirmationEvent, error) {

	err := retry.Do(func() error {
		return app.sendUnbondingTxToBtcWithWitness(
			stakingTxHash,
			stakerAddress,
			storedTx,
			unbondingData,
		)
	},
		longRetryOps(
			ctx,
			unbondingSendRetryTimeout,
			app.onLongRetryFunc(stakingTxHash, "failed to send unbonding tx to btc"),
		)...,
	)

	if err != nil {
		return nil, err
	}

	bestBlockAfterSend := app.currentBestBlockHeight.Load()
	unbondingTxHash := unbondingData.UnbondingTx.TxHash()

	var notificationEv *notifier.ConfirmationEvent
	err = retry.Do(func() error {
		ev, err := app.notifier.RegisterConfirmationsNtfn(
			&unbondingTxHash,
			unbondingData.UnbondingTx.TxOut[0].PkScript,
			UnbondingTxConfirmations,
			bestBlockAfterSend,
		)

		if err != nil {
			return err
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
		return nil, err
	}
	return notificationEv, nil
}

// waitForUnbondingTxConfirmation blocks until unbonding tx is confirmed on btc chain.
func (app *StakerApp) waitForUnbondingTxConfirmation(
	waitEv *notifier.ConfirmationEvent,
	unbondingData *stakerdb.UnbondingStoreData,
	stakingTxHash *chainhash.Hash,
) {
	defer app.wg.Done()
	defer waitEv.Cancel()
	unbondingTxHash := unbondingData.UnbondingTx.TxHash()

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
func (app *StakerApp) sendUnbondingTxToBtcTask(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData) {
	defer app.wg.Done()
	quitCtx, cancel := app.appQuitContext()
	defer cancel()

	waitEv, err := app.sendUnbondingTxToBtc(
		quitCtx,
		stakingTxHash,
		stakerAddress,
		storedTx,
		unbondingData,
	)

	if err != nil {
		app.reportCriticialError(*stakingTxHash, err, "Failed failed to send unbonding tx to btc")
		return
	}

	app.wg.Add(1)
	go app.waitForUnbondingTxConfirmation(
		waitEv,
		unbondingData,
		stakingTxHash,
	)
}

// context which will be cancelled when app is shutting down
func (app *StakerApp) appQuitContext() (context.Context, func()) {
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

func (app *StakerApp) buildAndSendDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
) (*pv.RelayerTxResponse, *cl.DelegationData, error) {
	delegation, err := app.buildDelegation(req, stakerAddress, storedTx)
	if err != nil {
		return nil, nil, err
	}
	resp, err := app.babylonMsgSender.SendDelegation(delegation, req.requiredInclusionBlockDepth)
	if err != nil {
		return nil, nil, err
	}

	return resp, delegation, nil
}

func (app *StakerApp) sendDelegationToBabylonTask(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
) {
	defer app.wg.Done()

	// using app quit context to cancel retrying when app is shutting down
	ctx, cancel := app.appQuitContext()
	defer cancel()

	var delegationData *cl.DelegationData
	err := retry.Do(func() error {
		_, del, err := app.buildAndSendDelegation(req, stakerAddress, storedTx)

		if err != nil {
			if errors.Is(err, cl.ErrInvalidBabylonExecution) {
				return retry.Unrecoverable(err)
			}
			return err
		}

		delegationData = del
		return nil
	},
		longRetryOps(
			ctx,
			app.config.StakerConfig.BabylonStallingInterval,
			app.onLongRetryFunc(&req.txHash, "Failed to deliver delegation to babylon due to error."),
		)...,
	)

	if err != nil {
		app.reportCriticialError(
			req.txHash,
			err,
			"Failed to deliver delegation to babylon due to error.",
		)
	} else {
		// report success with the values we sent to Babylon
		ev := &delegationSubmittedToBabylonEvent{
			stakingTxHash: req.txHash,
			unbondingTx:   delegationData.Ud.UnbondingTransaction,
			unbondingTime: delegationData.Ud.UnbondingTxUnbondingTime,
		}

		utils.PushOrQuit[*delegationSubmittedToBabylonEvent](
			app.delegationSubmittedToBabylonEvChan,
			ev,
			app.quit,
		)
	}
}

// main event loop for the staker app
func (app *StakerApp) handleStakingEvents() {
	defer app.wg.Done()

	for {
		select {
		case ev := <-app.stakingRequestedEvChan:
			app.logStakingEventReceived(ev)

			if ev.isWatched() {
				bestBlockHeight := app.currentBestBlockHeight.Load()

				err := app.txTracker.AddWatchedTransaction(
					ev.stakingTx,
					ev.stakingOutputIdx,
					ev.stakingTime,
					ev.fpBtcPks,
					babylonPopToDbPop(ev.pop),
					ev.stakerAddress,
					ev.watchTxData.slashingTx,
					ev.watchTxData.slashingTxSig,
					ev.watchTxData.stakerBabylonAddr,
					ev.watchTxData.stakerBtcPk,
					ev.watchTxData.unbondingTx,
					ev.watchTxData.slashUnbondingTx,
					ev.watchTxData.slashUnbondingTxSig,
					ev.watchTxData.unbondingTime,
				)

				if err != nil {
					ev.errChan <- err
					continue
				}

				// we assume tx is already on btc chain, so we need to wait for confirmation
				if err := app.waitForStakingTransactionConfirmation(
					&ev.stakingTxHash,
					ev.stakingTx.TxOut[ev.stakingOutputIdx].PkScript,
					ev.requiredDepthOnBtcChain,
					uint32(bestBlockHeight),
				); err != nil {
					ev.errChan <- err
					continue
				}

				app.m.ValidReceivedDelegationRequests.Inc()
				ev.successChan <- &ev.stakingTxHash
			} else {
				err := app.txTracker.AddTransaction(
					ev.stakingTx,
					ev.stakingOutputIdx,
					ev.stakingTime,
					ev.fpBtcPks,
					babylonPopToDbPop(ev.pop),
					ev.stakerAddress,
				)

				if err != nil {
					ev.errChan <- err
					continue
				}

				app.logger.Info("Recieved staking event", "ususePreApprovalFlowe", ev.usePreApprovalFlow)

				if ev.usePreApprovalFlow {
					req := &sendDelegationRequest{
						txHash:                      ev.stakingTxHash,
						inclusionInfo:               nil,
						requiredInclusionBlockDepth: uint64(ev.requiredDepthOnBtcChain),
					}

					storedTx, stakerAddress := app.mustGetTransactionAndStakerAddress(&ev.stakingTxHash)

					app.wg.Add(1)
					go func(
						req *sendDelegationRequest,
						stakerAddress btcutil.Address,
						storedTx *stakerdb.StoredTransaction,
						ev *stakingRequestedEvent,
					) {
						defer app.wg.Done()
						_, delegationData, err := app.buildAndSendDelegation(
							req,
							stakerAddress,
							storedTx,
						)

						if err != nil {
							utils.PushOrQuit(
								ev.errChan,
								err,
								app.quit,
							)
							return
						}

						submittedEv := &delegationSubmittedToBabylonEvent{
							stakingTxHash: req.txHash,
							unbondingTx:   delegationData.Ud.UnbondingTransaction,
							unbondingTime: delegationData.Ud.UnbondingTxUnbondingTime,
						}

						// push event to channel to start waiting for covenant signatures
						utils.PushOrQuit[*delegationSubmittedToBabylonEvent](
							app.delegationSubmittedToBabylonEvChan,
							submittedEv,
							app.quit,
						)

						// send success to caller
						utils.PushOrQuit(
							ev.successChan,
							&ev.stakingTxHash,
							app.quit,
						)
					}(req, stakerAddress, storedTx, ev)
				} else {
					// old flow, send to BTC first, end expect response to the caller
					app.wg.Add(1)
					go func() {
						defer app.wg.Done()
						utils.PushOrQuit(
							app.sendStakingTxToBTCRequestedEvChan,
							&sendStakingTxToBTCRequestedEvent{
								stakingTxHash:           ev.stakingTxHash,
								requiredDepthOnBtcChain: ev.requiredDepthOnBtcChain,
								responseExpected: &responseExpectedChan{
									errChan:     ev.errChan,
									successChan: ev.successChan,
								},
							},
							app.quit,
						)
					}()
				}
				app.logStakingEventProcessed(ev)
			}

		case ev := <-app.sendStakingTxToBTCRequestedEvChan:
			app.logStakingEventReceived(ev)

			bestBlockHeight := app.currentBestBlockHeight.Load()

			storedTx, _ := app.mustGetTransactionAndStakerAddress(&ev.stakingTxHash)

			_, err := app.wc.SendRawTransaction(storedTx.StakingTx, true)

			if err != nil {
				if ev.responseExpected != nil {
					utils.PushOrQuit(
						ev.responseExpected.errChan,
						err,
						app.quit,
					)
				}
				app.logStakingEventProcessed(ev)
				continue
			}

			if err := app.txTracker.SetTxSentToBtc(
				&ev.stakingTxHash,
			); err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}

			stakingOutputPkScript := storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].PkScript

			if err := app.waitForStakingTransactionConfirmation(
				&ev.stakingTxHash,
				stakingOutputPkScript,
				ev.requiredDepthOnBtcChain,
				uint32(bestBlockHeight),
			); err != nil {
				if ev.responseExpected != nil {
					utils.PushOrQuit(
						ev.responseExpected.errChan,
						err,
						app.quit,
					)
				}
				app.logStakingEventProcessed(ev)
				continue
			}

			if ev.responseExpected != nil {
				utils.PushOrQuit(
					ev.responseExpected.successChan,
					&ev.stakingTxHash,
					app.quit,
				)
			}

			app.logStakingEventProcessed(ev)

		case ev := <-app.stakingTxBtcConfirmedEvChan:
			app.logStakingEventReceived(ev)

			if err := app.txTracker.SetTxConfirmed(
				&ev.stakingTxHash,
				&ev.blockHash,
				ev.blockHeight,
			); err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}

			proof := app.mustBuildInclusionProof(
				ev.inlusionBlock,
				ev.txIndex,
			)

			req := &sendDelegationRequest{
				txHash: ev.stakingTxHash,
				inclusionInfo: &inclusionInfo{
					txIndex:        ev.txIndex,
					inclusionBlock: ev.inlusionBlock,
					inclusionProof: proof,
				},
				requiredInclusionBlockDepth: uint64(ev.blockDepth),
			}

			storedTx, stakerAddress := app.mustGetTransactionAndStakerAddress(&ev.stakingTxHash)

			app.m.DelegationsConfirmedOnBtc.Inc()
			// TODO: Introduce max number of sendToDelegationToBabylonTasks. It should be tied to
			// accepting new staking delegations i.e we will hit it we should stop accepting new stakingrequests
			// as either babylon node is not healthy or we are constructing invalid delegations
			app.wg.Add(1)
			go app.sendDelegationToBabylonTask(req, stakerAddress, storedTx)
			app.logStakingEventProcessed(ev)

		case ev := <-app.delegationSubmittedToBabylonEvChan:
			app.logStakingEventReceived(ev)
			if err := app.txTracker.SetTxSentToBabylon(&ev.stakingTxHash, ev.unbondingTx, ev.unbondingTime); err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}

			app.m.DelegationsSentToBabylon.Inc()
			// start checking for covenant signatures on unbodning transactions
			// when we receive them we treat delegation as active
			app.wg.Add(1)
			go app.checkForUnbondingTxSignaturesOnBabylon(&ev.stakingTxHash)

			app.logStakingEventProcessed(ev)

		case ev := <-app.unbondingTxSignaturesConfirmedOnBabylonEvChan:
			app.logStakingEventReceived(ev)

			if err := app.txTracker.SetTxUnbondingSignaturesReceived(
				&ev.stakingTxHash,
				babylonCovSigsToDbSigSigs(ev.covenantUnbondingSignatures),
			); err != nil {
				// TODO: handle this error somehow, it means we possilbly make invalid state transition
				app.logger.Fatalf("Error setting state for tx %s: %s", &ev.stakingTxHash, err)
			}

			app.m.DelegationsActivatedOnBabylon.Inc()
			app.logStakingEventProcessed(ev)

		case ev := <-app.unbondingTxConfirmedOnBtcEvChan:
			app.logStakingEventReceived(ev)
			if err := app.txTracker.SetTxUnbondingConfirmedOnBtc(
				&ev.stakingTxHash,
				&ev.blockHash,
				ev.blockHeight,
			); err != nil {
				// TODO: handle this error somehow, it means we received spend stake confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}
			app.logStakingEventProcessed(ev)

		case ev := <-app.spendStakeTxConfirmedOnBtcEvChan:
			app.logStakingEventReceived(ev)
			if err := app.txTracker.SetTxSpentOnBtc(&ev.stakingTxHash); err != nil {
				// TODO: handle this error somehow, it means we received spend stake confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", ev.stakingTxHash, err)
			}
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

func (app *StakerApp) Wallet() walletcontroller.WalletController {
	return app.wc
}

func (app *StakerApp) BabylonController() cl.BabylonClient {
	return app.babylonClient
}

func (app *StakerApp) WatchStaking(
	stakingTx *wire.MsgTx,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpPks []*btcec.PublicKey,
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
) (*chainhash.Hash, error) {
	currentParams, err := app.babylonClient.Params()

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Failed to get params: %w", err)
	}

	if len(fpPks) == 0 {
		return nil, fmt.Errorf("no finality provider public keys provided")
	}

	if haveDuplicates(fpPks) {
		return nil, fmt.Errorf("duplicate finality provider public keys provided")
	}

	watchedRequest, err := parseWatchStakingRequest(
		stakingTx,
		stakingTime,
		stakingValue,
		fpPks,
		slashingTx,
		slashingTxSig,
		stakerBabylonAddr,
		stakerBtcPk,
		stakerAddress,
		pop,
		unbondingTx,
		slashUnbondingTx,
		slashUnbondingTxSig,
		unbondingTime,
		currentParams,
		app.network,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid request: %w", err)
	}

	// we have valid request, check whether finality providers exists on babylon
	for _, fpPk := range fpPks {
		if err := app.finalityProviderExists(fpPk); err != nil {
			return nil, err
		}
	}

	app.logger.WithFields(logrus.Fields{
		"stakerAddress": stakerAddress,
		"stakingAmount": watchedRequest.stakingTx.TxOut[watchedRequest.stakingOutputIdx].Value,
		"btxTxHash":     stakingTx.TxHash(),
	}).Info("Received valid staking tx to watch")

	utils.PushOrQuit[*stakingRequestedEvent](
		app.stakingRequestedEvChan,
		watchedRequest,
		app.quit,
	)

	select {
	case reqErr := <-watchedRequest.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddress,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return nil, reqErr
	case hash := <-watchedRequest.successChan:
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}

func (app *StakerApp) StakeFunds(
	stakerAddress btcutil.Address,
	stakingAmount btcutil.Amount,
	fpPks []*btcec.PublicKey,
	stakingTimeBlocks uint16,
	sendToBabylonFirst bool,
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
			return nil, err
		}
	}

	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, err
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

	// unlock wallet for the rest of the operations
	// TODO consider unlock/lock with defer
	err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

	if err != nil {
		return nil, err
	}

	// build proof of possesion, no point moving forward if staker do not have all
	// the necessary keys
	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	babylonAddrHash := tmhash.Sum(app.babylonClient.GetKeyAddress().Bytes())

	sig, err := app.wc.SignBip322NativeSegwit(babylonAddrHash, stakerAddress)

	if err != nil {
		return nil, err
	}

	pop, err := cl.NewBabylonBip322Pop(
		babylonAddrHash,
		sig,
		stakerAddress,
	)

	if err != nil {
		return nil, err
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

	tx, err := app.wc.CreateAndSignTx([]*wire.TxOut{stakingInfo.StakingOutput}, btcutil.Amount(feeRate), stakerAddress)

	if err != nil {
		return nil, err
	}

	app.logger.WithFields(logrus.Fields{
		"stakerAddress": stakerAddress,
		"stakingAmount": stakingInfo.StakingOutput,
		"btxTxHash":     tx.TxHash(),
		"fee":           feeRate,
	}).Info("Created and signed staking transaction")

	req := newOwnedStakingRequest(
		stakerAddress,
		tx,
		0,
		stakingInfo.StakingOutput.PkScript,
		stakingTimeBlocks,
		stakingAmount,
		fpPks,
		params.ConfirmationTimeBlocks,
		pop,
		sendToBabylonFirst,
	)

	utils.PushOrQuit[*stakingRequestedEvent](
		app.stakingRequestedEvChan,
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

func (app *StakerApp) StoredTransactions(limit, offset uint64) (*stakerdb.StoredTransactionQueryResult, error) {
	query := stakerdb.StoredTransactionQuery{
		IndexOffset:        offset,
		NumMaxTransactions: limit,
		Reversed:           false,
	}
	resp, err := app.txTracker.QueryStoredTransactions(query)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (app *StakerApp) WithdrawableTransactions(limit, offset uint64) (*stakerdb.StoredTransactionQueryResult, error) {
	query := stakerdb.StoredTransactionQuery{
		IndexOffset:        offset,
		NumMaxTransactions: limit,
		Reversed:           false,
	}
	resp, err := app.txTracker.QueryStoredTransactions(query.WithdrawableTransactionsFilter(app.currentBestBlockHeight.Load()))
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (app *StakerApp) GetStoredTransaction(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, error) {
	return app.txTracker.GetTransaction(txHash)
}

func (app *StakerApp) ListUnspentOutputs() ([]walletcontroller.Utxo, error) {
	return app.wc.ListOutputs(false)
}

func (app *StakerApp) waitForSpendConfirmation(stakingTxHash chainhash.Hash, ev *notifier.ConfirmationEvent) {
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

func (app *StakerApp) signTaprootScriptSpendUsingWallet(
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
		return nil, err
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
func (app *StakerApp) SpendStake(stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil, nil

	default:
	}

	tx, err := app.txTracker.GetTransaction(stakingTxHash)

	if err != nil {
		return nil, nil, err
	}

	// we cannont spend tx which is watch only.
	// TODO. To make it possible additional endpoint is needed
	if tx.Watched {
		return nil, nil, fmt.Errorf("cannot spend staking which which is in watch only mode")
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

	spendStakeTxInfo, err := createSpendStakeTxFromStoredTx(
		pubKey,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		tx,
		destAddressScript,
		currentFeeRate,
		app.network,
	)

	if err != nil {
		return nil, nil, err
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

func (app *StakerApp) ListActiveFinalityProviders(limit uint64, offset uint64) (*cl.FinalityProvidersClientResponse, error) {
	return app.babylonClient.QueryFinalityProviders(limit, offset)
}

// Initiates whole unbonding process. Whole process looks like this:
// 1. Unbonding data is build based on exsitng staking transaction data
// 2. Unbonding data is sent to babylon as part of undelegete request
// 3. If request is successful, unbonding transaction is registred in db and
// staking transaction is marked as unbonded
// 4. Staker program starts watching for unbodning transactions signatures from
// covenant and finality provider
// 5. After gathering all signatures, unbonding transaction is sent to bitcoin
// This function returns control to the caller after step 3. Later is up to the caller
// to check what is state of unbonding transaction
func (app *StakerApp) UnbondStaking(
	stakingTxHash chainhash.Hash, feeRate *btcutil.Amount) (*chainhash.Hash, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	// 1. Check staking tx is managed by staker program
	tx, err := app.txTracker.GetTransaction(&stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("cannont unbond: %w", err)
	}

	// 2. Check tx is not watched and is in valid state
	if tx.Watched {
		return nil, fmt.Errorf("cannot unbond watched transaction")
	}

	if tx.State != proto.TransactionState_DELEGATION_ACTIVE {
		return nil, fmt.Errorf("cannot unbond transaction which is not active")
	}

	stakerAddress, err := btcutil.DecodeAddress(tx.StakerAddress, app.network)

	if err != nil {
		return nil, fmt.Errorf("error decoding staker address: %s. Err: %v", tx.StakerAddress, err)
	}

	// TODO: Move this to event handler to avoid somebody starting multiple unbonding routines
	app.wg.Add(1)
	go app.sendUnbondingTxToBtcTask(
		&stakingTxHash,
		stakerAddress,
		tx,
		tx.UnbondingTxData,
	)

	unbondingTxHash := tx.UnbondingTxData.UnbondingTx.TxHash()
	return &unbondingTxHash, nil
}
