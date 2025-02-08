package staker

import (
	"errors"
	"fmt"
	"strings"
	"time"

	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/sirupsen/logrus"
)

// TODO: All functions and types declared in this file should be moved to separate package
// and be part of new module which will be responsible for communication with babylon chain i.e
// retrieving data from babylon chain, sending data to babylon chain, queuing data to be send etc.

// These constants are used to indicate the status of a delegation
// From field in response of BTCDelegation
const (
	BabylonPendingStatus  = "PENDING"
	BabylonVerifiedStatus = "VERIFIED"
	BabylonActiveStatus   = "ACTIVE"
)

type inclusionInfo struct {
	txIndex                 uint32
	inclusionBlock          *wire.MsgBlock
	inclusionBlockBtcHeight uint32
	inclusionProof          []byte
}

type sendDelegationRequest struct {
	btcTxHash chainhash.Hash
	// optional field, if not provided, delegation will be sent to Babylon without
	// the inclusion proof
	inclusionInfo               *inclusionInfo
	requiredInclusionBlockDepth uint32
}

func (app *App) buildDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
) (*cl.DelegationData, error) {
	externalData, err := app.retrieveExternalDelegationData(stakerAddress, req.inclusionInfo)
	if err != nil {
		return nil, err
	}

	slashingFee := app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat)

	stakingSlashingTx, stakingSlashingSpendInfo, err := slashingTxForStakingTx(
		slashingFee,
		externalData,
		storedTx,
		app.network,
	)
	if err != nil {
		// This is truly unexpected, most probably programming error we have
		// valid and btc confirmed staking transacion, but for some reason we cannot
		// build delegation data using our own set of libraries
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":     req.btcTxHash,
			"stakerAddress": stakerAddress,
			"err":           err,
		}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
	}

	undelegationDesc, err := createUndelegationData(
		storedTx,
		externalData.stakerPublicKey,
		externalData.babylonParams.CovenantPks,
		externalData.babylonParams.CovenantQuruomThreshold,
		externalData.babylonParams.SlashingPkScript,
		externalData.babylonParams.UnbondingFee,
		externalData.babylonParams.UnbondingTime,
		app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat),
		externalData.babylonParams.SlashingRate,
		app.network,
	)

	if err != nil {
		// TODO: Most probable couse for this error would be some kind of problem with fees
		return nil, fmt.Errorf("error creating undelegation data: %w", err)
	}

	stakingSlashingSig, err := app.signTaprootScriptSpendUsingWallet(
		stakingSlashingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
		stakerAddress,
		&stakingSlashingSpendInfo.RevealedLeaf,
		&stakingSlashingSpendInfo.ControlBlock,
	)

	if err != nil {
		return nil, fmt.Errorf("error signing slashing transaction for staking transaction: %w", err)
	}

	if stakingSlashingSig.Signature == nil {
		return nil, fmt.Errorf("failed to receive stakingSlashingSig.Signature ")
	}

	unbondingSlashingSig, err := app.signTaprootScriptSpendUsingWallet(
		undelegationDesc.SlashUnbondingTransaction,
		undelegationDesc.UnbondingTransaction.TxOut[0],
		stakerAddress,
		&undelegationDesc.SlashUnbondingTransactionSpendInfo.RevealedLeaf,
		&undelegationDesc.SlashUnbondingTransactionSpendInfo.ControlBlock,
	)

	if err != nil {
		return nil, fmt.Errorf("error signing slashing transaction for unbonding transaction: %w", err)
	}

	if unbondingSlashingSig.Signature == nil {
		return nil, fmt.Errorf("failed to receive unbondingSlashingSig.Signature ")
	}

	dg := createDelegationData(
		externalData.stakerPublicKey,
		req.inclusionInfo,
		storedTx,
		stakingSlashingTx,
		stakingSlashingSig.Signature,
		externalData.babylonStakerAddr,
		&cl.UndelegationData{
			UnbondingTransaction:         undelegationDesc.UnbondingTransaction,
			UnbondingTxValue:             undelegationDesc.UnbondingTxValue,
			UnbondingTxUnbondingTime:     undelegationDesc.UnbondingTxUnbondingTime,
			SlashUnbondingTransaction:    undelegationDesc.SlashUnbondingTransaction,
			SlashUnbondingTransactionSig: unbondingSlashingSig.Signature,
		},
	)

	return dg, nil
}

// TODO for now we launch this handler indefinitely. At some point we may introduce
// timeout, and if signatures are not find in this timeout, then we may submit
// evidence that covenant members are censoring our staking transactions
func (app *App) checkForUnbondingTxSignaturesOnBabylon(stakingTxHash *chainhash.Hash) {
	checkSigTicker := time.NewTicker(app.config.StakerConfig.UnbondingTxCheckInterval)
	defer checkSigTicker.Stop()
	defer app.wg.Done()

	for {
		select {
		case <-checkSigTicker.C:
			di, err := app.babylonClient.QueryDelegationInfo(stakingTxHash)
			if err != nil {
				if errors.Is(err, cl.ErrDelegationNotFound) {
					// As we only start this handler when we are sure delegation is already on babylon
					// this can only that:
					// - either we are connected to wrong babylon network
					// - or babylon node lost data and is still syncing
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
					}).Error("Delegation for given staking tx hash does not exsist on babylon. Check your babylon node.")
				} else {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
						"err":           err,
					}).Error("Error getting delegation info from babylon")
				}
				continue
			}

			if di.UndelegationInfo == nil {
				// As we only start this handler when we are sure delegation received unbonding request
				// this can only that:
				// - babylon node lost data and is still syncing, and not processed unbonding request yet
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
				}).Error("Delegation for given staking tx hash is not unbonding yet.")
				continue
			}

			params, err := app.babylonClient.Params()
			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"err":           err,
				}).Error("Error getting babylon params")
				// Failed to get params, we cannont do anything, most probably connection error to babylon node
				// we will try again in next iteration
				continue
			}

			// we have enough signatures to submit unbonding tx this means that delegation is available to be activated.
			// staking tranction is verifed when enough covenant signatures are received.
			if len(di.UndelegationInfo.CovenantUnbondingSignatures) >= int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
				}).Debug("Received enough covenant unbonding signatures on babylon")

				if err := app.txTracker.SetTxUnbondingSignaturesReceived(
					stakingTxHash,
					babylonCovSigsToDBSigSigs(di.UndelegationInfo.CovenantUnbondingSignatures),
				); err != nil {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
						"err":           err,
					}).Error("Error setting unbonding signatures received state for staking tx")
					continue
				}

				req := &unbondingTxSignaturesConfirmedOnBabylonEvent{
					stakingTxHash:               *stakingTxHash,
					covenantUnbondingSignatures: di.UndelegationInfo.CovenantUnbondingSignatures,
				}

				utils.PushOrQuit[*unbondingTxSignaturesConfirmedOnBabylonEvent](
					app.unbondingTxSignaturesConfirmedOnBabylonEvChan,
					req,
					app.quit,
				)

				return
			} else {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
					"required":      params.CovenantQuruomThreshold,
				}).Debug("Received not enough covenant unbonding signatures on babylon")
			}

		case <-app.quit:
			return
		}
	}
}

func (app *App) finalityProviderExists(fpPk *btcec.PublicKey) error {
	if fpPk == nil {
		return fmt.Errorf("provided finality provider public key is nil")
	}

	_, err := app.babylonClient.QueryFinalityProvider(fpPk)

	if err != nil {
		return fmt.Errorf("error checking if finality provider exists on babylon chain: %w", err)
	}

	return nil
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

// handleActivatedDelegation handles delegation which is already active on babylon
func (app *App) handleActivatedDelegation(stakingTxHash *chainhash.Hash, stakingTransaction *wire.MsgTx, stakingOutputIndex uint32) {
	app.logger.WithFields(logrus.Fields{
		"stakingTxHash": stakingTxHash,
	}).Debug("Delegation has been activated on the Babylon chain")

	info, status, err := app.wc.TxDetails(stakingTxHash, stakingTransaction.TxOut[stakingOutputIndex].PkScript)
	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("error getting staking transaction details from btc chain")

		// failed to retrieve transaction details from bitcoind node, most probably
		// connection error, we will try again in next iteration
		return
	}
	if status != walletcontroller.TxInChain {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
		}).Debug("Staking transaction active on babylon, but not on btc chain. Waiting for btc node to catch up")
		return
	}

	// delegation has been activated on babylon
	utils.PushOrQuit[*delegationActivatedEvent](
		app.delegationActivatedEvChan,
		&delegationActivatedEvent{
			stakingTxHash: *stakingTxHash,
			blockHash:     *info.BlockHash,
			blockHeight:   info.BlockHeight,
		},
		app.quit,
	)
}

// handleNotActivatedDelegation handles delegation which is not active yet
func (app *App) handleNotActivatedDelegation(di *cl.DelegationInfo, stakingTxHash *chainhash.Hash, stakingTransaction *wire.MsgTx, stakingOutputIndex uint32) {
	// if delegation is not active yet, check transaction is sent to bitcoin chain
	// covenant signatures are not enough to activate delegation

	params, err := app.babylonClient.Params()
	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Error getting babylon params")
		// Failed to get params, we cannont do anything, most probably connection error to babylon node
		// we will try again in next iteration
		return
	}

	if len(di.UndelegationInfo.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
			"required":      params.CovenantQuruomThreshold,
		}).Debug("Received not enough covenant unbonding signatures on babylon to wait fo activation")
		return
	}

	// check if staking tx is already on BTC chain
	_, status, err := app.wc.TxDetails(stakingTxHash, stakingTransaction.TxOut[stakingOutputIndex].PkScript)
	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Error checking existence of staking transaction on btc chain")
		return
	}

	// waiting for activation since staking transaction is on btc chain
	if status != walletcontroller.TxNotFound {
		app.logger.WithFields(logrus.Fields{
			"status":        status,
			"stakingTxHash": stakingTxHash,
		}).Error("Staking transaction found on btc chain, waiting for activation on Babylon")
		return
	}

	// at this point we know that:
	// - delegation is not active and already have quorum of covenant signatures
	// - staking transaction is not on btc chain

	// check if staking transaction is fully signed
	isSigned, err := isTransacionFullySigned(stakingTransaction)
	if err != nil {
		app.reportCriticialError(
			*stakingTxHash,
			err,
			"Error checking if staking transaction is fully signed",
		)
		return
	}

	// if fully signed, send staking transaction to btc chain
	if isSigned {
		if err := app.sendTransactionToBtc(stakingTransaction); err != nil {
			app.logger.WithFields(logrus.Fields{
				"err":           err,
				"stakingTxHash": stakingTxHash,
			}).Error("failed to sign and send verified staking transaction to btc chain")
		}
		return
	}

	if err := app.signAndSendTransactionToBtc(stakingTransaction); err != nil {
		app.logger.WithFields(logrus.Fields{
			"err":           err,
			"stakingTxHash": stakingTxHash,
		}).Error("failed to sign and send verified staking transaction to btc chain")
		return
	}

	// set staking transaction sent to btc to be checked confirmed in staker db
	storedTx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)

	if err := app.waitForStakingTransactionConfirmation(
		stakingTxHash,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].PkScript,
		params.ConfirmationTimeBlocks,
		app.currentBestBlockHeight.Load(),
	); err != nil {
		app.logger.WithFields(logrus.Fields{
			"err":           err,
			"stakingTxHash": stakingTxHash,
		}).Error("failed to wait for staking transaction confirmation")
		return
	}
}

// signAndSendTransactionToBitcoin signs a transaction and sends it to the bitcoin chain
// and stores the status to the database with the given txHash
func (app *App) signAndSendTransactionToBtc(tx *wire.MsgTx) error {
	// return error if unlocking wallet failed
	if err := app.wc.UnlockWallet(defaultWalletUnlockTimeout); err != nil {
		return fmt.Errorf("failed to unlock wallet to sign staking transaction: %w", err)
	}

	// staking transaction is not signed, we must sign it before sending to btc chain
	signedTx, fullySigned, err := app.wc.SignRawTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to sign staking transaction: %w", err)
	}

	// check if staking transaction is fully signed
	if !fullySigned {
		return fmt.Errorf("cannot sign staking transction with configured wallet")
	}

	if err := app.sendTransactionToBtc(signedTx); err != nil {
		return fmt.Errorf("failed to send staking transaction to btc chain to activate verified delegation: %w", err)
	}
	// at this point we send signed staking transaction to BTC chain, we will
	// still wait for its activation
	return nil
}

// sendTransactionToBtc sends a transaction to the bitcoin chain
// and stores the status to the database with the given txHash
func (app *App) sendTransactionToBtc(tx *wire.MsgTx) error {
	_, err := app.wc.SendRawTransaction(tx, true)
	if err != nil {
		return fmt.Errorf("failed to send staking transaction to btc chain to activate verified delegation: %w", err)
	}

	return nil
}

// waitForStakingTransactionConfirmation waits for staking transaction confirmation
// on the btc chain
func (app *App) waitForStakingTransactionConfirmation(
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
		return fmt.Errorf("failed to register for staking transaction confirmation: %w", err)
	}

	app.wg.Add(1)
	go app.handleBtcConfirmationEvent(*stakingTxHash, confEvent)
	return nil
}

// waitForStakingTxConfirmation waits for staking transaction confirmation
// on the btc chain
func (app *App) handleBtcConfirmationEvent(
	txHash chainhash.Hash,
	ev *notifier.ConfirmationEvent,
) {
	defer app.wg.Done()

	for {
		// TODO add handling of more events like ev.NegativeConf which signals that
		// transaction have beer reorged out of the chain
		select {
		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		case conf := <-ev.Confirmed:
			txHash := conf.Tx.TxHash()
			if err := app.txTracker.SetTxConfirmed(
				&txHash,
				conf.BlockHash,
				conf.BlockHeight,
			); err != nil {
				app.logger.Fatalf("Error setting state for tx %s: %s", txHash.String(), err)
			}
			ev.Cancel()
			return
		case u := <-ev.Updates:
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": txHash,
				"confLeft":  u,
			}).Debugf("Staking transaction received confirmation")
		}
	}
}

// activateVerifiedDelegation is called when we are sure that staking transaction
// is fully signed by all finality providers.
// This function must be run in separate goroutine whenever delegation
// reaches verified state. i.e
// - delegation is on babylon
// - delegation has received enough covenant signatures
func (app *App) activateVerifiedDelegation(
	stakingTransaction *wire.MsgTx,
	stakingOutputIndex uint32,
	stakingTxHash *chainhash.Hash) {
	checkSigTicker := time.NewTicker(app.config.StakerConfig.CheckActiveInterval)
	defer checkSigTicker.Stop()
	defer app.wg.Done()

	for {
		select {
		case <-checkSigTicker.C:
			di, err := app.babylonClient.QueryDelegationInfo(stakingTxHash)
			if err != nil {
				if errors.Is(err, cl.ErrDelegationNotFound) {
					// As we only start this handler when we are sure delegation is already on babylon
					// this can only that:
					// - either we are connected to wrong babylon network
					// - or babylon node lost data and is still syncing
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
					}).Error("Delegation for given staking tx hash does not exsist on babylon. Check your babylon node.")
				} else {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
						"err":           err,
					}).Error("Error getting delegation info from babylon")
				}
				continue
			}

			// check if check is active
			// this loop assume there is at least one active vigiliante to activate delegation
			if strings.EqualFold(di.Status, BabylonActiveStatus) {
				app.handleActivatedDelegation(stakingTxHash, stakingTransaction, stakingOutputIndex)
			}
			app.handleNotActivatedDelegation(di, stakingTxHash, stakingTransaction, stakingOutputIndex)
		case <-app.quit:
			return
		}
	}
}

func newSendDelegationRequest(
	btcStakingTxHash *chainhash.Hash,
	inclusionInfo *inclusionInfo,
	requiredInclusionBlockDepth uint32,
) *sendDelegationRequest {
	return &sendDelegationRequest{
		btcTxHash:                   *btcStakingTxHash,
		inclusionInfo:               inclusionInfo,
		requiredInclusionBlockDepth: requiredInclusionBlockDepth,
	}
}
