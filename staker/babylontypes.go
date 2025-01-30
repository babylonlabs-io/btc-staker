package staker

import (
	"errors"
	"fmt"
	"time"

	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

// TODO: All functions and types declared in this file should be moved to separate package
// and be part of new module which will be responsible for communication with babylon chain i.e
// retrieving data from babylon chain, sending data to babylon chain, queuing data to be send etc.

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

func (app *App) buildOwnedDelegation(
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

func (app *App) buildDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction) (*cl.DelegationData, error) {
	if storedTx.Watched {
		watchedData, err := app.txTracker.GetWatchedTransactionData(&req.btcTxHash)

		if err != nil {
			// Fatal error as if delegation is watched, the watched data must be in database
			// and must be not malformed
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":     req.btcTxHash,
				"stakerAddress": stakerAddress,
				"err":           err,
			}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
		}

		undelegationData := cl.UndelegationData{
			UnbondingTransaction:         watchedData.UnbondingTx,
			UnbondingTxValue:             btcutil.Amount(watchedData.UnbondingTx.TxOut[0].Value),
			UnbondingTxUnbondingTime:     watchedData.UnbondingTime,
			SlashUnbondingTransaction:    watchedData.SlashingUnbondingTx,
			SlashUnbondingTransactionSig: watchedData.SlashingUnbondingTxSig,
		}

		dg := createDelegationData(
			watchedData.StakerBtcPubKey,
			req.inclusionInfo,
			storedTx,
			watchedData.SlashingTx,
			watchedData.SlashingTxSig,
			watchedData.StakerBabylonAddr,
			&undelegationData,
		)
		return dg, nil
	}

	return app.buildOwnedDelegation(
		req,
		stakerAddress,
		storedTx,
	)
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

			// we have enough signatures to submit unbonding tx this means that delegation is active
			if len(di.UndelegationInfo.CovenantUnbondingSignatures) >= int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
				}).Debug("Received enough covenant unbonding signatures on babylon")

				req := &unbondingTxSignaturesConfirmedOnBabylonEvent{
					stakingTxHash:               *stakingTxHash,
					delegationActive:            di.Active,
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

// activateVerifiedDelegation must be run in separate goroutine whenever delegation
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

			// check if check is active
			// this loop assume there is at least one active vigiliante to activate delegation
			if di.Active {
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
					continue
				}

				if status != walletcontroller.TxInChain {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
					}).Debug("Staking transaction active on babylon, but not on btc chain. Waiting for btc node to catch up")
					continue
				}

				utils.PushOrQuit[*delegationActivatedPreApprovalEvent](
					app.delegationActivatedPreApprovalEvChan,
					&delegationActivatedPreApprovalEvent{
						stakingTxHash: *stakingTxHash,
						blockHash:     *info.BlockHash,
						blockHeight:   info.BlockHeight,
					},
					app.quit,
				)
				return
			}

			if len(di.UndelegationInfo.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
					"required":      params.CovenantQuruomThreshold,
				}).Debug("Received not enough covenant unbonding signatures on babylon to wait fo activation")
				continue
			}

			// check if staking tx is already on BTC chain
			_, status, err := app.wc.TxDetails(stakingTxHash, stakingTransaction.TxOut[stakingOutputIndex].PkScript)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"err":           err,
				}).Error("Error checking existence of staking transaction on btc chain")
				continue
			}

			if status != walletcontroller.TxNotFound {
				app.logger.WithFields(logrus.Fields{
					"status":        status,
					"stakingTxHash": stakingTxHash,
				}).Error("Staking transaction found on btc chain, waiting for activation on Babylon")
				continue
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

			if isSigned {
				_, err := app.wc.SendRawTransaction(stakingTransaction, true)

				if err != nil {
					app.logger.WithFields(logrus.Fields{
						"err":           err,
						"stakingTxHash": stakingTxHash,
					}).Error("failed to send staking transaction to btc chain to activate verified delegation")
				}

				continue
			}

			err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"err":           err,
					"stakingTxHash": stakingTxHash,
				}).Error("failed to unlock wallet to sign staking transaction")
				continue
			}

			// staking transaction is not signed, we must sign it before sending to btc chain
			signedTx, fullySigned, err := app.wc.SignRawTransaction(stakingTransaction)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"err":           err,
					"stakingTxHash": stakingTxHash,
				}).Error("failed to sign staking transaction")
				continue
			}

			if !fullySigned {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
				}).Debug("cannot sign staking transction with configured wallet")
				continue
			}

			_, err = app.wc.SendRawTransaction(signedTx, true)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"err":           err,
					"stakingTxHash": stakingTxHash,
				}).Error("failed to send staking transaction to btc chain to activate verified delegation")
			}
			// at this point we send signed staking transaction to BTC chain, we will
			// still wait for its activation
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
