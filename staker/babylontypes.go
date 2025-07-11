package staker

import (
	"errors"
	"fmt"
	"time"

	staking "github.com/babylonlabs-io/babylon/v3/btcstaking"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/babylonlabs-io/btc-staker/stakerdb"
	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/sirupsen/logrus"
)

// TODO: All functions and types declared in this file should be moved to separate package
// and be part of new module which will be responsible for communication with babylon chain i.e
// retrieving data from babylon chain, sending data to babylon chain, queuing data to be send etc.

const (
	BabylonPendingStatus  = "PENDING"
	BabylonVerifiedStatus = "VERIFIED"
	BabylonActiveStatus   = "ACTIVE"
	BabylonUnbondedStatus = "UNBONDED"
	BabylonExpiredStatus  = "EXPIRED"
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
	fpBtcPubkeys                []*btcec.PublicKey
	pop                         *cl.BabylonPop
	// expansion-specific fields
	prevActiveStkTxHash *chainhash.Hash
	fundingTx           *wire.MsgTx
}

// buildDelegation builds a delegation data for a given staker address, staking output index and staking time.
func (app *App) buildDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	stakingOutputIndex uint32,
	stakingTime uint16,
	storedTx *stakerdb.StoredTransaction,
) (*cl.DelegationData, error) {
	externalData, err := app.retrieveExternalDelegationData(stakerAddress, req.inclusionInfo)
	if err != nil {
		return nil, fmt.Errorf("error retrieving external delegation data: %w", err)
	}

	slashingFee := app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat)

	stakingSlashingTx, stakingSlashingSpendInfo, err := slashingTxForStakingTx(
		slashingFee,
		externalData,
		stakingOutputIndex,
		stakingTime,
		storedTx,
		req.fpBtcPubkeys,
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
		req.fpBtcPubkeys,
		stakingOutputIndex,
		app.network,
	)

	if err != nil {
		// TODO: Most probable couse for this error would be some kind of problem with fees
		return nil, fmt.Errorf("error creating undelegation data: %w", err)
	}

	stakingSlashingSig, err := app.signTaprootScriptSpendUsingWallet(
		stakingSlashingTx,
		storedTx.StakingTx.TxOut[stakingOutputIndex],
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

	// sanity check that all our transactions are standard
	// if they are not this can mean bug either in Babylon parameters or in Staker code
	if err := utils.CheckTransaction(stakingSlashingTx); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build staking slashing tx: %w", err)
	}
	if err := utils.CheckTransaction(undelegationDesc.UnbondingTransaction); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build unbonding tx: %w", err)
	}
	if err := utils.CheckTransaction(undelegationDesc.SlashUnbondingTransaction); err != nil {
		return nil, fmt.Errorf("failed to build delegation data: failed to build unbondingslashing tx: %w", err)
	}

	dg := createDelegationData(
		req,
		externalData.stakerPublicKey,
		stakingOutputIndex,
		stakingTime,
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
			di, err := app.babylonClient.QueryBTCDelegation(stakingTxHash)

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

			if di.BtcDelegation.UndelegationResponse == nil {
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

			undelegationInfo, err := app.babylonClient.GetUndelegationInfo(di)
			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"err":           err,
				}).Error("Error getting undelegation info from babylon")
				continue
			}

			// we have enough signatures to submit unbonding tx this means that delegation is active
			if len(undelegationInfo.CovenantUnbondingSignatures) >= int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(undelegationInfo.CovenantUnbondingSignatures),
				}).Debug("Received enough covenant unbonding signatures on babylon")

				if undelegationInfo.UnbondingTransaction == nil {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
					}).Error("No unbonding transaction on babylon")
					continue
				}

				req := &unbondingTxSignaturesConfirmedOnBabylonEvent{
					stakingTxHash:      *stakingTxHash,
					stakingOutputIndex: di.BtcDelegation.StakingOutputIdx,
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
					"numSignatures": len(undelegationInfo.CovenantUnbondingSignatures),
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

// signStakingTransaction signs a staking transaction, handling both regular staking
// and stake expansion transactions with different signing requirements
func (app *App) signStakingTransaction(tx *wire.MsgTx, stakingTxHash *chainhash.Hash) (*wire.MsgTx, error) {
	// Check if this is a stake expansion transaction (exactly 2 inputs)
	if len(tx.TxIn) == 2 {
		// This is likely a stake expansion transaction
		// Input 0: Previous staking output (taproot, needs special signing)
		// Input 1: Funding output (regular UTXO, can be signed normally)

		// Try to sign as stake expansion transaction
		return app.signStakeExpansionTransaction(tx, stakingTxHash)
	}

	// Regular staking transaction - use normal wallet signing
	signedTx, fullySigned, err := app.wc.SignRawTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign regular staking transaction: %w", err)
	}

	if !fullySigned {
		return nil, nil // Return nil to indicate signing failed
	}

	return signedTx, nil
}

// signStakeExpansionTransaction signs a stake expansion transaction with mixed input types
func (app *App) signStakeExpansionTransaction(tx *wire.MsgTx, stakingTxHash *chainhash.Hash) (*wire.MsgTx, error) {
	// Input 0: Previous staking output (taproot, needs unbonding path signing)
	// Input 1: Funding output (regular UTXO, can be signed normally)
	fundingOutpoint := tx.TxIn[1].PreviousOutPoint

	// Get delegation info for the expansion transaction
	di, err := app.babylonClient.QueryBTCDelegation(stakingTxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get delegation info for expansion transaction: %w", err)
	}

	// Verify this is a stake expansion transaction
	if di.BtcDelegation.StkExp == nil {
		return nil, fmt.Errorf("delegation is not a stake expansion")
	}

	// Get the funding transaction (we need it for validation but don't use it directly)
	fundingTx, err := app.wc.Tx(&fundingOutpoint.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get funding transaction: %w", err)
	}

	// Get the previous staking transaction
	prevStakingHash, err := chainhash.NewHashFromStr(di.BtcDelegation.StkExp.PreviousStakingTxHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous staking transaction hash: %w", err)
	}
	prevStakingTx, err := app.wc.Tx(prevStakingHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous staking transaction: %w", err)
	}

	// Check if we have covenant signatures for stake expansion
	params, err := app.babylonClient.Params()
	if err != nil {
		return nil, fmt.Errorf("failed to get babylon params: %w", err)
	}

	// For stake expansion, we need to check both:
	// 1. PreviousStkCovenantSigs - for spending the previous staking output
	// 2. Regular covenant unbonding signatures - for the new staking transaction

	if len(di.BtcDelegation.StkExp.PreviousStkCovenantSigs) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("not enough previous staking covenant signatures for stake expansion: have %d, need %d",
			len(di.BtcDelegation.StkExp.PreviousStkCovenantSigs), params.CovenantQuruomThreshold)
	}

	// Also check if we have regular covenant unbonding signatures for the expansion delegation
	undelegationInfo, err := app.babylonClient.GetUndelegationInfo(di)
	if err != nil {
		return nil, fmt.Errorf("failed to get undelegation info for expansion: %w", err)
	}

	if len(undelegationInfo.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("not enough covenant unbonding signatures for stake expansion: have %d, need %d",
			len(undelegationInfo.CovenantUnbondingSignatures), params.CovenantQuruomThreshold)
	}

	// Get the previous delegation info to build the correct unbonding spend info
	// The covenant signatures were created using the PREVIOUS delegation's parameters
	prevDelegationResult, err := app.babylonClient.QueryBTCDelegation(prevStakingHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous delegation: %w", err)
	}

	if prevDelegationResult.BtcDelegation == nil {
		return nil, fmt.Errorf("previous delegation not found")
	}

	prevDel := prevDelegationResult.BtcDelegation

	// Step 1: Sign the funding input (regular UTXO) using normal wallet signing
	// Create a temporary transaction with only the funding input from the expansion tx
	tempTx := wire.NewMsgTx(tx.Version)
	tempTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: fundingOutpoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         tx.TxIn[1].Sequence,
	})

	// Add all outputs to the temporary transaction
	for _, output := range tx.TxOut {
		tempTx.AddTxOut(output)
	}

	// Sign the funding input
	signedFundingTx, fullySigned, err := app.wc.SignRawTransaction(tempTx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign funding input: %w", err)
	}

	if !fullySigned {
		return nil, fmt.Errorf("failed to fully sign funding input")
	}

	// Step 2: Sign the taproot input (previous staking output) using unbonding path
	// First, get the staker address and public key from the stored transaction
	_, stakerAddress := app.mustGetTransactionAndStakerAddress(stakingTxHash)

	stakerPubKey, err := app.wc.AddressPublicKey(stakerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get staker public key: %w", err)
	}

	// Get finality provider public keys from the PREVIOUS delegation
	// The covenant signatures were created using the PREVIOUS delegation's parameters
	prevFpBtcPubkeys, err := convertFpBtcPkToBtcPk(prevDel.FpBtcPkList)
	if err != nil {
		return nil, fmt.Errorf("failed to convert previous fp btc pubkeys: %w", err)
	}

	// Build the unbonding spend info using the PREVIOUS delegation's parameters
	// This matches how the covenant signatures were created in the test manager
	prevStakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		prevFpBtcPubkeys,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		uint16(prevDel.StakingTime),
		btcutil.Amount(prevDel.TotalSat),
		app.network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build previous staking info: %w", err)
	}

	prevStkUnbondingSpendInfo, err := prevStakingInfo.UnbondingPathSpendInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get unbonding spend info: %w", err)
	}

	// Use the new two-input signing method that matches the covenant signature approach
	twoInputReq := &walletcontroller.TwoInputTaprootSigningRequest{
		TxToSign:      tx,                                                     // Complete two-input transaction
		StakingOutput: prevStakingTx.MsgTx().TxOut[prevDel.StakingOutputIdx], // Input 0: Previous staking output
		FundingOutput: fundingTx.MsgTx().TxOut[fundingOutpoint.Index],         // Input 1: Funding output
		SignerAddress: stakerAddress,
		SpendDescription: &walletcontroller.SpendPathDescription{
			ScriptLeaf:   &prevStkUnbondingSpendInfo.RevealedLeaf,
			ControlBlock: &prevStkUnbondingSpendInfo.ControlBlock,
		},
	}

	stakerSig, err := app.wc.SignTwoInputTaprootSpendingTransaction(twoInputReq)
	if err != nil {
		return nil, fmt.Errorf("failed to sign taproot input: %w", err)
	}

	if stakerSig.Signature == nil {
		return nil, fmt.Errorf("failed to get taproot signature")
	}

	var prevStkCovSigs []cl.CovenantSignatureInfo
	for _, covSigInfo := range di.BtcDelegation.StkExp.PreviousStkCovenantSigs {
		covSig := covSigInfo
		sig, err := covSig.Sig.ToBTCSig()
		if err != nil {
			return nil, fmt.Errorf("failed to get covenant signature: %w", err)
		}

		pk, err := covSig.Pk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("failed to get covenant public key: %w", err)
		}

		sigInfo := cl.CovenantSignatureInfo{
			Signature: sig,
			PubKey:    pk,
		}
		prevStkCovSigs = append(prevStkCovSigs, sigInfo)
	}

	// Create covenant signatures witness using the stake expansion signatures
	covenantSignatures, err := createWitnessSignaturesForPubKeys(
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		prevStkCovSigs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create covenant signatures: %w", err)
	}

	// Build the unbondWitness for the taproot input
	unbondWitness, err := prevStkUnbondingSpendInfo.CreateUnbondingPathWitness(
		covenantSignatures,
		stakerSig.Signature,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create unbonding path witness: %w", err)
	}

	// Step 3: Add both signatures into the final transaction
	tx.TxIn[0].Witness = unbondWitness
	// Copy the signed funding input's signature and witness
	tx.TxIn[1].SignatureScript = signedFundingTx.TxIn[0].SignatureScript
	tx.TxIn[1].Witness = signedFundingTx.TxIn[0].Witness

	return tx, nil
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
			di, err := app.babylonClient.QueryBTCDelegation(stakingTxHash)
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
			if di.BtcDelegation.Active {
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

				utils.PushOrQuit[*delegationActivatedEvent](
					app.delegationActivatedEvChan,
					&delegationActivatedEvent{
						stakingTxHash: *stakingTxHash,
						blockHash:     *info.BlockHash,
						blockHeight:   info.BlockHeight,
					},
					app.quit,
				)
				return
			}

			udi, err := app.babylonClient.GetUndelegationInfo(di)
			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"err":           err,
				}).Error("error getting undelegation info from babylon")
				continue
			}

			if len(udi.CovenantUnbondingSignatures) < int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(udi.CovenantUnbondingSignatures),
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
			signedTx, err := app.signStakingTransaction(stakingTransaction, stakingTxHash)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"err":           err,
					"stakingTxHash": stakingTxHash,
				}).Error("failed to sign staking transaction")
				continue
			}

			if signedTx == nil {
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

// newSendDelegationRequest builds a sendDelegationRequest
func newSendDelegationRequest(
	btcStakingTxHash *chainhash.Hash,
	inclusionInfo *inclusionInfo,
	requiredInclusionBlockDepth uint32,
	fpBtcPubkeys []*secp256k1.PublicKey,
	pop *cl.BabylonPop,
) *sendDelegationRequest {
	return &sendDelegationRequest{
		btcTxHash:                   *btcStakingTxHash,
		inclusionInfo:               inclusionInfo,
		requiredInclusionBlockDepth: requiredInclusionBlockDepth,
		fpBtcPubkeys:                fpBtcPubkeys,
		pop:                         pop,
	}
}

// newSendDelegationExpansionRequest builds a sendDelegationRequest for stake expansion
func newSendDelegationExpansionRequest(
	btcStakingTxHash *chainhash.Hash,
	requiredInclusionBlockDepth uint32,
	fpBtcPubkeys []*secp256k1.PublicKey,
	pop *cl.BabylonPop,
	prevActiveStkTxHash *chainhash.Hash,
	fundingTx *wire.MsgTx,
) *sendDelegationRequest {
	return &sendDelegationRequest{
		btcTxHash:                   *btcStakingTxHash,
		requiredInclusionBlockDepth: requiredInclusionBlockDepth,
		fpBtcPubkeys:                fpBtcPubkeys,
		pop:                         pop,
		prevActiveStkTxHash:         prevActiveStkTxHash,
		fundingTx:                   fundingTx,
	}
}
