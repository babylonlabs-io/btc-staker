package staker

import (
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/sirupsen/logrus"
)

type StakingEvent interface {
	EventID() chainhash.Hash // Each staking event is identified by initial staking transaction hash
	EventDesc() string
}

var _ StakingEvent = (*delegationActivatedPreApprovalEvent)(nil)
var _ StakingEvent = (*unbondingTxSignaturesConfirmedOnBabylonEvent)(nil)
var _ StakingEvent = (*unbondingTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*spendStakeTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*criticalErrorEvent)(nil)

type unbondingTxSignaturesConfirmedOnBabylonEvent struct {
	stakingTxHash               chainhash.Hash
	covenantUnbondingSignatures []cl.CovenantSignatureInfo
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventDesc() string {
	return "UNBONDING_TX_SIGNATURES_CONFIRMED_ON_BABYLON"
}

type unbondingTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
	blockHash     chainhash.Hash
	blockHeight   uint32
}

func (event *unbondingTxConfirmedOnBtcEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *unbondingTxConfirmedOnBtcEvent) EventDesc() string {
	return "UNBONDING_TX_CONFIRMED_ON_BTC"
}

type spendStakeTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventDesc() string {
	return "SPEND_STAKE_TX_CONFIRMED_ON_BTC"
}

type criticalErrorEvent struct {
	stakingTxHash     chainhash.Hash
	err               error
	additionalContext string
}

func (event *criticalErrorEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *criticalErrorEvent) EventDesc() string {
	return "CRITICAL_ERROR"
}

func (app *App) logStakingEventReceived(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventID(),
		"event":   event.EventDesc(),
	}).Debug("Received staking event")
}

func (app *App) logStakingEventProcessed(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventID(),
		"event":   event.EventDesc(),
	}).Debug("Processed staking event")
}

type delegationActivatedPreApprovalEvent struct {
	stakingTxHash chainhash.Hash
	blockHash     chainhash.Hash
	blockHeight   uint32
}

func (event *delegationActivatedPreApprovalEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *delegationActivatedPreApprovalEvent) EventDesc() string {
	return "DELEGATION_ACTIVE_ON_BABYLON_PRE_APPROVAL_EVENT"
}
