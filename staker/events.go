package staker

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/sirupsen/logrus"
)

// StakingEvent describes an internal event generated while monitoring Babylon or
// Bitcoin state transitions for a delegation.
type StakingEvent interface {
	EventID() chainhash.Hash // Each staking event is identified by initial staking transaction hash
	EventDesc() string
}

var _ StakingEvent = (*unbondingTxSignaturesConfirmedOnBabylonEvent)(nil)
var _ StakingEvent = (*delegationActivatedEvent)(nil)
var _ StakingEvent = (*unbondingTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*spendStakeTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*criticalErrorEvent)(nil)

// unbondingTxSignaturesConfirmedOnBabylonEvent represents an event when
// unbonding tx signatures are confirmed on Babylon
type unbondingTxSignaturesConfirmedOnBabylonEvent struct {
	stakingTxHash      chainhash.Hash
	stakingOutputIndex uint32
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventDesc() string {
	return "UNBONDING_TX_SIGNATURES_CONFIRMED_ON_BABYLON"
}

// delegationActivatedEvent represents an event when
// a delegation is activated on Babylon
type delegationActivatedEvent struct {
	stakingTxHash chainhash.Hash
	blockHash     chainhash.Hash
	blockHeight   uint32
}

func (event *delegationActivatedEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *delegationActivatedEvent) EventDesc() string {
	return "DELEGATION_ACTIVE_ON_BABYLON"
}

// unbondingTxConfirmedOnBtcEvent represents an event when
// unbonding tx is confirmed on Bitcoin
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

// spendStakeTxConfirmedOnBtcEvent represents an event when
// spend stake tx is confirmed on Bitcoin
type spendStakeTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventDesc() string {
	return "SPEND_STAKE_TX_CONFIRMED_ON_BTC"
}

// criticalErrorEvent represents an event when critical error occurs
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

// logStakingEventReceived logs a received staking event
func (app *App) logStakingEventReceived(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventID(),
		"event":   event.EventDesc(),
	}).Debug("Received staking event")
}

// logStakingEventProcessed logs a processed staking event
func (app *App) logStakingEventProcessed(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventID(),
		"event":   event.EventDesc(),
	}).Debug("Processed staking event")
}
