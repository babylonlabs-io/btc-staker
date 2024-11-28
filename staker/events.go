package staker

import (
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

type StakingEvent interface {
	EventID() chainhash.Hash // Each staking event is identified by initial staking transaction hash
	EventDesc() string
}

var _ StakingEvent = (*stakingTxBtcConfirmedEvent)(nil)
var _ StakingEvent = (*delegationSubmittedToBabylonEvent)(nil)
var _ StakingEvent = (*delegationActivatedPostApprovalEvent)(nil)
var _ StakingEvent = (*delegationActivatedPreApprovalEvent)(nil)
var _ StakingEvent = (*unbondingTxSignaturesConfirmedOnBabylonEvent)(nil)
var _ StakingEvent = (*unbondingTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*spendStakeTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*criticalErrorEvent)(nil)

type stakingTxBtcConfirmedEvent struct {
	stakingTxHash chainhash.Hash
	txIndex       uint32
	blockDepth    uint32
	blockHash     chainhash.Hash
	blockHeight   uint32
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

func (event *stakingTxBtcConfirmedEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *stakingTxBtcConfirmedEvent) EventDesc() string {
	return "STAKING_TX_BTC_CONFIRMED"
}

type delegationSubmittedToBabylonEvent struct {
	stakingTxHash              chainhash.Hash
	babylonBTCDelegationTxHash string
	unbondingTx                *wire.MsgTx
	unbondingTime              uint16
}

func (event *delegationSubmittedToBabylonEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *delegationSubmittedToBabylonEvent) EventDesc() string {
	return "DELEGATION_SUBMITTED_TO_BABYLON"
}

type unbondingTxSignaturesConfirmedOnBabylonEvent struct {
	stakingTxHash               chainhash.Hash
	delegationActive            bool
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

type delegationActivatedPostApprovalEvent struct {
	stakingTxHash chainhash.Hash
}

func (event *delegationActivatedPostApprovalEvent) EventID() chainhash.Hash {
	return event.stakingTxHash
}

func (event *delegationActivatedPostApprovalEvent) EventDesc() string {
	return "DELEGATION_ACTIVE_ON_BABYLON_POST_APPROVAL_EVENT"
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
