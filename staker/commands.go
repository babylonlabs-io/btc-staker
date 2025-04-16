package staker

import (
	staking "github.com/babylonlabs-io/babylon/btcstaking"
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// we can make command to implement StakingEvent interface
var _ StakingEvent = (*stakingRequestCmd)(nil)

// sendDelegationRequestCmd represents a command to send a delegation request
type stakingRequestCmd struct {
	stakerAddress           btcutil.Address
	stakingOutput           *wire.TxOut
	feeRate                 chainfee.SatPerKVByte
	stakingTime             uint16
	stakingValue            btcutil.Amount
	fpBtcPks                []*btcec.PublicKey
	requiredDepthOnBtcChain uint32
	pop                     *cl.BabylonPop
	errChan                 chan error
	successChan             chan *chainhash.Hash
}

// newOwnedStakingCommand builds a new staking command
func newOwnedStakingCommand(
	stakerAddress btcutil.Address,
	stakingOutput *wire.TxOut,
	feeRate chainfee.SatPerKVByte,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpBtcPks []*btcec.PublicKey,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
) *stakingRequestCmd {
	return &stakingRequestCmd{
		stakerAddress:           stakerAddress,
		stakingOutput:           stakingOutput,
		feeRate:                 feeRate,
		stakingTime:             stakingTime,
		stakingValue:            stakingValue,
		fpBtcPks:                fpBtcPks,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		errChan:                 make(chan error, 1),
		successChan:             make(chan *chainhash.Hash, 1),
	}
}

// EventID returns the ID of the event
func (req *stakingRequestCmd) EventID() chainhash.Hash {
	// we do not have has for this event
	return chainhash.Hash{}
}

// EventDesc returns the description of the event
func (req *stakingRequestCmd) EventDesc() string {
	return "STAKING_REQUESTED_CMD"
}

// migrateStakingCmd represents a command to migrate a staking transaction
type migrateStakingCmd struct {
	stakerAddr        btcutil.Address
	notifierTx        *notifier.TxConfirmation
	parsedStakingTx   *staking.ParsedV0StakingTx
	pop               *cl.BabylonPop
	errChan           chan error
	successChanTxHash chan string
}

// newMigrateStakingCmd builds a new migrate staking command
func newMigrateStakingCmd(
	stakerAddr btcutil.Address,
	notifierTx *notifier.TxConfirmation,
	parsedStakingTx *staking.ParsedV0StakingTx,
	pop *cl.BabylonPop,
) *migrateStakingCmd {
	return &migrateStakingCmd{
		stakerAddr:        stakerAddr,
		notifierTx:        notifierTx,
		parsedStakingTx:   parsedStakingTx,
		pop:               pop,
		errChan:           make(chan error, 1),
		successChanTxHash: make(chan string, 1),
	}
}
