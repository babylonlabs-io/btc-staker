package staker

import (
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// we can make command to implement StakingEvent interface
var _ StakingEvent = (*stakingRequestCmd)(nil)

type stakingRequestCmd struct {
	stakerAddress           btcutil.Address
	stakingTxHash           chainhash.Hash
	stakingTx               *wire.MsgTx
	stakingOutputIdx        uint32
	stakingOutputPkScript   []byte
	stakingTime             uint16
	stakingValue            btcutil.Amount
	fpBtcPks                []*btcec.PublicKey
	requiredDepthOnBtcChain uint32
	pop                     *cl.BabylonPop
	watchTxData             *watchTxDataCmd
	usePreApprovalFlow      bool
	errChan                 chan error
	successChan             chan *chainhash.Hash
}

func (req *stakingRequestCmd) isWatched() bool {
	return req.watchTxData != nil
}

func newOwnedStakingCommand(
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpBtcPks []*btcec.PublicKey,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
	usePreApprovalFlow bool,
) *stakingRequestCmd {
	return &stakingRequestCmd{
		stakerAddress:           stakerAddress,
		stakingTxHash:           stakingTx.TxHash(),
		stakingTx:               stakingTx,
		stakingOutputIdx:        stakingOutputIdx,
		stakingOutputPkScript:   stakingOutputPkScript,
		stakingTime:             stakingTime,
		stakingValue:            stakingValue,
		fpBtcPks:                fpBtcPks,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		watchTxData:             nil,
		usePreApprovalFlow:      usePreApprovalFlow,
		errChan:                 make(chan error, 1),
		successChan:             make(chan *chainhash.Hash, 1),
	}
}

type watchTxDataCmd struct {
	slashingTx        *wire.MsgTx
	slashingTxSig     *schnorr.Signature
	stakerBabylonAddr sdk.AccAddress
	stakerBtcPk       *btcec.PublicKey
	// unbonding related data
	unbondingTx         *wire.MsgTx
	slashUnbondingTx    *wire.MsgTx
	slashUnbondingTxSig *schnorr.Signature
	unbondingTime       uint16
}

func newWatchedStakingCmd(
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpBtcPks []*btcec.PublicKey,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	stakerBabylonAddr sdk.AccAddress,
	stakerBtcPk *btcec.PublicKey,
	unbondingTx *wire.MsgTx,
	slashUnbondingTx *wire.MsgTx,
	slashUnbondingTxSig *schnorr.Signature,
	unbondingTime uint16,
) *stakingRequestCmd {
	return &stakingRequestCmd{
		stakerAddress:           stakerAddress,
		stakingTxHash:           stakingTx.TxHash(),
		stakingTx:               stakingTx,
		stakingOutputIdx:        stakingOutputIdx,
		stakingOutputPkScript:   stakingOutputPkScript,
		stakingTime:             stakingTime,
		stakingValue:            stakingValue,
		fpBtcPks:                fpBtcPks,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		watchTxData: &watchTxDataCmd{
			slashingTx:          slashingTx,
			slashingTxSig:       slashingTxSignature,
			stakerBabylonAddr:   stakerBabylonAddr,
			stakerBtcPk:         stakerBtcPk,
			unbondingTx:         unbondingTx,
			slashUnbondingTx:    slashUnbondingTx,
			slashUnbondingTxSig: slashUnbondingTxSig,
			unbondingTime:       unbondingTime,
		},
		errChan:     make(chan error, 1),
		successChan: make(chan *chainhash.Hash, 1),
	}
}

func (event *stakingRequestCmd) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *stakingRequestCmd) EventDesc() string {
	return "STAKING_REQUESTED_CMD"
}
