package staker

import (
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// we can make command to implement StakingEvent interface
var _ StakingEvent = (*stakingRequestCmd)(nil)

type stakingRequestCmd struct {
	stakerAddress           btcutil.Address
	stakingOutput           *wire.TxOut
	feeRate                 chainfee.SatPerKVByte
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
	stakingOutput *wire.TxOut,
	feeRate chainfee.SatPerKVByte,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	fpBtcPks []*btcec.PublicKey,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
	usePreApprovalFlow bool,
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
		watchTxData:             nil,
		usePreApprovalFlow:      usePreApprovalFlow,
		errChan:                 make(chan error, 1),
		successChan:             make(chan *chainhash.Hash, 1),
	}
}

type watchTxDataCmd struct {
	// watched tx data
	stakingTxHash         chainhash.Hash
	stakingTx             *wire.MsgTx
	stakingOutputIdx      uint32
	stakingOutputPkScript []byte

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
		stakingTime:             stakingTime,
		stakingValue:            stakingValue,
		fpBtcPks:                fpBtcPks,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		watchTxData: &watchTxDataCmd{
			stakingTxHash:         stakingTx.TxHash(),
			stakingTx:             stakingTx,
			stakingOutputIdx:      stakingOutputIdx,
			stakingOutputPkScript: stakingOutputPkScript,
			slashingTx:            slashingTx,
			slashingTxSig:         slashingTxSignature,
			stakerBabylonAddr:     stakerBabylonAddr,
			stakerBtcPk:           stakerBtcPk,
			unbondingTx:           unbondingTx,
			slashUnbondingTx:      slashUnbondingTx,
			slashUnbondingTxSig:   slashUnbondingTxSig,
			unbondingTime:         unbondingTime,
		},
		errChan:     make(chan error, 1),
		successChan: make(chan *chainhash.Hash, 1),
	}
}

func (req *stakingRequestCmd) EventId() chainhash.Hash {
	// we do not have has for this event
	return chainhash.Hash{}
}

func (req *stakingRequestCmd) EventDesc() string {
	return "STAKING_REQUESTED_CMD"
}
