package walletcontroller

import (
	"bytes"
	"fmt"

	staking "github.com/babylonlabs-io/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// copy from https://github.com/babylonlabs-io/babylon/blob/b6635c95fa1ad4018af74152140abd71c8e4a05e/btcstaking/identifiable_staking.go#L376
// one a new tag of main is made, update go mod import and load it from there.

// ParseV0StakingTxWithoutTag takes a btc transaction and checks whether it is a staking transaction and if so parses it
// for easy data retrieval.
// It does all necessary checks to ensure that the transaction is valid staking transaction.
func ParseV0StakingTxWithoutTag(
	tx *wire.MsgTx,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	net *chaincfg.Params,
) (*staking.ParsedV0StakingTx, error) {
	// 1. Basic arguments checks
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}

	if len(covenantKeys) == 0 {
		return nil, fmt.Errorf("no covenant keys specified")
	}

	if int(covenantQuorum) > len(covenantKeys) {
		return nil, fmt.Errorf("covenant quorum is greater than the number of covenant keys")
	}

	// 2. Identify whether the transaction has expected shape
	if len(tx.TxOut) < 2 {
		return nil, fmt.Errorf("staking tx must have at least 2 outputs")
	}

	opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)

	if err != nil {
		return nil, fmt.Errorf("cannot parse staking transaction: %w", err)
	}

	if opReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected op return output")
	}

	if opReturnData.Version != 0 {
		return nil, fmt.Errorf("unexpected version: %d, expected: %d", opReturnData.Version, 0)
	}

	// 3. Op return seems to be valid V0 op return output. Now, we need to check whether
	// the staking output exists and is valid.
	stakingInfo, err := staking.BuildStakingInfo(
		opReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{opReturnData.FinalityProviderPublicKey.PubKey},
		covenantKeys,
		covenantQuorum,
		opReturnData.StakingTime,
		// we can pass 0 here, as staking amount is not used when creating taproot address
		0,
		net,
	)

	if err != nil {
		return nil, fmt.Errorf("cannot build staking info: %w", err)
	}

	stakingOutput, stakingOutputIdx, err := tryToGetStakingOutput(tx.TxOut, stakingInfo.StakingOutput.PkScript)

	if err != nil {
		return nil, fmt.Errorf("cannot parse staking transaction: %w", err)
	}

	if stakingOutput == nil {
		return nil, fmt.Errorf("staking output not found in potential staking transaction")
	}

	return &staking.ParsedV0StakingTx{
		StakingOutput:     stakingOutput,
		StakingOutputIdx:  stakingOutputIdx,
		OpReturnOutput:    tx.TxOut[opReturnOutputIdx],
		OpReturnOutputIdx: opReturnOutputIdx,
		OpReturnData:      opReturnData,
	}, nil
}

func tryToGetOpReturnDataFromOutputs(outputs []*wire.TxOut) (*staking.V0OpReturnData, int, error) {
	// lack of outputs is not an error
	if len(outputs) == 0 {
		return nil, -1, nil
	}

	var opReturnData *staking.V0OpReturnData
	var opReturnOutputIdx int

	for i, o := range outputs {
		output := o
		d, err := staking.NewV0OpReturnDataFromTxOutput(output)

		if err != nil {
			// this is not an op return output recognized by Babylon, move forward
			continue
		}
		// this case should not happen as standard bitcoin node propagation rules
		// disallow multiple op return outputs in a single transaction. However, miner could
		// include multiple op return outputs in a single transaction. In such case, we should
		// return an error.
		if opReturnData != nil {
			return nil, -1, fmt.Errorf("multiple op return outputs found")
		}

		opReturnData = d
		opReturnOutputIdx = i
	}

	return opReturnData, opReturnOutputIdx, nil
}

func tryToGetStakingOutput(outputs []*wire.TxOut, stakingOutputPkScript []byte) (*wire.TxOut, int, error) {
	// lack of outputs is not an error
	if len(outputs) == 0 {
		return nil, -1, nil
	}

	var stakingOutput *wire.TxOut
	var stakingOutputIdx int

	for i, o := range outputs {
		output := o

		if !bytes.Equal(output.PkScript, stakingOutputPkScript) {
			// this is not the staking output we are looking for
			continue
		}

		if stakingOutput != nil {
			// we only allow for one staking output per transaction
			return nil, -1, fmt.Errorf("multiple staking outputs found")
		}

		stakingOutput = output
		stakingOutputIdx = i
	}

	return stakingOutput, stakingOutputIdx, nil
}
