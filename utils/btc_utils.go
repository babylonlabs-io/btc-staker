package utils

import (
	"fmt"

	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	minTransactionSize = 65
)

// Perform subset of transactions standard tests:
// - whether transaction is not considered dust
// - whether transactions is not too small
func CheckTransaction(tx *wire.MsgTx) error {
	if tx.SerializeSizeStripped() < minTransactionSize {
		return fmt.Errorf("transaction is too small. Tx size: %d, min size: %d", tx.SerializeSizeStripped(), minTransactionSize)
	}

	numOpReturns := 0
	for _, txOut := range tx.TxOut {
		scriptClass := txscript.GetScriptClass(txOut.PkScript)
		if scriptClass == txscript.NullDataTy {
			numOpReturns++
		} else if mempool.IsDust(txOut, mempool.DefaultMinRelayTxFee) {
			return fmt.Errorf("transaction output is dust. Value: %d", txOut.Value)
		}
	}

	if numOpReturns > 1 {
		return fmt.Errorf("transaction has more than one op_return output")
	}

	return nil
}
