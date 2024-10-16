package walletcontroller

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
)

type TxStatus int

const (
	TxNotFound TxStatus = iota
	TxInMemPool
	TxInChain
)

type SpendPathDescription struct {
	ControlBlock *txscript.ControlBlock
	ScriptLeaf   *txscript.TapLeaf
}

type TaprootSigningRequest struct {
	FundingOutput    *wire.TxOut
	TxToSign         *wire.MsgTx
	SignerAddress    btcutil.Address
	SpendDescription *SpendPathDescription
}

// TaprootSigningResult contains result of signing taproot spend through bitcoind
// wallet. It will contain either Signature or FullInputWitness, never both.
type TaprootSigningResult struct {
	Signature        *schnorr.Signature
	FullInputWitness wire.TxWitness
}

// Function to filer utxos that should be used in transaction creation
type UseUtxoFn func(utxo Utxo) bool

type WalletController interface {
	UnlockWallet(timeoutSecs int64) error
	AddressPublicKey(address btcutil.Address) (*btcec.PublicKey, error)
	ImportPrivKey(privKeyWIF *btcutil.WIF) error
	NetworkName() string
	// passning nil usedUtxoFilter will use all possible spendable utxos to choose
	// inputs
	CreateTransaction(
		outputs []*wire.TxOut,
		feeRatePerKb btcutil.Amount,
		changeScript btcutil.Address,
		usedUtxoFilter UseUtxoFn,
	) (*wire.MsgTx, error)
	SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error)
	// requires wallet to be unlocked
	// passning nil usedUtxoFilter will use all possible spendable utxos to choose
	// inputs
	CreateAndSignTx(
		outputs []*wire.TxOut,
		feeRatePerKb btcutil.Amount,
		changeAddress btcutil.Address,
		usedUtxoFilter UseUtxoFn,
	) (*wire.MsgTx, error)
	SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error)
	ListOutputs(onlySpendable bool) ([]Utxo, error)
	TxDetails(txHash *chainhash.Hash, pkScript []byte) (*notifier.TxConfirmation, TxStatus, error)
	SignBip322NativeSegwit(msg []byte, address btcutil.Address) (wire.TxWitness, error)
	// SignOneInputTaprootSpendingTransaction signs transactions with one taproot input that
	// uses script spending path.
	SignOneInputTaprootSpendingTransaction(req *TaprootSigningRequest) (*TaprootSigningResult, error)
	OutputSpent(
		txHash *chainhash.Hash,
		outputIdx uint32,
	) (bool, error)
}
