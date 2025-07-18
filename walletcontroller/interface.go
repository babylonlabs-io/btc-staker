package walletcontroller

import (
	"fmt"

	staking "github.com/babylonlabs-io/babylon/v3/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	notifier "github.com/lightningnetwork/lnd/chainntnfs"
)

type TxStatus int

const (
	TxNotFound TxStatus = iota
	TxInMemPool
	TxInChain
)

func (ts TxStatus) String() string {
	switch ts {
	case TxNotFound:
		return "TxNotFound"
	case TxInMemPool:
		return "TxInMemPool"
	case TxInChain:
		return "TxInChain"
	default:
		return fmt.Sprintf("UnknownTxStatus(%d)", int(ts))
	}
}

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

type TwoInputTaprootSigningRequest struct {
	TxToSign         *wire.MsgTx           // The two-input transaction to sign
	StakingOutput    *wire.TxOut           // Input 0: Previous staking output (taproot)
	FundingOutput    *wire.TxOut           // Input 1: Funding output
	SignerAddress    btcutil.Address       // Address that controls the staking output
	SpendDescription *SpendPathDescription // Script path for spending the staking output
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
	// passing nil usedUtxoFilter will use all possible spendable utxos to choose
	// inputs
	CreateTransaction(
		outputs []*wire.TxOut,
		feeRatePerKb btcutil.Amount,
		changeScript btcutil.Address,
		usedUtxoFilter UseUtxoFn,
	) (*wire.MsgTx, error)
	// CreateTransactionWithInputs creates a transaction with specified number of inputs
	// and ensures required inputs are included
	CreateTransactionWithInputs(
		requiredInputs []wire.OutPoint,
		inputsCount int,
		outputs []*wire.TxOut,
		feeRatePerKb btcutil.Amount,
		changeAddress btcutil.Address,
		useUtxoFn UseUtxoFn,
	) (*wire.MsgTx, error)
	SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error)
	// requires wallet to be unlocked
	// passing nil usedUtxoFilter will use all possible spendable utxos to choose
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
	Tx(txHash *chainhash.Hash) (*btcutil.Tx, error)
	TxVerbose(txHash *chainhash.Hash) (*btcjson.TxRawResult, error)
	BlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error)
	// SignBip322Signature signs arbitrary message using bip322 signing scheme.
	// Works only for:
	// - native segwit addresses
	// - taproot addresses with no script spending path (https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
	SignBip322Signature(msg []byte, address btcutil.Address) (wire.TxWitness, error)
	// SignOneInputTaprootSpendingTransaction signs transactions with one taproot input that
	// uses script spending path.
	SignOneInputTaprootSpendingTransaction(req *TaprootSigningRequest) (*TaprootSigningResult, error)
	// SignTwoInputTaprootSpendingTransaction signs the first input of a two-input transaction
	// using the same method as Babylon's SignTxForFirstScriptSpendWithTwoInputsFromTapLeaf
	SignTwoInputTaprootSpendingTransaction(req *TwoInputTaprootSigningRequest) (*TaprootSigningResult, error)
	OutputSpent(
		txHash *chainhash.Hash,
		outputIdx uint32,
	) (bool, error)
}

func StkTxV0ParsedWithBlock(
	wc WalletController,
	btcNetwork *chaincfg.Params,
	stkTxHash *chainhash.Hash,
	covenantPks []*secp256k1.PublicKey,
	covenantQuorum uint32,
) (*staking.ParsedV0StakingTx, *notifier.TxConfirmation, TxStatus, error) {
	stkTx, err := wc.Tx(stkTxHash)
	if err != nil {
		return nil, nil, TxNotFound, err
	}

	wireStkTx := stkTx.MsgTx()
	parsedStakingTx, err := ParseV0StakingTxWithoutTag(wireStkTx, covenantPks, covenantQuorum, btcNetwork)
	if err != nil {
		return nil, nil, TxNotFound, err
	}

	notifierTx, status, err := wc.TxDetails(stkTxHash, parsedStakingTx.StakingOutput.PkScript)
	if err != nil {
		return nil, nil, TxNotFound, err
	}

	return parsedStakingTx, notifierTx, status, nil
}
