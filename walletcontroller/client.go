package walletcontroller

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/babylonlabs-io/babylon/crypto/bip322"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
)

type RPCWalletController struct {
	*rpcclient.Client
	walletPassphrase string
	network          string
	backend          types.SupportedWalletBackend
}

var _ WalletController = (*RPCWalletController)(nil)

const (
	txNotFoundErrMsgBtcd     = "No information available about transaction"
	txNotFoundErrMsgBitcoind = "No such mempool or blockchain transaction"
)

func NewRPCWalletController(scfg *stakercfg.Config) (*RPCWalletController, error) {
	return NewRPCWalletControllerFromArgs(
		scfg.WalletRPCConfig.Host,
		scfg.WalletRPCConfig.User,
		scfg.WalletRPCConfig.Pass,
		scfg.ActiveNetParams.Name,
		scfg.WalletConfig.WalletName,
		scfg.WalletConfig.WalletPass,
		scfg.BtcNodeBackendConfig.ActiveWalletBackend,
		&scfg.ActiveNetParams,
		scfg.WalletRPCConfig.DisableTLS,
		scfg.WalletRPCConfig.RawRPCWalletCert,
		scfg.WalletRPCConfig.RPCWalletCert,
	)
}

func NewRPCWalletControllerFromArgs(
	host string,
	user string,
	pass string,
	network string,
	walletName string,
	walletPassphrase string,
	nodeBackend types.SupportedWalletBackend,
	params *chaincfg.Params,
	disableTLS bool,
	rawWalletCert string, walletCertFilePath string,
) (*RPCWalletController, error) {
	connCfg := &rpcclient.ConnConfig{
		Host:                 rpcHostURL(host, walletName),
		User:                 user,
		Pass:                 pass,
		DisableTLS:           disableTLS,
		DisableConnectOnNew:  true,
		DisableAutoReconnect: false,
		// we use post mode as it sure it works with either bitcoind or btcwallet
		// we may need to re-consider it later if we need any notifications
		HTTPPostMode: true,
	}

	if !connCfg.DisableTLS {
		cert, err := stakercfg.ReadCertFile(rawWalletCert, walletCertFilePath)
		if err != nil {
			return nil, err
		}
		connCfg.Certificates = cert
	}

	rpcclient, err := rpcclient.New(connCfg, nil)
	if err != nil {
		return nil, err
	}

	return &RPCWalletController{
		Client:           rpcclient,
		walletPassphrase: walletPassphrase,
		network:          params.Name,
		backend:          nodeBackend,
	}, nil
}

func rpcHostURL(host, walletName string) string {
	if len(walletName) > 0 {
		return host + "/wallet/" + walletName
	}
	return host
}

func (w *RPCWalletController) UnlockWallet(timoutSec int64) error {
	return w.WalletPassphrase(w.walletPassphrase, timoutSec)
}

func (w *RPCWalletController) AddressPublicKey(address btcutil.Address) (*btcec.PublicKey, error) {
	encoded := address.EncodeAddress()

	info, err := w.GetAddressInfo(encoded)

	if err != nil {
		return nil, err
	}

	if info.PubKey == nil {
		return nil, fmt.Errorf("address %s has no public key", encoded)
	}

	decodedHex, err := hex.DecodeString(*info.PubKey)

	if err != nil {
		return nil, err
	}

	return btcec.ParsePubKey(decodedHex)
}

func (w *RPCWalletController) NetworkName() string {
	return w.network
}

func (w *RPCWalletController) CreateTransaction(
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeAddres btcutil.Address,
	useUtxoFn UseUtxoFn,
) (*wire.MsgTx, error) {
	utxoResults, err := w.ListUnspent()

	if err != nil {
		return nil, err
	}

	utxos, err := resultsToUtxos(utxoResults, true)

	if err != nil {
		return nil, err
	}

	var utxosToUse []Utxo
	if useUtxoFn != nil {
		for _, u := range utxos {
			if useUtxoFn(u) {
				utxosToUse = append(utxosToUse, u)
			}
		}
	} else {
		utxosToUse = utxos
	}

	// sort utxos by amount from highest to lowest, this is effectively strategy of using
	// largest inputs first
	sort.Sort(sort.Reverse(byAmount(utxosToUse)))

	changeScript, err := txscript.PayToAddrScript(changeAddres)

	if err != nil {
		return nil, err
	}

	tx, err := buildTxFromOutputs(utxosToUse, outputs, feeRatePerKb, changeScript)

	if err != nil {
		return nil, err
	}

	return tx, err
}

func (w *RPCWalletController) CreateAndSignTx(
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeAddress btcutil.Address,
	useUtxoFn UseUtxoFn,
) (*wire.MsgTx, error) {
	tx, err := w.CreateTransaction(outputs, feeRatePerKb, changeAddress, useUtxoFn)

	if err != nil {
		return nil, err
	}

	fundedTx, signed, err := w.SignRawTransaction(tx)

	if err != nil {
		return nil, err
	}

	if !signed {
		// TODO: Investigate this case a bit more thoroughly, to check if we can recover
		// somehow
		return nil, fmt.Errorf("not all transactions inputs could be signed")
	}

	return fundedTx, nil
}

func (w *RPCWalletController) SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error) {
	switch w.backend {
	case types.BitcoindWalletBackend:
		return w.Client.SignRawTransactionWithWallet(tx)
	case types.BtcwalletWalletBackend:
		return w.Client.SignRawTransaction(tx)
	default:
		return nil, false, fmt.Errorf("invalid bitcoin backend")
	}
}

func (w *RPCWalletController) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error) {
	return w.Client.SendRawTransaction(tx, allowHighFees)
}

func (w *RPCWalletController) ListOutputs(onlySpendable bool) ([]Utxo, error) {
	utxoResults, err := w.ListUnspent()

	if err != nil {
		return nil, err
	}

	utxos, err := resultsToUtxos(utxoResults, onlySpendable)

	if err != nil {
		return nil, err
	}

	return utxos, nil
}

func nofitierStateToWalletState(state notifier.TxConfStatus) TxStatus {
	switch state {
	case notifier.TxNotFoundIndex:
		return TxNotFound
	case notifier.TxFoundMempool:
		return TxInMemPool
	case notifier.TxFoundIndex:
		return TxInChain
	case notifier.TxNotFoundManually:
		return TxNotFound
	case notifier.TxFoundManually:
		return TxInChain
	default:
		panic(fmt.Sprintf("unknown notifier state: %s", state))
	}
}

func (w *RPCWalletController) getTxDetails(req notifier.ConfRequest, msg string) (*notifier.TxConfirmation, TxStatus, error) {
	res, state, err := notifier.ConfDetailsFromTxIndex(w.Client, req, msg)

	if err != nil {
		return nil, TxNotFound, err
	}

	return res, nofitierStateToWalletState(state), nil
}

// Tx returns the raw transaction based on the transaction hash
func (w *RPCWalletController) Tx(txHash *chainhash.Hash) (*btcutil.Tx, error) {
	return w.Client.GetRawTransaction(txHash)
}

// TxVerbose returns the raw transaction verbose based on the transaction hash
func (w *RPCWalletController) TxVerbose(txHash *chainhash.Hash) (*btcjson.TxRawResult, error) {
	return w.Client.GetRawTransactionVerbose(txHash)
}

// BlockHeaderVerbose returns the block header data based on the block hash
func (w *RPCWalletController) BlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {
	return w.Client.GetBlockHeaderVerbose(blockHash)
}

// Fetch info about transaction from mempool or blockchain, requires node to have enabled  transaction index
func (w *RPCWalletController) TxDetails(txHash *chainhash.Hash, pkScript []byte) (*notifier.TxConfirmation, TxStatus, error) {
	req, err := notifier.NewConfRequest(txHash, pkScript)

	if err != nil {
		return nil, TxNotFound, err
	}

	switch w.backend {
	case types.BitcoindWalletBackend:
		return w.getTxDetails(req, txNotFoundErrMsgBitcoind)
	case types.BtcwalletWalletBackend:
		return w.getTxDetails(req, txNotFoundErrMsgBtcd)
	default:
		return nil, TxNotFound, fmt.Errorf("invalid bitcoin backend")
	}
}

// SignBip322NativeSegwit signs arbitrary message using bip322 signing scheme.
// To work properly:
// - wallet must be unlocked
// - address must be under wallet control
// - address must be native segwit address
func (w *RPCWalletController) SignBip322NativeSegwit(msg []byte, address btcutil.Address) (wire.TxWitness, error) {
	toSpend, err := bip322.GetToSpendTx(msg, address)

	if err != nil {
		return nil, fmt.Errorf("failed to bip322 to spend tx: %w", err)
	}

	if !txscript.IsPayToWitnessPubKeyHash(toSpend.TxOut[0].PkScript) {
		return nil, fmt.Errorf("Bip322NativeSegwit support only native segwit addresses")
	}

	toSpendhash := toSpend.TxHash()

	toSign := bip322.GetToSignTx(toSpend)

	amt := float64(0)
	signed, all, err := w.SignRawTransactionWithWallet2(toSign, []btcjson.RawTxWitnessInput{
		{
			Txid:         toSpendhash.String(),
			Vout:         0,
			ScriptPubKey: hex.EncodeToString(toSpend.TxOut[0].PkScript),
			Amount:       &amt,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to sign raw transaction while creating bip322 signature: %w", err)
	}

	if !all {
		return nil, fmt.Errorf("failed to create bip322 signature, address %s is not under wallet control", address)
	}

	return signed.TxIn[0].Witness, nil
}

func (w *RPCWalletController) OutputSpent(
	txHash *chainhash.Hash,
	outputIdx uint32,
) (bool, error) {
	res, err := w.Client.GetTxOut(
		txHash, outputIdx, true,
	)

	if err != nil {
		return false, err
	}

	return res == nil, nil
}

func (w *RPCWalletController) SignOneInputTaprootSpendingTransaction(request *TaprootSigningRequest) (*TaprootSigningResult, error) {
	if len(request.TxToSign.TxIn) != 1 {
		return nil, fmt.Errorf("cannot sign transaction with more than one input")
	}

	if !txscript.IsPayToTaproot(request.FundingOutput.PkScript) {
		return nil, fmt.Errorf("cannot sign transaction spending non-taproot output")
	}

	key, err := w.AddressPublicKey(request.SignerAddress)

	if err != nil {
		return nil, fmt.Errorf("failed to get public key for address: %w", err)
	}

	psbtPacket, err := psbt.New(
		[]*wire.OutPoint{&request.TxToSign.TxIn[0].PreviousOutPoint},
		request.TxToSign.TxOut,
		request.TxToSign.Version,
		request.TxToSign.LockTime,
		[]uint32{request.TxToSign.TxIn[0].Sequence},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT packet with transaction to sign: %w", err)
	}

	psbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	psbtPacket.Inputs[0].WitnessUtxo = request.FundingOutput
	psbtPacket.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		{
			PubKey: key.SerializeCompressed(),
		},
	}

	ctrlBlockBytes, err := request.SpendDescription.ControlBlock.ToBytes()

	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	psbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: ctrlBlockBytes,
			Script:       request.SpendDescription.ScriptLeaf.Script,
			LeafVersion:  request.SpendDescription.ScriptLeaf.LeafVersion,
		},
	}

	psbtEncoded, err := psbtPacket.B64Encode()

	if err != nil {
		return nil, fmt.Errorf("failed to encode PSBT packet: %w", err)
	}

	sign := true
	signResult, err := w.Client.WalletProcessPsbt(
		psbtEncoded,
		&sign,
		"DEFAULT",
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign PSBT packet: %w", err)
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(signResult.Psbt)

	if err != nil {
		return nil, fmt.Errorf("failed to decode signed PSBT packet from b64: %w", err)
	}

	decodedPsbt, err := psbt.NewFromRawBytes(bytes.NewReader(decodedBytes), false)

	if err != nil {
		return nil, fmt.Errorf("failed to decode signed PSBT packet from bytes: %w", err)
	}

	// In our signing request we only handle transaction with one input, and request
	// signature for one public key, thus we can receive at most one signature from btc
	if len(decodedPsbt.Inputs[0].TaprootScriptSpendSig) == 1 {
		schnorSignature := decodedPsbt.Inputs[0].TaprootScriptSpendSig[0].Signature

		parsedSignature, err := schnorr.ParseSignature(schnorSignature)

		if err != nil {
			return nil, fmt.Errorf("failed to parse schnorr signature in psbt packet: %w", err)
		}

		return &TaprootSigningResult{
			Signature: parsedSignature,
		}, nil
	}

	// decodedPsbt.Inputs[0].TaprootScriptSpendSig was 0, it is possible that script
	// required only one signature to build whole witness
	if len(decodedPsbt.Inputs[0].FinalScriptWitness) > 0 {
		// we go whole witness, return it to the caller
		witness, err := bip322.SimpleSigToWitness(decodedPsbt.Inputs[0].FinalScriptWitness)

		if err != nil {
			return nil, fmt.Errorf("failed to parse witness in psbt packet: %w", err)
		}

		return &TaprootSigningResult{
			FullInputWitness: witness,
		}, nil
	}

	// neither witness, nor signature is filled.
	return nil, fmt.Errorf("no signature found in PSBT packet. Wallet can't sign given tx")
}
