package walletcontroller

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/babylonlabs-io/babylon/v3/crypto/bip322"
	"github.com/babylonlabs-io/btc-staker/stakercfg"
	"github.com/babylonlabs-io/btc-staker/types"
	"github.com/babylonlabs-io/btc-staker/utils"
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

// Extracts public key from the descriptor in format:
// tr([fingerprint/derivation/path/x/y/z]extracted_key)#checksum
func extractPubKeyFromDescriptor(descriptor string) (string, error) {
	// Find the position of the opening bracket and closing parenthesis
	start := strings.Index(descriptor, "]")
	end := strings.Index(descriptor, ")")

	if start == -1 || end == -1 || start >= end {
		return "", fmt.Errorf("invalid descriptor format")
	}

	// Extract the public key (everything between "]" and ")")
	pubKey := descriptor[start+1 : end]

	return pubKey, nil
}

func extractTaprootInternalKey(
	descriptor string,
) (*btcec.PublicKey, error) {
	internalKeyHex, err := extractPubKeyFromDescriptor(descriptor)

	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from taproot descriptor: %w", err)
	}

	internalKeyBytes, err := hex.DecodeString(internalKeyHex)

	if err != nil {
		return nil, fmt.Errorf("failed to decode internal key: %w", err)
	}

	internalKey, err := schnorr.ParsePubKey(internalKeyBytes)

	if err != nil {
		return nil, fmt.Errorf("failed to parse internal key: %w", err)
	}

	return internalKey, nil
}

func (w *RPCWalletController) AddressPublicKey(address btcutil.Address) (*btcec.PublicKey, error) {
	encoded := address.EncodeAddress()

	info, err := w.GetAddressInfo(encoded)

	if err != nil {
		return nil, fmt.Errorf("failed to get address info: %w", err)
	}

	// first try to get public key directly from address info. Not all address types
	// fill this field
	if info.PubKey != nil {
		decodedHex, err := hex.DecodeString(*info.PubKey)

		if err != nil {
			return nil, fmt.Errorf("failed to decode public key: %w", err)
		}

		return btcec.ParsePubKey(decodedHex)
	}

	// if not found, check if this is taproot address and extract public key from descriptor
	// we are interested in bip86 taproot addresses i.e https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
	// as those addresses have direct mapping address -> public key
	addressTxScript, err := txscript.PayToAddrScript(address)

	if err != nil {
		return nil, fmt.Errorf("failed to get address tx script: %w", err)
	}

	if txscript.IsPayToTaproot(addressTxScript) {
		internalKey, err := extractTaprootInternalKey(*info.Descriptor)

		if err != nil {
			return nil, fmt.Errorf("failed to extract internal key from descriptor: %w", err)
		}
		// now that we extracted public key from descriptor, we need to check whether
		// this is address that commits to taproot output with no script spending
		// path
		payToTaprootScript, err := txscript.PayToTaprootScript(
			txscript.ComputeTaprootKeyNoScript(internalKey),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create pay to taproot script: %w", err)
		}

		if !bytes.Equal(payToTaprootScript, addressTxScript) {
			return nil, fmt.Errorf("address %s is not a taproot address", encoded)
		}

		return internalKey, nil
	}

	return nil, fmt.Errorf("cannot get public key for address %s", encoded)
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

	err = utils.CheckTransaction(tx)

	if err != nil {
		// returning error here means our tx building code is buggy, but it will save
		// user from submitting invalid transaction to the network
		return nil, fmt.Errorf("transaction is not standard: %w", err)
	}

	return tx, err
}

// CreateTransactionWithInputs creates a transaction with a specified number of inputs and required inputs
func (w *RPCWalletController) CreateTransactionWithInputs(
	requiredInputs []wire.OutPoint,
	desiredInputCount int,
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeAddress btcutil.Address,
	useUtxoFn UseUtxoFn,
) (*wire.MsgTx, error) {
	// Check if we have too many required inputs
	if len(requiredInputs) > desiredInputCount {
		return nil, fmt.Errorf("number of required inputs (%d) exceeds desired input count (%d)", len(requiredInputs), desiredInputCount)
	}

	utxoResults, err := w.ListUnspent()
	if err != nil {
		return nil, err
	}

	utxos, err := resultsToUtxos(utxoResults, true)
	if err != nil {
		return nil, err
	}

	// Create map for quick lookup of available UTXOs
	utxoMap := make(map[wire.OutPoint]Utxo)
	for _, u := range utxos {
		utxoMap[u.OutPoint] = u
	}

	// First, collect required inputs and ensure they exist
	var orderedUtxos []Utxo
	for _, reqOutPoint := range requiredInputs {
		if utxo, exists := utxoMap[reqOutPoint]; exists {
			// Apply useUtxoFn filter if provided
			if useUtxoFn == nil || useUtxoFn(utxo) {
				orderedUtxos = append(orderedUtxos, utxo)
				delete(utxoMap, reqOutPoint) // Remove from available pool
			} else {
				return nil, fmt.Errorf("required input %s is filtered out by useUtxoFn", reqOutPoint.String())
			}
		} else {
			// Required input not found in wallet's UTXO set (e.g., taproot staking output)
			// Create a synthetic UTXO by fetching the transaction and output
			tx, err := w.Tx(&reqOutPoint.Hash)
			if err != nil {
				return nil, fmt.Errorf("required input %s not found in available UTXOs and cannot fetch transaction: %w", reqOutPoint.String(), err)
			}

			if reqOutPoint.Index >= uint32(len(tx.MsgTx().TxOut)) {
				return nil, fmt.Errorf("required input %s has invalid output index %d", reqOutPoint.String(), reqOutPoint.Index)
			}

			txOut := tx.MsgTx().TxOut[reqOutPoint.Index]

			// Create synthetic UTXO for the required input
			syntheticUtxo := Utxo{
				Amount:   btcutil.Amount(txOut.Value),
				OutPoint: reqOutPoint,
				PkScript: txOut.PkScript,
				Address:  "", // We don't need the address for synthetic UTXOs
			}

			// Apply useUtxoFn filter if provided
			if useUtxoFn == nil || useUtxoFn(syntheticUtxo) {
				orderedUtxos = append(orderedUtxos, syntheticUtxo)
			} else {
				return nil, fmt.Errorf("required input %s is filtered out by useUtxoFn", reqOutPoint.String())
			}
		}
	}

	// Convert remaining UTXOs to slice and apply filter
	var remainingUtxos []Utxo
	for _, u := range utxoMap {
		if useUtxoFn == nil || useUtxoFn(u) {
			remainingUtxos = append(remainingUtxos, u)
		}
	}

	// Sort remaining UTXOs by amount from highest to lowest
	sort.Sort(sort.Reverse(byAmount(remainingUtxos)))

	// Add additional inputs to reach desired count
	// Note: orderedUtxos already contains required inputs in specified order
	// Now we add the highest-value remaining UTXOs to fill up to desiredInputCount
	remainingInputsNeeded := desiredInputCount - len(orderedUtxos)
	if remainingInputsNeeded > 0 {
		if len(remainingUtxos) < remainingInputsNeeded {
			return nil, fmt.Errorf("not enough UTXOs available: need %d more inputs, only %d available", remainingInputsNeeded, len(remainingUtxos))
		}

		// Add the required number of additional inputs (sorted by highest amount first)
		for i := range remainingInputsNeeded {
			orderedUtxos = append(orderedUtxos, remainingUtxos[i])
		}
	}

	changeScript, err := txscript.PayToAddrScript(changeAddress)
	if err != nil {
		return nil, err
	}

	tx, err := buildTxFromOutputs(orderedUtxos, outputs, feeRatePerKb, changeScript)
	if err != nil {
		return nil, err
	}

	// Final validation that we have the exact desired input count
	if len(tx.TxIn) != desiredInputCount {
		return nil, fmt.Errorf("transaction must have exactly %d inputs, got %d", desiredInputCount, len(tx.TxIn))
	}

	err = utils.CheckTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("transaction is not standard: %w", err)
	}

	return tx, nil
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

func isSupportedAddress(payToAddrScript []byte) bool {
	return txscript.IsPayToTaproot(payToAddrScript) || txscript.IsPayToWitnessPubKeyHash(payToAddrScript)
}

// SignBip322Signature signs arbitrary message using bip322 signing scheme.
// To work properly:
// - wallet must be unlocked
// - address must be under wallet control
// - address must be native segwit address or taproot address with no script spending path
func (w *RPCWalletController) SignBip322Signature(msg []byte, address btcutil.Address) (wire.TxWitness, error) {
	toSpend, err := bip322.GetToSpendTx(msg, address)

	if err != nil {
		return nil, fmt.Errorf("failed to bip322 to spend tx: %w", err)
	}

	if !isSupportedAddress(toSpend.TxOut[0].PkScript) {
		return nil, fmt.Errorf("address %s is not supported for bip322 signing. Only p2wpkh and p2tr addresses are supported", address)
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

	return w.signTaprootTransaction(
		request.TxToSign,
		request.SignerAddress,
		request.SpendDescription,
		[]*wire.TxOut{request.FundingOutput},
		0, // Sign the only input
	)
}

func (w *RPCWalletController) SignTwoInputTaprootSpendingTransaction(request *TwoInputTaprootSigningRequest) (*TaprootSigningResult, error) {
	if len(request.TxToSign.TxIn) != 2 {
		return nil, fmt.Errorf("transaction must have exactly two inputs, got %d", len(request.TxToSign.TxIn))
	}

	return w.signTaprootTransaction(
		request.TxToSign,
		request.SignerAddress,
		request.SpendDescription,
		[]*wire.TxOut{request.StakingOutput, request.FundingOutput},
		0, // Sign the first input (staking output)
	)
}

// signTaprootTransaction is a generic function that handles taproot transaction signing
// for both single and multi-input transactions
func (w *RPCWalletController) signTaprootTransaction(
	txToSign *wire.MsgTx,
	signerAddress btcutil.Address,
	spendDescription *SpendPathDescription,
	inputUtxos []*wire.TxOut,
	inputToSignIndex int,
) (*TaprootSigningResult, error) {
	// Validate that we're signing a taproot output
	if !txscript.IsPayToTaproot(inputUtxos[inputToSignIndex].PkScript) {
		return nil, fmt.Errorf("input %d must be a taproot output", inputToSignIndex)
	}

	// Get the public key for the signer address
	key, err := w.AddressPublicKey(signerAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for address: %w", err)
	}

	// Create outpoints and sequences for all inputs
	outpoints := make([]*wire.OutPoint, len(txToSign.TxIn))
	sequences := make([]uint32, len(txToSign.TxIn))
	for i, txIn := range txToSign.TxIn {
		outpoints[i] = &txIn.PreviousOutPoint
		sequences[i] = txIn.Sequence
	}

	// Create PSBT packet
	psbtPacket, err := psbt.New(
		outpoints,
		txToSign.TxOut,
		txToSign.Version,
		txToSign.LockTime,
		sequences,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT packet: %w", err)
	}

	// Set UTXO information for all inputs
	for i, utxo := range inputUtxos {
		psbtPacket.Inputs[i].WitnessUtxo = utxo
	}

	// Configure signing for the target input only
	psbtPacket.Inputs[inputToSignIndex].SighashType = txscript.SigHashDefault
	psbtPacket.Inputs[inputToSignIndex].Bip32Derivation = []*psbt.Bip32Derivation{
		{
			PubKey: key.SerializeCompressed(),
		},
	}

	// Set up taproot leaf script for the input to sign
	ctrlBlockBytes, err := spendDescription.ControlBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	psbtPacket.Inputs[inputToSignIndex].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: ctrlBlockBytes,
			Script:       spendDescription.ScriptLeaf.Script,
			LeafVersion:  spendDescription.ScriptLeaf.LeafVersion,
		},
	}

	// Clear signing information for other inputs
	for i := range psbtPacket.Inputs {
		if i != inputToSignIndex {
			psbtPacket.Inputs[i].SighashType = 0
			psbtPacket.Inputs[i].Bip32Derivation = nil
			psbtPacket.Inputs[i].TaprootLeafScript = nil
		}
	}

	// Encode and sign the PSBT
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

	// Decode the signed PSBT
	decodedBytes, err := base64.StdEncoding.DecodeString(signResult.Psbt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed PSBT packet from b64: %w", err)
	}

	decodedPsbt, err := psbt.NewFromRawBytes(bytes.NewReader(decodedBytes), false)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed PSBT packet from bytes: %w", err)
	}

	// Check if we got a signature for the target input
	if len(decodedPsbt.Inputs[inputToSignIndex].TaprootScriptSpendSig) == 1 {
		schnorSignature := decodedPsbt.Inputs[inputToSignIndex].TaprootScriptSpendSig[0].Signature
		parsedSignature, err := schnorr.ParseSignature(schnorSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to parse schnorr signature in psbt packet: %w", err)
		}

		return &TaprootSigningResult{
			Signature: parsedSignature,
		}, nil
	}

	// Check if we got a full witness
	if len(decodedPsbt.Inputs[inputToSignIndex].FinalScriptWitness) > 0 {
		witness, err := bip322.SimpleSigToWitness(decodedPsbt.Inputs[inputToSignIndex].FinalScriptWitness)
		if err != nil {
			return nil, fmt.Errorf("failed to parse witness in psbt packet: %w", err)
		}

		return &TaprootSigningResult{
			FullInputWitness: witness,
		}, nil
	}

	// No signature found
	return nil, fmt.Errorf("no signature found in PSBT packet. Wallet can't sign given tx")
}
