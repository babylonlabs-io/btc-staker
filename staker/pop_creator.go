package staker

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/babylonlabs-io/babylon/crypto/bip322"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
)

type Response struct {
	BabyAddress   string        `json:"babyAddress"`
	BTCAddress    string        `json:"btcAddress"`
	BTCPublicKey  string        `json:"btcPublicKey"`
	BTCSignBaby   string        `json:"btcSignBaby"`
	BabySignBTC   string        `json:"babySignBtc"`
	BabyPublicKey BabyPublicKey `json:"babyPublicKey"`
}

type BabyPublicKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type PopCreator struct {
	BitcoinWalletController walletcontroller.WalletController
	KeyRing                 keyring.Keyring
}

func NewPopCreator(bitcoinWalletController *walletcontroller.RPCWalletController, keyring keyring.Keyring) *PopCreator {
	return &PopCreator{
		BitcoinWalletController: bitcoinWalletController,
		KeyRing:                 keyring,
	}
}

func (pc *PopCreator) getBabyPubKey(babylonAddress sdk.AccAddress) (*keyring.Record, *secp256k1.PubKey, error) {
	record, err := pc.KeyRing.KeyByAddress(babylonAddress)

	if err != nil {
		return nil, nil, err
	}

	pubKey, err := record.GetPubKey()

	if err != nil {
		return nil, nil, err
	}

	switch v := pubKey.(type) {
	case *secp256k1.PubKey:
		return record, v, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type in keyring")
	}
}

func (pc *PopCreator) CreatePop(
	btcAddress btcutil.Address,
	babyAddressPrefix string,
	babyAddress sdk.AccAddress,
) (*Response, error) {
	bech32cosmosAddressString, err := sdk.Bech32ifyAddressBytes(babyAddressPrefix, babyAddress.Bytes())
	if err != nil {
		return nil, err
	}

	signature, err := pc.BitcoinWalletController.SignBip322NativeSegwit(
		[]byte(bech32cosmosAddressString),
		btcAddress,
	)

	if err != nil {
		return nil, err
	}

	btcPubKey, err := pc.BitcoinWalletController.AddressPublicKey(btcAddress)
	if err != nil {
		return nil, err
	}

	signatureBytes, err := bip322.SerializeWitness(signature)
	if err != nil {
		return nil, err
	}

	record, babyPubKey, err := pc.getBabyPubKey(babyAddress)
	if err != nil {
		return nil, err
	}

	btcAddressString := btcAddress.String()
	btcAddressBytes := []byte(btcAddressString)

	babySignBTCAddress, _, err := pc.KeyRing.Sign(
		record.Name,
		btcAddressBytes,
		signing.SignMode_SIGN_MODE_DIRECT,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign btc address bytes: %w", err)
	}

	return &Response{
		BabyAddress:  bech32cosmosAddressString,
		BTCAddress:   btcAddress.String(),
		BTCPublicKey: hex.EncodeToString(schnorr.SerializePubKey(btcPubKey)),
		BTCSignBaby:  base64.StdEncoding.EncodeToString(signatureBytes),
		BabySignBTC:  base64.StdEncoding.EncodeToString(babySignBTCAddress),
		BabyPublicKey: BabyPublicKey{
			Type:  babyPubKey.Type(),
			Value: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
		},
	}, nil
}
