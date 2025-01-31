package staker

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	BabyAddress   string `json:"babyAddress"`
	BTCAddress    string `json:"btcAddress"`
	BTCPublicKey  string `json:"btcPublicKey"`
	BTCSignBaby   string `json:"btcSignBaby"`
	BabySignBTC   string `json:"babySignBtc"`
	BabyPublicKey string `json:"babyPublicKey"`
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

	record, babyPubKey, err := GetBabyPubKey(pc.KeyRing, babyAddress)
	if err != nil {
		return nil, err
	}

	babySignBTCAddress, err := SignCosmosAdr36(
		pc.KeyRing,
		record.Name,
		bech32cosmosAddressString,
		[]byte(btcAddress.String()),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign btc address: %w", err)
	}

	return &Response{
		BabyAddress:   bech32cosmosAddressString,
		BTCAddress:    btcAddress.String(),
		BTCPublicKey:  hex.EncodeToString(schnorr.SerializePubKey(btcPubKey)),
		BTCSignBaby:   base64.StdEncoding.EncodeToString(signatureBytes),
		BabySignBTC:   base64.StdEncoding.EncodeToString(babySignBTCAddress),
		BabyPublicKey: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
	}, nil
}

type Fee struct {
	Gas    string   `json:"gas"`
	Amount []string `json:"amount"`
}

type MsgValue struct {
	Signer string `json:"signer"`
	Data   string `json:"data"`
}

type Msg struct {
	Type  string   `json:"type"`
	Value MsgValue `json:"value"`
}

type SignDoc struct {
	ChainID       string `json:"chain_id"`
	AccountNumber string `json:"account_number"`
	Sequence      string `json:"sequence"`
	Fee           Fee    `json:"fee"`
	Msgs          []Msg  `json:"msgs"`
	Memo          string `json:"memo"`
}

func NewCosmosSignDoc(
	signer string,
	data string,
) *SignDoc {
	return &SignDoc{
		ChainID:       "",
		AccountNumber: "0",
		Sequence:      "0",
		Fee: Fee{
			Gas:    "0",
			Amount: []string{},
		},
		Msgs: []Msg{
			{
				Type: "sign/MsgSignData",
				Value: MsgValue{
					Signer: signer,
					Data:   data,
				},
			},
		},
		Memo: "",
	}
}

func GetBabyPubKey(kr keyring.Keyring, babylonAddress sdk.AccAddress) (*keyring.Record, *secp256k1.PubKey, error) {
	record, err := kr.KeyByAddress(babylonAddress)

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

func SignCosmosAdr36(
	kr keyring.Keyring,
	keyName string,
	cosmosBech32Address string,
	bytesToSign []byte,
) ([]byte, error) {
	base64Bytes := base64.StdEncoding.EncodeToString(bytesToSign)

	signDoc := NewCosmosSignDoc(
		cosmosBech32Address,
		base64Bytes,
	)

	marshaled, err := json.Marshal(signDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sign doc: %w", err)
	}

	bz := sdk.MustSortJSON(marshaled)

	babySignBTCAddress, _, err := kr.Sign(
		keyName,
		bz,
		signing.SignMode_SIGN_MODE_DIRECT,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign btc address bytes: %w", err)
	}

	return babySignBTCAddress, nil
}
