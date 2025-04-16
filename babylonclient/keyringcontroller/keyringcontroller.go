package keyringcontroller

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdksecp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/go-bip39"
)

const (
	secp256k1Type       = "secp256k1"
	mnemonicEntropySize = 256
)

type ChainKeyInfo struct {
	Name       string
	Mnemonic   string
	PublicKey  *btcec.PublicKey
	PrivateKey *btcec.PrivateKey
}

type ChainKeyringController struct {
	kr      keyring.Keyring
	keyName string
	// input is to send passphrase to kr
	input *strings.Reader
}

func NewChainKeyringController(ctx client.Context, name, keyringBackend string) (*ChainKeyringController, error) {
	if name == "" {
		return nil, fmt.Errorf("the key name should not be empty")
	}

	if keyringBackend == "" {
		return nil, fmt.Errorf("the keyring backend should not be empty")
	}

	inputReader := strings.NewReader("")
	kr, err := keyring.New(
		ctx.ChainID,
		keyringBackend,
		ctx.KeyringDir,
		inputReader,
		ctx.Codec,
		ctx.KeyringOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	return &ChainKeyringController{
		keyName: name,
		kr:      kr,
		input:   inputReader,
	}, nil
}

func NewChainKeyringControllerWithKeyring(kr keyring.Keyring, name string, input *strings.Reader) (*ChainKeyringController, error) {
	if name == "" {
		return nil, fmt.Errorf("the key name should not be empty")
	}

	return &ChainKeyringController{
		kr:      kr,
		keyName: name,
		input:   input,
	}, nil
}

func (kc *ChainKeyringController) GetKeyring() keyring.Keyring {
	return kc.kr
}

func (kc *ChainKeyringController) CreateChainKey(passphrase, hdPath string) (*ChainKeyInfo, error) {
	keyringAlgos, _ := kc.kr.SupportedAlgorithms()
	algo, err := keyring.NewSigningAlgoFromString(secp256k1Type, keyringAlgos)
	if err != nil {
		return nil, err
	}
	// read entropy seed straight from tmcrypto.Rand and convert to mnemonic
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return nil, err
	}

	mnemonic, err := bip39.NewMnemonic(entropySeed)
	if err != nil {
		return nil, err
	}

	// we need to repeat the passphrase to mock the reentry
	kc.input.Reset(passphrase + "\n" + passphrase)
	record, err := kc.kr.NewAccount(kc.keyName, mnemonic, passphrase, hdPath, algo)
	if err != nil {
		return nil, err
	}

	privKey := record.GetLocal().PrivKey.GetCachedValue()

	switch v := privKey.(type) {
	case *sdksecp256k1.PrivKey:
		sk, pk := btcec.PrivKeyFromBytes(v.Key)
		return &ChainKeyInfo{
			Name:       kc.keyName,
			PublicKey:  pk,
			PrivateKey: sk,
			Mnemonic:   mnemonic,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type in keyring")
	}
}

func (kc *ChainKeyringController) GetChainPrivKey(passphrase string) (*sdksecp256k1.PrivKey, error) {
	kc.input.Reset(passphrase)
	k, err := kc.kr.Key(kc.keyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	privKeyCached := k.GetLocal().PrivKey.GetCachedValue()

	switch v := privKeyCached.(type) {
	case *sdksecp256k1.PrivKey:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported key type in keyring")
	}
}

func (kc *ChainKeyringController) KeyRecord() (*keyring.Record, error) {
	return kc.GetKeyring().Key(kc.keyName)
}
