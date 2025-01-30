package keyringcontroller

import (
	"fmt"
	"strings"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
)

func CreateKeyring(keyringDir string, chainID string, backend string, input *strings.Reader) (keyring.Keyring, error) {
	ctx, err := CreateClientCtx(keyringDir, chainID)
	if err != nil {
		return nil, err
	}

	if backend == "" {
		return nil, fmt.Errorf("the keyring backend should not be empty")
	}

	kr, err := keyring.New(
		ctx.ChainID,
		backend,
		ctx.KeyringDir,
		input,
		ctx.Codec,
		ctx.KeyringOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyring: %w", err)
	}

	return kr, nil
}

func CreateClientCtx(keyringDir string, chainID string) (client.Context, error) {
	if keyringDir == "" {
		return client.Context{}, fmt.Errorf("the keyring directory should not be empty")
	}
	return client.Context{}.
		WithChainID(chainID).
		WithCodec(MakeCodec()).
		WithKeyringDir(keyringDir), nil
}
