// Package keyringcontroller provides keyring management functionality for Cosmos SDK chains.
package keyringcontroller

import (
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
)

// MakeCodec creates a ProtoCodec with crypto interfaces registered.
func MakeCodec() *codec.ProtoCodec {
	ir := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(ir)

	cryptocodec.RegisterInterfaces(ir)

	return cdc
}
