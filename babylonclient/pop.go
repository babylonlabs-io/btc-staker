package babylonclient

import (
	"fmt"

	"github.com/babylonlabs-io/babylon/v4/crypto/bip322"
	bbn "github.com/babylonlabs-io/babylon/v4/types"
	btcstypes "github.com/babylonlabs-io/babylon/v4/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BabylonBtcPopType enumerates the supported PoP signature types.
type BabylonBtcPopType uint32

const (
	// SchnorrType denotes BIP340 schnorr signatures.
	SchnorrType BabylonBtcPopType = iota
	// Bip322Type denotes BIP322 message signatures.
	Bip322Type
	// EcdsaType denotes legacy ECDSA signatures.
	EcdsaType
)

// BabylonPop stores the BTC PoP bytes and their type.
type BabylonPop struct {
	popType BabylonBtcPopType
	BtcSig  []byte
}

// NewBabylonPop Generic constructor for BabylonPop that do as little validation
// as possible. It assumes passed btcSigOverBbnAddr is matching the popType `t`
func NewBabylonPop(t BabylonBtcPopType, btcSigOverBbnAddr []byte) (*BabylonPop, error) {
	if len(btcSigOverBbnAddr) == 0 {
		return nil, fmt.Errorf("cannot create BabylonPop with empty signatures")
	}

	return &BabylonPop{
		popType: t,
		BtcSig:  btcSigOverBbnAddr,
	}, nil
}

// NewBabylonBip322Pop build proper BabylonPop in BIP322 style, it verifies
// the bip322 signature validity
func NewBabylonBip322Pop(
	msg []byte,
	w wire.TxWitness,
	btcPk *bbn.BIP340PubKey,
	a btcutil.Address,
	net *chaincfg.Params,
) (*BabylonPop, error) {
	sigSerialized, err := bip322.SerializeWitness(w)
	if err != nil {
		return nil, fmt.Errorf("invalid bip322 pop parameters: %w", err)
	}

	btcKeyBytes, err := btcPk.Marshal()
	if err != nil {
		return nil, fmt.Errorf("invalid bip322 pop parameters, failed to marshal btc pk: %w", err)
	}

	err = btcstypes.VerifyBIP322SigPop(msg, a.EncodeAddress(), sigSerialized, btcKeyBytes, net)
	if err != nil {
		return nil, fmt.Errorf("invalid bip322: %w", err)
	}

	serializedWitness, err := bip322.SerializeWitness(w)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize bip322 witness: %w", err)
	}

	bip322Sig := btcstypes.BIP322Sig{
		Sig:     serializedWitness,
		Address: a.EncodeAddress(),
	}

	m, err := bip322Sig.Marshal()

	if err != nil {
		return nil, fmt.Errorf("failed to serialize btcstypes.BIP322Sig proto: %w", err)
	}

	return NewBabylonPop(Bip322Type, m)
}

// NewBTCSigType converts Babylon pop types into btcstaking enums.
func NewBTCSigType(t BabylonBtcPopType) (btcstypes.BTCSigType, error) {
	switch t {
	case SchnorrType:
		return btcstypes.BTCSigType_BIP340, nil
	case Bip322Type:
		return btcstypes.BTCSigType_BIP322, nil
	case EcdsaType:
		return btcstypes.BTCSigType_ECDSA, nil
	default:
		return btcstypes.BTCSigType_BIP340, fmt.Errorf("unknown pop type")
	}
}

// PopTypeNum returns the numeric value for proto serialization.
func (pop *BabylonPop) PopTypeNum() uint32 {
	return uint32(pop.popType)
}

// ToBtcStakingPop converts the helper struct to the btcstaking proto.
func (pop *BabylonPop) ToBtcStakingPop() (*btcstypes.ProofOfPossessionBTC, error) {
	popType, err := NewBTCSigType(pop.popType)

	if err != nil {
		return nil, err
	}

	return &btcstypes.ProofOfPossessionBTC{
		BtcSigType: popType,
		BtcSig:     pop.BtcSig,
	}, nil
}

// ValidatePop ensures the BTC signature matches the given addresses/keys.
func (pop *BabylonPop) ValidatePop(
	bbnAddr sdk.AccAddress,
	btcPk *btcec.PublicKey,
	net *chaincfg.Params,
) error {
	if btcPk == nil || net == nil {
		return fmt.Errorf("cannot validate pop with nil parameters")
	}

	bPop, err := pop.ToBtcStakingPop()

	if err != nil {
		return err
	}

	btcPkBabylonFormat := bbn.NewBIP340PubKeyFromBTCPK(btcPk)
	return bPop.Verify(
		bbnAddr,
		btcPkBabylonFormat,
		net,
	)
}
