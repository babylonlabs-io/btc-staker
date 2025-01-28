package babylonclient

import (
	"fmt"
	bct "github.com/babylonlabs-io/babylon/client/babylonclient"

	sdkmath "cosmossdk.io/math"
	"github.com/babylonlabs-io/babylon/testutil/datagen"
	"github.com/babylonlabs-io/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type BTCCheckpointParams struct {
	// K-deep
	ConfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32
}

type StakingParams struct {
	// K-deep
	ConfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current covenant
	CovenantPks []*btcec.PublicKey

	// PkScript that must be inserted in the slashing output of the slashing transaction
	SlashingPkScript []byte

	// The rate at which the staked funds will be slashed, expressed as a decimal.
	SlashingRate sdkmath.LegacyDec

	// Covenant quorum threshold
	CovenantQuruomThreshold uint32

	// Minimum unbonding time required by babylon
	UnbondingTime uint16

	// Fee required by unbonding transaction
	UnbondingFee btcutil.Amount

	// Minimum staking time required by babylon
	MinStakingTime uint16

	// Maximum staking time required by babylon
	MaxStakingTime uint16

	// Minimum staking value required by babylon
	MinStakingValue btcutil.Amount

	// Maximum staking value required by babylon
	MaxStakingValue btcutil.Amount

	// AllowList expiration height
	AllowListExpirationHeight uint64
}

// SingleKeyCosmosKeyring represents a keyring that supports only one pritvate/public key pair
type SingleKeyKeyring interface {
	Sign(msg []byte) ([]byte, error)
	GetKeyAddress() sdk.AccAddress
	GetPubKey() *secp256k1.PubKey
}

type BabylonClient interface {
	SingleKeyKeyring
	BTCCheckpointParams() (*BTCCheckpointParams, error)
	Params() (*StakingParams, error)
	ParamsByBtcHeight(btcHeight uint32) (*StakingParams, error)
	Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error)
	QueryFinalityProviders(limit uint64, offset uint64) (*FinalityProvidersClientResponse, error)
	QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error)
	QueryHeaderDepth(headerHash *chainhash.Hash) (uint32, error)
	IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error)
	QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error)
	GetLatestBlockHeight() (uint64, error)
	QueryBtcLightClientTipHeight() (uint32, error)
}

type MockBabylonClient struct {
	ClientParams           *StakingParams
	babylonKey             *secp256k1.PrivKey
	SentMessages           chan *types.MsgCreateBTCDelegation
	ActiveFinalityProvider *FinalityProviderInfo
}

var _ BabylonClient = (*MockBabylonClient)(nil)

func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.ClientParams, nil
}

func (m *MockBabylonClient) ParamsByBtcHeight(_ uint32) (*StakingParams, error) {
	return m.ClientParams, nil
}

func (m *MockBabylonClient) BTCCheckpointParams() (*BTCCheckpointParams, error) {
	return &BTCCheckpointParams{
		ConfirmationTimeBlocks:    m.ClientParams.ConfirmationTimeBlocks,
		FinalizationTimeoutBlocks: m.ClientParams.FinalizationTimeoutBlocks,
	}, nil
}

func (m *MockBabylonClient) Sign(msg []byte) ([]byte, error) {
	sig, err := m.babylonKey.Sign(msg)

	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (m *MockBabylonClient) GetKeyAddress() sdk.AccAddress {
	address := m.babylonKey.PubKey().Address()

	return sdk.AccAddress(address)
}

func (m *MockBabylonClient) GetPubKey() *secp256k1.PubKey {
	pk := m.babylonKey.PubKey()

	switch v := pk.(type) {
	case *secp256k1.PubKey:
		return v
	default:
		panic("Unsupported key type in keyring")
	}
}

func (m *MockBabylonClient) Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	msg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &bct.RelayerTxResponse{Code: 0}, nil
}

func (m *MockBabylonClient) QueryFinalityProviders(_ uint64, _ uint64) (*FinalityProvidersClientResponse, error) {
	return &FinalityProvidersClientResponse{
		FinalityProviders: []FinalityProviderInfo{*m.ActiveFinalityProvider},
		Total:             1,
	}, nil
}

func (m *MockBabylonClient) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if m.ActiveFinalityProvider.BtcPk.IsEqual(btcPubKey) {
		return &FinalityProviderClientResponse{
			FinalityProvider: *m.ActiveFinalityProvider,
		}, nil
	}

	return nil, ErrFinalityProviderDoesNotExist
}

func (m *MockBabylonClient) QueryHeaderDepth(_ *chainhash.Hash) (uint32, error) {
	// return always confirmed depth
	return m.ClientParams.ConfirmationTimeBlocks + 1, nil
}

func (m *MockBabylonClient) IsTxAlreadyPartOfDelegation(_ *chainhash.Hash) (bool, error) {
	return false, nil
}

func (m *MockBabylonClient) QueryDelegationInfo(_ *chainhash.Hash) (*DelegationInfo, error) {
	return nil, fmt.Errorf("delegation do not exist")
}

func (m *MockBabylonClient) Undelegate(
	_ *UndelegationRequest) (*bct.RelayerTxResponse, error) {
	return &bct.RelayerTxResponse{Code: 0}, nil
}

func (m *MockBabylonClient) GetLatestBlockHeight() (uint64, error) {
	return 0, nil
}

func GetMockClient() *MockBabylonClient {
	covenantPk, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	priv := secp256k1.GenPrivKey()

	slashingAddress, _ := btcutil.NewAddressPubKey(covenantPk.PubKey().SerializeCompressed(), &chaincfg.SimNetParams)

	slashingPkScript, err := txscript.PayToAddrScript(slashingAddress)

	if err != nil {
		panic(err)
	}

	fpBtcPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	vi := FinalityProviderInfo{
		BabylonAddr: datagen.GenRandomAccount().GetAddress(),
		BtcPk:       *fpBtcPrivKey.PubKey(),
	}

	return &MockBabylonClient{
		ClientParams: &StakingParams{
			ConfirmationTimeBlocks:    2,
			FinalizationTimeoutBlocks: 5,
			MinSlashingTxFeeSat:       btcutil.Amount(1000),
			CovenantPks:               []*btcec.PublicKey{covenantPk.PubKey()},
			SlashingPkScript:          slashingPkScript,
			SlashingRate:              sdkmath.LegacyNewDecWithPrec(1, 1), // 1 * 10^{-1} = 0.1
		},
		babylonKey:             priv,
		SentMessages:           make(chan *types.MsgCreateBTCDelegation),
		ActiveFinalityProvider: &vi,
	}
}

func (m *MockBabylonClient) QueryBtcLightClientTipHeight() (uint32, error) {
	return 0, nil
}
