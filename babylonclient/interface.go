package babylonclient

import (
	"fmt"

	bct "github.com/babylonlabs-io/babylon/v4/client/babylonclient"

	sdkmath "cosmossdk.io/math"
	"github.com/babylonlabs-io/babylon/v4/testutil/datagen"
	btcstypes "github.com/babylonlabs-io/babylon/v4/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BTCCheckpointParams defines the parameters for a BTC checkpoint
type BTCCheckpointParams struct {
	// K-deep
	ConfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32
}

// StakingParams defines the parameters for staking
type StakingParams struct {
	BTCCheckpointParams
	BtcStakingParams
}

// BtcStakingParams captures the BTC staking-related thresholds and scripts the
// Babylon chain exposes.
type BtcStakingParams struct {
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

// SingleKeyKeyring represents a keyring that supports only one private/public key pair.
type SingleKeyKeyring interface {
	Sign(msg []byte) ([]byte, error)
	GetKeyAddress() sdk.AccAddress
	GetPubKey() *secp256k1.PubKey
}

// BabylonClient defines the Babylon RPC queries the staker relies on.
type BabylonClient interface {
	SingleKeyKeyring
	BTCCheckpointParams() (*BTCCheckpointParams, error)
	Params() (*StakingParams, error)
	ParamsByBtcHeight(btcHeight uint32) (*StakingParams, error)
	ParamsByVersion(version uint32) (*BtcStakingParams, error)
	Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error)
	ExpandDelegation(dg *DelegationData) (*bct.RelayerTxResponse, error)
	QueryFinalityProviders(limit uint64, offset uint64) (*FinalityProvidersClientResponse, error)
	QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error)
	QueryHeaderDepth(headerHash *chainhash.Hash) (uint32, error)
	IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error)
	QueryBTCDelegation(stakingTxHash *chainhash.Hash) (*btcstypes.QueryBTCDelegationResponse, error)
	GetUndelegationInfo(resp *btcstypes.QueryBTCDelegationResponse) (*UndelegationInfo, error)
	GetLatestBlockHeight() (uint64, error)
	QueryBtcLightClientTipHeight() (uint32, error)
}

// BtcStakingParamsFromStakingTracker converts tracker responses into staking params.
func BtcStakingParamsFromStakingTracker(stakingTrackerParams *StakingTrackerResponse) BtcStakingParams {
	return BtcStakingParams{
		SlashingPkScript:          stakingTrackerParams.SlashingPkScript,
		CovenantPks:               stakingTrackerParams.CovenantPks,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
		CovenantQuruomThreshold:   stakingTrackerParams.CovenantQuruomThreshold,
		UnbondingTime:             stakingTrackerParams.UnbondingTime,
		UnbondingFee:              stakingTrackerParams.UnbondingFee,
		MinStakingTime:            stakingTrackerParams.MinStakingTime,
		MaxStakingTime:            stakingTrackerParams.MaxStakingTime,
		MinStakingValue:           stakingTrackerParams.MinStakingValue,
		MaxStakingValue:           stakingTrackerParams.MaxStakingValue,
		AllowListExpirationHeight: stakingTrackerParams.AllowListExpirationHeight,
	}
}

// MockBabylonClient is a lightweight BabylonClient implementation for tests.
type MockBabylonClient struct {
	ClientParams           *StakingParams
	babylonKey             *secp256k1.PrivKey
	SentMessages           chan sdk.Msg
	ActiveFinalityProvider *FinalityProviderInfo
}

var _ BabylonClient = (*MockBabylonClient)(nil)

// Params returns the mock staking parameters.
func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.ClientParams, nil
}

// ParamsByBtcHeight returns the same params regardless of height for tests.
func (m *MockBabylonClient) ParamsByBtcHeight(_ uint32) (*StakingParams, error) {
	return m.ClientParams, nil
}

// ParamsByVersion returns the embedded BTC staking params.
func (m *MockBabylonClient) ParamsByVersion(_ uint32) (*BtcStakingParams, error) {
	return &m.ClientParams.BtcStakingParams, nil
}

// BTCCheckpointParams exposes checkpoint timing derived from the staking params.
func (m *MockBabylonClient) BTCCheckpointParams() (*BTCCheckpointParams, error) {
	return &BTCCheckpointParams{
		ConfirmationTimeBlocks:    m.ClientParams.ConfirmationTimeBlocks,
		FinalizationTimeoutBlocks: m.ClientParams.FinalizationTimeoutBlocks,
	}, nil
}

// Sign signs arbitrary data with the mock Babylon key.
func (m *MockBabylonClient) Sign(msg []byte) ([]byte, error) {
	sig, err := m.babylonKey.Sign(msg)

	if err != nil {
		return nil, err
	}
	return sig, nil
}

// GetKeyAddress returns the Babylon account address associated with the key.
func (m *MockBabylonClient) GetKeyAddress() sdk.AccAddress {
	address := m.babylonKey.PubKey().Address()

	return sdk.AccAddress(address)
}

// GetPubKey exposes the Babylon public key.
func (m *MockBabylonClient) GetPubKey() *secp256k1.PubKey {
	pk := m.babylonKey.PubKey()

	switch v := pk.(type) {
	case *secp256k1.PubKey:
		return v
	default:
		panic("Unsupported key type in keyring")
	}
}

// Delegate stores the delegation message in the SentMessages channel.
func (m *MockBabylonClient) Delegate(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	msg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &bct.RelayerTxResponse{Code: 0}, nil
}

// ExpandDelegation tracks expansion messages for verification in tests.
func (m *MockBabylonClient) ExpandDelegation(dg *DelegationData) (*bct.RelayerTxResponse, error) {
	msg, err := delegationDataToMsgBtcStakeExpand(dg)
	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &bct.RelayerTxResponse{Code: 0}, nil
}

// QueryFinalityProviders returns the single configured provider.
func (m *MockBabylonClient) QueryFinalityProviders(_ uint64, _ uint64) (*FinalityProvidersClientResponse, error) {
	return &FinalityProvidersClientResponse{
		FinalityProviders: []FinalityProviderInfo{*m.ActiveFinalityProvider},
		Total:             1,
	}, nil
}

// QueryFinalityProvider returns the mock provider if keys match.
func (m *MockBabylonClient) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if m.ActiveFinalityProvider.BtcPk.IsEqual(btcPubKey) {
		return &FinalityProviderClientResponse{
			FinalityProvider: *m.ActiveFinalityProvider,
		}, nil
	}

	return nil, ErrFinalityProviderDoesNotExist
}

// QueryHeaderDepth pretends every header is deeply confirmed.
func (m *MockBabylonClient) QueryHeaderDepth(_ *chainhash.Hash) (uint32, error) {
	// return always confirmed depth
	return m.ClientParams.ConfirmationTimeBlocks + 1, nil
}

// IsTxAlreadyPartOfDelegation always returns false in tests.
func (m *MockBabylonClient) IsTxAlreadyPartOfDelegation(_ *chainhash.Hash) (bool, error) {
	return false, nil
}

// QueryBTCDelegation reports that delegations do not exist for simplicity.
func (m *MockBabylonClient) QueryBTCDelegation(_ *chainhash.Hash) (*btcstypes.QueryBTCDelegationResponse, error) {
	return nil, fmt.Errorf("delegation do not exist")
}

// GetUndelegationInfo always returns an error in the mock implementation.
func (m *MockBabylonClient) GetUndelegationInfo(_ *btcstypes.QueryBTCDelegationResponse) (*UndelegationInfo, error) {
	return nil, fmt.Errorf("delegation do not exist")
}

// Undelegate pretends undelegations always succeed.
func (m *MockBabylonClient) Undelegate(
	_ *UndelegationRequest) (*bct.RelayerTxResponse, error) {
	return &bct.RelayerTxResponse{Code: 0}, nil
}

// GetLatestBlockHeight returns zero for deterministic tests.
func (m *MockBabylonClient) GetLatestBlockHeight() (uint64, error) {
	return 0, nil
}

// GetMockClient constructs a ready-to-use MockBabylonClient for tests.
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
			BTCCheckpointParams: BTCCheckpointParams{
				ConfirmationTimeBlocks:    2,
				FinalizationTimeoutBlocks: 5,
			},
			BtcStakingParams: BtcStakingParams{
				MinSlashingTxFeeSat: btcutil.Amount(1000),
				CovenantPks:         []*btcec.PublicKey{covenantPk.PubKey()},
				SlashingPkScript:    slashingPkScript,
				SlashingRate:        sdkmath.LegacyNewDecWithPrec(1, 1), // 1 * 10^{-1} = 0.1
			},
		},
		babylonKey:             priv,
		SentMessages:           make(chan sdk.Msg),
		ActiveFinalityProvider: &vi,
	}
}

// QueryBtcLightClientTipHeight returns zero for deterministic tests.
func (m *MockBabylonClient) QueryBtcLightClientTipHeight() (uint32, error) {
	return 0, nil
}
