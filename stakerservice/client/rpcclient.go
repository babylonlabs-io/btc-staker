package client

import (
	"context"
	"encoding/hex"
	"fmt"

	service "github.com/babylonlabs-io/btc-staker/stakerservice"
	"github.com/babylonlabs-io/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcec/v2"
	jsonrpcclient "github.com/cometbft/cometbft/rpc/jsonrpc/client"
)

type StakerServiceJSONRPCClient struct {
	client *jsonrpcclient.Client
}

// NewStakerServiceJSONRPCClient creates a new instance of StakerServiceJSONRPCClient
// TODO Add some kind of timeout config
func NewStakerServiceJSONRPCClient(remoteAddress string) (*StakerServiceJSONRPCClient, error) {
	client, err := jsonrpcclient.New(remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}

	return &StakerServiceJSONRPCClient{
		client: client,
	}, nil
}

// Health returns a health check response
func (c *StakerServiceJSONRPCClient) Health(ctx context.Context) (*service.ResultHealth, error) {
	result := new(service.ResultHealth)
	_, err := c.client.Call(ctx, "health", map[string]interface{}{}, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call health: %w", err)
	}
	return result, nil
}

// ListOutputs returns a list of outputs
func (c *StakerServiceJSONRPCClient) ListOutputs(ctx context.Context) (*service.OutputsResponse, error) {
	result := new(service.OutputsResponse)
	_, err := c.client.Call(ctx, "list_outputs", map[string]interface{}{}, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call list_outputs: %w", err)
	}
	return result, nil
}

// BabylonFinalityProviders returns a list of finality providers
func (c *StakerServiceJSONRPCClient) BabylonFinalityProviders(ctx context.Context, offset *int, limit *int) (*service.FinalityProvidersResponse, error) {
	result := new(service.FinalityProvidersResponse)

	params := make(map[string]interface{})

	if limit != nil {
		params["limit"] = limit
	}

	if offset != nil {
		params["offset"] = offset
	}

	_, err := c.client.Call(ctx, "babylon_finality_providers", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call babylon_finality_providers: %w", err)
	}
	return result, nil
}

// Stake initiates a stake transaction
func (c *StakerServiceJSONRPCClient) Stake(
	ctx context.Context,
	stakerAddress string,
	stakingAmount int64,
	fpPks []string,
	stakingTimeBlocks int64,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["stakingAmount"] = stakingAmount
	params["fpBtcPks"] = fpPks
	params["stakingTimeBlocks"] = stakingTimeBlocks

	_, err := c.client.Call(ctx, "stake", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call stake: %w", err)
	}
	return result, nil
}

// BtcDelegationFromBtcStakingTx returns a btc delegation from a btc staking transaction
func (c *StakerServiceJSONRPCClient) BtcDelegationFromBtcStakingTx(
	ctx context.Context,
	stakerAddress string,
	btcStkTxHash string,
	versionedParams *parser.ParsedVersionedGlobalParams,
) (*service.ResultBtcDelegationFromBtcStakingTx, error) {
	result := new(service.ResultBtcDelegationFromBtcStakingTx)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["btcStkTxHash"] = btcStkTxHash
	params["tag"] = versionedParams.Tag
	params["covenantPksHex"] = parseCovenantsPubKeyToHex(versionedParams.CovenantPks...)
	params["covenantQuorum"] = versionedParams.CovenantQuorum

	_, err := c.client.Call(ctx, "btc_delegation_from_btc_staking_tx", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call btc_delegation_from_btc_staking_tx: %w", err)
	}
	return result, nil
}

// BtcTxDetails returns a btc transaction and block details
func (c *StakerServiceJSONRPCClient) BtcTxDetails(
	ctx context.Context,
	txHash string,
) (*service.BtcTxAndBlockResponse, error) {
	result := new(service.BtcTxAndBlockResponse)

	params := make(map[string]interface{})
	params["txHashStr"] = txHash

	_, err := c.client.Call(ctx, "btc_tx_blk_details", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call btc_tx_blk_details: %w", err)
	}
	return result, nil
}

// parseCovenantsPubKeyToHex parses public keys into serialized compressed
func parseCovenantsPubKeyToHex(pks ...*btcec.PublicKey) []string {
	pksHex := make([]string, len(pks))
	for i, pk := range pks {
		pksHex[i] = parseCovenantPubKeyToHex(pk)
	}
	return pksHex
}

// parseCovenantPubKeyFromHex parses public key into serialized compressed
// with 33 bytes and in hex string
func parseCovenantPubKeyToHex(pk *btcec.PublicKey) string {
	return hex.EncodeToString(pk.SerializeCompressed())
}

// ListStakingTransactions returns a list of staking transactions
func (c *StakerServiceJSONRPCClient) ListStakingTransactions(ctx context.Context, offset *int, limit *int) (*service.ListStakingTransactionsResponse, error) {
	result := new(service.ListStakingTransactionsResponse)

	params := make(map[string]interface{})

	if limit != nil {
		params["limit"] = limit
	}

	if offset != nil {
		params["offset"] = offset
	}

	_, err := c.client.Call(ctx, "list_staking_transactions", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call list_staking_transactions: %w", err)
	}
	return result, nil
}

// WithdrawableTransactions returns a list of withdrawable transactions
func (c *StakerServiceJSONRPCClient) WithdrawableTransactions(ctx context.Context, offset *int, limit *int) (*service.WithdrawableTransactionsResponse, error) {
	result := new(service.WithdrawableTransactionsResponse)

	params := make(map[string]interface{})

	if limit != nil {
		params["limit"] = limit
	}

	if offset != nil {
		params["offset"] = offset
	}

	_, err := c.client.Call(ctx, "withdrawable_transactions", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call withdrawable_transactions: %w", err)
	}
	return result, nil
}

// StakingDetails returns a staking details
func (c *StakerServiceJSONRPCClient) StakingDetails(ctx context.Context, txHash string) (*service.StakingDetails, error) {
	result := new(service.StakingDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "staking_details", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call staking_details: %w", err)
	}
	return result, nil
}

// SpendStakingTransaction returns a spend staking transaction details
func (c *StakerServiceJSONRPCClient) SpendStakingTransaction(ctx context.Context, txHash string) (*service.SpendTxDetails, error) {
	result := new(service.SpendTxDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "spend_stake", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call spend_stake: %w", err)
	}
	return result, nil
}

// UnbondStaking returns an unbond staking transaction details
func (c *StakerServiceJSONRPCClient) UnbondStaking(ctx context.Context, txHash string) (*service.UnbondingResponse, error) {
	result := new(service.UnbondingResponse)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "unbond_staking", params, result)

	if err != nil {
		return nil, fmt.Errorf("failed to call unbond_staking: %w", err)
	}
	return result, nil
}

// BtcStakingParameters returns an slice of staking parameters from the babylon chain
func (c *StakerServiceJSONRPCClient) BtcStakingParameters(ctx context.Context) (*service.BtcStakingParametersResponse, error) {
	result := new(service.BtcStakingParametersResponse)

	params := make(map[string]interface{})
	_, err := c.client.Call(ctx, "btc_staking_parameters", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call btc_staking_parameters: %w", err)
	}
	return result, nil
}
