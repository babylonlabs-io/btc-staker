// Package client exposes a JSON-RPC client for interacting with stakerservice.
package client

import (
	"context"
	"fmt"

	service "github.com/babylonlabs-io/btc-staker/stakerservice"
	jsonrpcclient "github.com/cometbft/cometbft/rpc/jsonrpc/client"
)

// StakerServiceJSONRPCClient wraps a CometBFT JSON-RPC client for stakerservice.
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

// StakeMultisig initiates a stake transaction using multisig staker keys configured in stakerd.
func (c *StakerServiceJSONRPCClient) StakeMultisig(
	ctx context.Context,
	fundingAddress string,
	stakingAmount int64,
	fpPks []string,
	stakingTimeBlocks int64,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["fundingAddress"] = fundingAddress
	params["stakingAmount"] = stakingAmount
	params["fpBtcPks"] = fpPks
	params["stakingTimeBlocks"] = stakingTimeBlocks

	_, err := c.client.Call(ctx, "stake_multisig", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call stake_multisig: %w", err)
	}
	return result, nil
}

// StakeExpand expand a previous active stake transaction
func (c *StakerServiceJSONRPCClient) StakeExpand(
	ctx context.Context,
	stakerAddress string,
	stakingAmount int64,
	fpPks []string,
	stakingTimeBlocks int64,
	prevActiveStkTxHashHex string,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["stakingAmount"] = stakingAmount
	params["fpBtcPks"] = fpPks
	params["stakingTimeBlocks"] = stakingTimeBlocks
	params["prevActiveStkTxHashHex"] = prevActiveStkTxHashHex

	_, err := c.client.Call(ctx, "stake_expand", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call stake expand: %w", err)
	}
	return result, nil
}

// ConsolidateUTXOs consolidates UTXOs into a single larger UTXO
func (c *StakerServiceJSONRPCClient) ConsolidateUTXOs(
	ctx context.Context,
	stakerAddress string,
	targetAmount int64,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["targetAmount"] = targetAmount

	_, err := c.client.Call(ctx, "consolidate_utxos", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call consolidate_utxos: %w", err)
	}
	return result, nil
}

// BtcDelegationFromBtcStakingTx returns a btc delegation from a btc staking transaction
func (c *StakerServiceJSONRPCClient) BtcDelegationFromBtcStakingTx(
	ctx context.Context,
	stakerAddress string,
	btcStkTxHash string,
	covPksHex []string,
	covenantQuorum uint32,
) (*service.ResultBtcDelegationFromBtcStakingTx, error) {
	result := new(service.ResultBtcDelegationFromBtcStakingTx)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["btcStkTxHash"] = btcStkTxHash
	params["covenantPksHex"] = covPksHex
	params["covenantQuorum"] = covenantQuorum

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

// SpendStakingTransactionMultisig spends a staking transaction using multisig staker keys configured in stakerd.
func (c *StakerServiceJSONRPCClient) SpendStakingTransactionMultisig(ctx context.Context, txHash string) (*service.SpendTxDetails, error) {
	result := new(service.SpendTxDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "spend_stake_multisig", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call spend_stake_multisig: %w", err)
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

// BtcStakingParamByBtcHeight returns the btc staking parameter for the BTC block height from the babylon chain
func (c *StakerServiceJSONRPCClient) BtcStakingParamByBtcHeight(ctx context.Context, btcHeight uint32) (*service.BtcStakingParamsByBtcHeightResponse, error) {
	result := new(service.BtcStakingParamsByBtcHeightResponse)

	params := make(map[string]interface{})
	params["btcHeight"] = btcHeight

	_, err := c.client.Call(ctx, "btc_staking_param_by_btc_height", params, result)
	if err != nil {
		return nil, fmt.Errorf("failed to call btc_staking_param_by_btc_height: %w", err)
	}
	return result, nil
}
