package client

import (
	"context"
	"encoding/hex"

	service "github.com/babylonlabs-io/btc-staker/stakerservice"
	"github.com/babylonlabs-io/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcec/v2"
	jsonrpcclient "github.com/cometbft/cometbft/rpc/jsonrpc/client"
)

type StakerServiceJSONRPCClient struct {
	client *jsonrpcclient.Client
}

// TODO Add some kind of timeout config
func NewStakerServiceJSONRPCClient(remoteAddress string) (*StakerServiceJSONRPCClient, error) {
	client, err := jsonrpcclient.New(remoteAddress)
	if err != nil {
		return nil, err
	}

	return &StakerServiceJSONRPCClient{
		client: client,
	}, nil
}

func (c *StakerServiceJSONRPCClient) Health(ctx context.Context) (*service.ResultHealth, error) {
	result := new(service.ResultHealth)
	_, err := c.client.Call(ctx, "health", map[string]interface{}{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) ListOutputs(ctx context.Context) (*service.OutputsResponse, error) {
	result := new(service.OutputsResponse)
	_, err := c.client.Call(ctx, "list_outputs", map[string]interface{}{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

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
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) Stake(
	ctx context.Context,
	stakerAddress string,
	stakingAmount int64,
	fpPks []string,
	stakingTimeBlocks int64,
	sendToBabylonFirst bool,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["stakingAmount"] = stakingAmount
	params["fpBtcPks"] = fpPks
	params["stakingTimeBlocks"] = stakingTimeBlocks
	params["sendToBabylonFirst"] = sendToBabylonFirst

	_, err := c.client.Call(ctx, "stake", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

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
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) BtcTxDetails(
	ctx context.Context,
	txHash string,
) (*service.BtcTxAndBlockResponse, error) {
	result := new(service.BtcTxAndBlockResponse)

	params := make(map[string]interface{})
	params["txHashStr"] = txHash

	_, err := c.client.Call(ctx, "btc_tx_blk_details", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

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
		return nil, err
	}
	return result, nil
}

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
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) StakingDetails(ctx context.Context, txHash string) (*service.StakingDetails, error) {
	result := new(service.StakingDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "staking_details", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) SpendStakingTransaction(ctx context.Context, txHash string) (*service.SpendTxDetails, error) {
	result := new(service.SpendTxDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "spend_stake", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) WatchStaking(
	ctx context.Context,
	stakingTx string,
	stakingTime int,
	stakingValue int,
	stakerBtcPk string,
	fpBtcPks []string,
	slashingTx string,
	slashingTxSig string,
	stakerBabylonAddr string,
	stakerAddress string,
	stakerBtcSig string,
	unbondingTx string,
	slashUnbondingTx string,
	slashUnbondingTxSig string,
	unbondingTime int,
	popType int,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)
	params := make(map[string]interface{})
	params["stakingTx"] = stakingTx
	params["stakingTime"] = stakingTime
	params["stakingValue"] = stakingValue
	params["stakerBtcPk"] = stakerBtcPk
	params["fpBtcPks"] = fpBtcPks
	params["slashingTx"] = slashingTx
	params["slashingTxSig"] = slashingTxSig
	params["stakerBabylonAddr"] = stakerBabylonAddr
	params["stakerAddress"] = stakerAddress
	params["stakerBtcSig"] = stakerBtcSig
	params["unbondingTx"] = unbondingTx
	params["slashUnbondingTx"] = slashUnbondingTx
	params["slashUnbondingTxSig"] = slashUnbondingTxSig
	params["unbondingTime"] = unbondingTime
	params["popType"] = popType

	_, err := c.client.Call(ctx, "watch_staking_tx", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJSONRPCClient) UnbondStaking(ctx context.Context, txHash string) (*service.UnbondingResponse, error) {
	result := new(service.UnbondingResponse)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "unbond_staking", params, result)

	if err != nil {
		return nil, err
	}
	return result, nil
}
