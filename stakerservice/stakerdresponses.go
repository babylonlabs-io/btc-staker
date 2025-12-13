package stakerservice

import (
	"github.com/btcsuite/btcd/btcjson"
)

// ResultHealth represents the empty response for the health RPC.
type ResultHealth struct{}

// ResultBtcDelegationFromBtcStakingTx contains the Babylon delegation hash.
type ResultBtcDelegationFromBtcStakingTx struct {
	BabylonBTCDelegationTxHash string `json:"babylon_btc_delegation_tx_hash"`
}

// ResultStake wraps the staking transaction hash.
type ResultStake struct {
	TxHash string `json:"tx_hash"`
}

// StakingDetails summarizes a staking transaction returned by the RPC API.
type StakingDetails struct {
	StakingTxHash  string `json:"staking_tx_hash"`
	StakerAddress  string `json:"staker_address"`
	StakingState   string `json:"staking_state"`
	TransactionIdx string `json:"transaction_idx"`
}

// OutputDetail describes a transaction output and its address.
type OutputDetail struct {
	Amount  string `json:"amount"`
	Address string `json:"address"`
}

// OutputsResponse contains a list of spendable outputs.
type OutputsResponse struct {
	Outputs []OutputDetail `json:"outputs"`
}

// SpendTxDetails provides details about a spend transaction from the API.
type SpendTxDetails struct {
	TxHash  string `json:"tx_hash"`
	TxValue string `json:"tx_value"`
}

// FinalityProviderInfoResponse contains identifying information about a finality provider.
type FinalityProviderInfoResponse struct {
	// bech 32 encoded Babylon address
	BabylonAddress string `json:"babylon_address"`
	// Hex encoded Bitcoin public secp256k1 key in BIP340 format
	BtcPublicKey string `json:"bitcoin_public_Key"`
}

// FinalityProvidersResponse contains a paginated set of finality providers.
type FinalityProvidersResponse struct {
	FinalityProviders           []FinalityProviderInfoResponse `json:"finality_providers"`
	TotalFinalityProvidersCount string                         `json:"total_finality_providers_count"`
}

// ListStakingTransactionsResponse returns a page of staking transaction details.
type ListStakingTransactionsResponse struct {
	Transactions          []StakingDetails `json:"transactions"`
	TotalTransactionCount string           `json:"total_transaction_count"`
}

// UnbondingResponse wraps the unbonding tx hash returned by the RPC.
type UnbondingResponse struct {
	UnbondingTxHash string `json:"unbonding_tx_hash"`
}

// WithdrawableTransactionsResponse contains paginated withdrawable staking transactions.
type WithdrawableTransactionsResponse struct {
	Transactions                     []StakingDetails `json:"transactions"`
	LastWithdrawableTransactionIndex string           `json:"last_transaction_index"`
	TotalTransactionCount            string           `json:"total_transaction_count"`
}

// BtcTxAndBlockResponse bundles a BTC transaction with its containing block header.
type BtcTxAndBlockResponse struct {
	Tx  *btcjson.TxRawResult                 `json:"tx"`
	Blk *btcjson.GetBlockHeaderVerboseResult `json:"blk"`
}

// BtcStakingParamsByBtcHeightResponse returns staking parameters at a specific BTC height.
type BtcStakingParamsByBtcHeightResponse struct {
	StakingParams BtcStakingParams `json:"staking_params"`
}

// BtcStakingParams represents the subset of staking parameters exposed over RPC.
type BtcStakingParams struct {
	CovenantPkHex  []string
	CovenantQuorum uint32
}
