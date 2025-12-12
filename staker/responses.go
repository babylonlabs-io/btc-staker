package staker

// GenerateScriptResponse returns the generated script and its address.
type GenerateScriptResponse struct {
	Script  string `json:"script"`
	Address string `json:"address"`
}

// CreateStakingTransactionResponse wraps the serialized staking transaction.
type CreateStakingTransactionResponse struct {
	TransactionHex string `json:"transactionHex"`
}

// SendTransactionResponse contains information about the broadcast result.
type SendTransactionResponse struct {
	TransactionHashHex string `json:"transactionHashHex"`
	TransactionHex     string `json:"transactionHex"`
}
