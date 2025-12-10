// Package helpers contains CLI helper constants used by stakercli commands.
package helpers

import (
	"strconv"

	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
)

// Common CLI flag names used across commands.
const (
	StakingAmountFlag        = "staking-amount"
	StakingTimeBlocksFlag    = "staking-time"
	StakingDaemonAddressFlag = "daemon-address"
	TxInclusionHeightFlag    = "tx-inclusion-height"
)

var (
	// DefaultStakingDaemonAddress is the default RPC address for stakerd.
	DefaultStakingDaemonAddress = "tcp://127.0.0.1:" + strconv.Itoa(scfg.DefaultRPCPort)
)
