package helpers

import (
	"strconv"

	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
)

const (
	StakingAmountFlag        = "staking-amount"
	StakingTimeBlocksFlag    = "staking-time"
	SendToBabylonFirstFlag   = "send-to-babylon-first"
	StakingDaemonAddressFlag = "daemon-address"
	TxInclusionHeightFlag    = "tx-inclusion-height"
)

var (
	DefaultStakingDaemonAddress = "tcp://127.0.0.1:" + strconv.Itoa(scfg.DefaultRPCPort)
)
