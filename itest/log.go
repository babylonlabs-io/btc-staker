//go:build e2e
// +build e2e

package e2etest

import (
	"github.com/babylonlabs-io/btc-staker/stakercfg"
)

var (
	zapLogger, _ = stakercfg.NewRootLogger("auto", "debug")
)
