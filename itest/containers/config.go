// Package containers contains helpers for managing dockerized test dependencies.
package containers

import (
	"testing"
)

// ImageConfig contains all images and their respective tags
// needed for running e2e tests.
type ImageConfig struct {
	BitcoindRepository string
	BitcoindVersion    string
	BabylonRepository  string
	BabylonVersion     string
}

//nolint:deadcode
const (
	dockerBitcoindRepository = "lncm/bitcoind"
	dockerBitcoindVersionTag = "v26.0"
	dockerBabylondRepository = "babylonlabs/babylond"
	// TODO: remove this after publishing feat/staker-multi-sig babylond to the docker hub
	tmpBabylondRepository = "babylonlabs-io/babylond"
	tmpBabylondVersionTag = "latest"
)

// NewImageConfig returns ImageConfig needed for running e2e test.
func NewImageConfig(t *testing.T) ImageConfig {
	// TODO: Temporary fixed babylond version with snapshot tag
	//babylondVersion, err := testutil.GetBabylonVersion()
	//require.NoError(t, err)
	return ImageConfig{
		BitcoindRepository: dockerBitcoindRepository,
		BitcoindVersion:    dockerBitcoindVersionTag,
		BabylonRepository:  tmpBabylondRepository,
		BabylonVersion:     tmpBabylondVersionTag,
	}
}
