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
)

// NewImageConfig returns ImageConfig needed for running e2e test.
func NewImageConfig(t *testing.T) ImageConfig {
	// TODO: when new docker hub of babylon is released with
	// https://github.com/babylonlabs-io/babylon/pull/655
	// use the babylon version from go.mod.
	// babylondVersion, err := testutil.GetBabylonVersion()
	// require.NoError(t, err)

	return ImageConfig{
		BitcoindRepository: dockerBitcoindRepository,
		BitcoindVersion:    dockerBitcoindVersionTag,
		BabylonRepository:  dockerBabylondRepository,
		BabylonVersion:     "v1.99.0-snapshot.250131",
	}
}
