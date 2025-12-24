// Package e2etest contains helpers for integration tests against dockerized nodes.
package e2etest

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/babylonlabs-io/btc-staker/itest/containers"
	"github.com/stretchr/testify/require"
)

var (
	startTimeout = 30 * time.Second
)

// CreateWalletResponse mirrors the JSON response from bitcoind's createwallet RPC.
type CreateWalletResponse struct {
	Name    string `json:"name"`
	Warning string `json:"warning"`
}

// GenerateBlockResponse contains the addresses and hashes returned by generateblocks.
type GenerateBlockResponse struct {
	// address of the recipient of rewards
	Address string `json:"address"`
	// blocks generated
	Blocks []string `json:"blocks"`
}

// BitcoindTestHandler orchestrates bitcoind docker resources for tests.
type BitcoindTestHandler struct {
	t             *testing.T
	m             *containers.Manager
	defaultWallet string
}

// NewBitcoindHandler creates a new test helper for managing bitcoind.
func NewBitcoindHandler(t *testing.T, m *containers.Manager) *BitcoindTestHandler {
	return &BitcoindTestHandler{
		t: t,
		m: m,
	}
}

// Start launches bitcoind inside docker and waits until it responds.
func (h *BitcoindTestHandler) Start() *dockertest.Resource {
	tempPath, err := os.MkdirTemp("", "bitcoind-staker-test-*")
	require.NoError(h.t, err)

	h.t.Cleanup(func() {
		_ = os.RemoveAll(tempPath)
	})

	bitcoinResource, err := h.m.RunBitcoindResource(h.t, tempPath)
	require.NoError(h.t, err)

	h.t.Cleanup(func() {
		_ = h.m.ClearResources()
	})

	require.Eventually(h.t, func() bool {
		_, err := h.GetBlockCount()
		h.t.Logf("failed to get block count: %v", err)
		return err == nil
	}, startTimeout, 500*time.Millisecond, "bitcoind did not start")

	return bitcoinResource
}

// GetBlockCount queries bitcoind for the current block height.
func (h *BitcoindTestHandler) GetBlockCount() (int, error) {
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, []string{"getblockcount"})
	if err != nil {
		return 0, err
	}

	buffStr := buff.String()

	parsedBuffStr := strings.TrimSuffix(buffStr, "\n")

	num, err := strconv.Atoi(parsedBuffStr)
	if err != nil {
		return 0, err
	}

	return num, nil
}

// CreateWallet provisions a legacy wallet for integration tests.
func (h *BitcoindTestHandler) CreateWallet(walletName string, passphrase string) *CreateWalletResponse {
	return h.CreateWalletWithDescriptor(walletName, passphrase, false)
}

// CreateWalletWithDescriptor provisions a wallet, allowing descriptor wallets when needed.
func (h *BitcoindTestHandler) CreateWalletWithDescriptor(walletName string, passphrase string, isDescriptor bool) *CreateWalletResponse {
	// last bool flag controls descriptors. Legacy wallets are needed when we must dump privkeys;
	// descriptor wallets are needed for taproot address generation.
	descFlag := "false"
	if isDescriptor {
		descFlag = "true"
	}
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, []string{"createwallet", walletName, "false", "false", passphrase, "false", descFlag})
	require.NoError(h.t, err)

	var response CreateWalletResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(h.t, err)

	// remember first wallet as default for mining/generation
	// NOTE: for current e2e test, it will be test-wallet
	if h.defaultWallet == "" {
		h.defaultWallet = walletName
	}

	return &response
}

// GenerateBlocks mines the requested number of blocks and returns their info.
func (h *BitcoindTestHandler) GenerateBlocks(count int) *GenerateBlockResponse {
	cmd := []string{"-generate", fmt.Sprintf("%d", count)}
	if h.defaultWallet != "" {
		cmd = append([]string{"-rpcwallet=" + h.defaultWallet}, cmd...)
	}
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, cmd)
	require.NoError(h.t, err)

	var response GenerateBlockResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(h.t, err)

	return &response
}
