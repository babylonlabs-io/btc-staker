package containers

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	bbn "github.com/babylonlabs-io/babylon/types"
	"github.com/babylonlabs-io/btc-staker/itest/testutil"
	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
)

const (
	bitcoindContainerName = "bitcoind"
	babylondContainerName = "babylond"
)

var errRegex = regexp.MustCompile(`(E|e)rror`)

// Manager is a wrapper around all Docker instances, and the Docker API.
// It provides utilities to run and interact with all Docker containers used within e2e testing.
type Manager struct {
	cfg       ImageConfig
	pool      *dockertest.Pool
	resources map[string]*dockertest.Resource
}

// NewManager creates a new Manager instance and initializes
// all Docker specific utilities. Returns an error if initialization fails.
func NewManager(t *testing.T) (docker *Manager, err error) {
	docker = &Manager{
		cfg:       NewImageConfig(t),
		resources: make(map[string]*dockertest.Resource),
	}
	docker.pool, err = dockertest.NewPool("")
	if err != nil {
		return nil, err
	}
	return docker, nil
}

func (m *Manager) ExecBitcoindCliCmd(t *testing.T, command []string) (bytes.Buffer, bytes.Buffer, error) {
	// this is currently hardcoded, as it will be the same for all tests
	cmd := []string{"bitcoin-cli", "-chain=regtest", "-rpcuser=user", "-rpcpassword=pass"}
	cmd = append(cmd, command...)
	return m.ExecCmd(t, bitcoindContainerName, cmd)
}

// ExecCmd executes command by running it on the given container.
// It word for word `error` in output to discern between error and regular output.
// It retures stdout and stderr as bytes.Buffer and an error if the command fails.
func (m *Manager) ExecCmd(t *testing.T, containerName string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	if _, ok := m.resources[containerName]; !ok {
		return bytes.Buffer{}, bytes.Buffer{}, fmt.Errorf("no resource %s found", containerName)
	}
	containerId := m.resources[containerName].Container.ID

	var (
		outBuf bytes.Buffer
		errBuf bytes.Buffer
	)

	timeout := 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Logf("\n\nRunning: \"%s\"", command)

	// We use the `require.Eventually` function because it is only allowed to do one transaction per block without
	// sequence numbers. For simplicity, we avoid keeping track of the sequence number and just use the `require.Eventually`.
	require.Eventually(
		t,
		func() bool {
			exec, err := m.pool.Client.CreateExec(docker.CreateExecOptions{
				Context:      ctx,
				AttachStdout: true,
				AttachStderr: true,
				Container:    containerId,
				User:         "root",
				Cmd:          command,
			})

			if err != nil {
				t.Logf("failed to create exec: %v", err)
				return false
			}

			err = m.pool.Client.StartExec(exec.ID, docker.StartExecOptions{
				Context:      ctx,
				Detach:       false,
				OutputStream: &outBuf,
				ErrorStream:  &errBuf,
			})
			if err != nil {
				t.Logf("failed to start exec: %v", err)
				return false
			}

			errBufString := errBuf.String()
			// Note that this does not match all errors.
			// This only works if CLI outputs "Error" or "error"
			// to stderr.
			if errRegex.MatchString(errBufString) {
				t.Log("\nstderr:")
				t.Log(errBufString)

				t.Log("\nstdout:")
				t.Log(outBuf.String())
				return false
			}

			return true
		},
		timeout,
		500*time.Millisecond,
		"command failed",
	)

	return outBuf, errBuf, nil
}

func (m *Manager) RunBitcoindResource(
	t *testing.T,
	bitcoindCfgPath string,
) (*dockertest.Resource, error) {
	bitcoindResource, err := m.pool.RunWithOptions(
		&dockertest.RunOptions{
			Name:       fmt.Sprintf("%s-%s", bitcoindContainerName, t.Name()),
			Repository: m.cfg.BitcoindRepository,
			Tag:        m.cfg.BitcoindVersion,
			User:       "root:root",
			Mounts: []string{
				fmt.Sprintf("%s/:/data/.bitcoin", bitcoindCfgPath),
			},
			Labels: map[string]string{
				"e2e": "bitcoind",
			},
			ExposedPorts: []string{
				"18443/tcp",
			},
			Cmd: []string{
				"-regtest",
				"-txindex",
				"-rpcuser=user",
				"-rpcpassword=pass",
				"-rpcallowip=0.0.0.0/0",
				"-rpcbind=0.0.0.0",
			},
		},
		func(config *docker.HostConfig) {
			config.PortBindings = map[docker.Port][]docker.PortBinding{
				"18443/tcp": {{HostIP: "", HostPort: strconv.Itoa(testutil.AllocateUniquePort(t))}}, // only expose what we need
			}
			config.PublishAllPorts = false // because in dockerfile they already expose them
		},
		noRestart,
	)
	if err != nil {
		return nil, err
	}
	m.resources[bitcoindContainerName] = bitcoindResource

	return bitcoindResource, nil
}

// RunBabylondResource starts a babylond container
func (m *Manager) RunBabylondResource(
	t *testing.T,
	mounthPath string,
	coventantQuorum int,
	baseHeaderHex string,
	slashingPkScript string,
	covenantPks ...*btcec.PublicKey,
) (*dockertest.Resource, error) {
	covenantPksStr := make([]string, len(covenantPks))
	for i, cvPk := range covenantPks {
		covenantPksStr[i] = bbn.NewBIP340PubKeyFromBTCPK(cvPk).MarshalHex()
	}

	cmd := []string{
		"sh", "-c", fmt.Sprintf(
			"babylond testnet --v=1 --output-dir=/home --starting-ip-address=192.168.10.2 "+
				"--keyring-backend=test --chain-id=chain-test --btc-finalization-timeout=4 "+
				"--btc-confirmation-depth=2 --unbonding-time=5 --additional-sender-account --btc-network=regtest "+
				"--min-staking-time-blocks=200 --min-staking-amount-sat=10000 "+
				"--slashing-pk-script=%s --btc-base-header=%s --covenant-quorum=%d "+
				"--covenant-pks=%s && chmod -R 777 /home && "+
				"babylond start --home=/home/node0/babylond",
			slashingPkScript, baseHeaderHex, coventantQuorum, strings.Join(covenantPksStr, ",")),
	}

	resource, err := m.pool.RunWithOptions(
		&dockertest.RunOptions{
			Name:       fmt.Sprintf("%s-%s", babylondContainerName, t.Name()),
			Repository: m.cfg.BabylonRepository,
			Tag:        m.cfg.BabylonVersion,
			Labels: map[string]string{
				"e2e": "babylond",
			},
			User: "root:root",
			Mounts: []string{
				fmt.Sprintf("%s/:/home/", mounthPath),
			},
			ExposedPorts: []string{
				"9090/tcp", // only expose what we need
				"26657/tcp",
			},
			Cmd: cmd,
		},
		func(config *docker.HostConfig) {
			config.PortBindings = map[docker.Port][]docker.PortBinding{
				"9090/tcp":  {{HostIP: "", HostPort: strconv.Itoa(testutil.AllocateUniquePort(t))}},
				"26657/tcp": {{HostIP: "", HostPort: strconv.Itoa(testutil.AllocateUniquePort(t))}},
			}
		},
		noRestart,
	)
	if err != nil {
		return nil, err
	}

	m.resources[babylondContainerName] = resource

	return resource, nil
}

// BabylondTxBankSend send transaction to an address from the node address.
func (m *Manager) BabylondTxBankSend(t *testing.T, addr, coins, walletName string) (bytes.Buffer, bytes.Buffer, error) {
	flags := []string{
		"babylond",
		"tx",
		"bank",
		"send",
		walletName,
		addr,
		coins,
		"--keyring-backend=test",
		"--home=/home/node0/babylond",
		"--log_level=debug",
		"--chain-id=chain-test",
		"-b=sync", "--yes", "--gas-prices=10ubbn",
	}

	return m.ExecCmd(t, babylondContainerName, flags)
}

// BabylondTxBankMultiSend send transaction to an addresses from the node address.
func (m *Manager) BabylondTxBankMultiSend(t *testing.T, walletName string, coins string, addresses ...string) (bytes.Buffer, bytes.Buffer, error) {
	// babylond tx bank multi-send [from_key_or_address] [to_address_1 to_address_2 ...] [amount] [flags]
	switch len(addresses) {
	case 0:
		return bytes.Buffer{}, bytes.Buffer{}, nil
	case 1:
		return m.BabylondTxBankSend(t, addresses[0], coins, walletName)
	}

	flags := []string{
		"babylond",
		"tx",
		"bank",
		"multi-send",
		walletName,
	}
	flags = append(flags, addresses...)
	flags = append(flags,
		coins,
		"--keyring-backend=test",
		"--home=/home/node0/babylond",
		"--log_level=debug",
		"--chain-id=chain-test",
		"-b=sync", "--yes", "--gas-prices=10ubbn",
	)

	return m.ExecCmd(t, babylondContainerName, flags)
}

// ClearResources removes all outstanding Docker resources created by the Manager.
func (m *Manager) ClearResources() error {
	for _, resource := range m.resources {
		if err := m.pool.Purge(resource); err != nil {
			return err
		}
	}

	return nil
}

func noRestart(config *docker.HostConfig) {
	// in this case we don't want the nodes to restart on failure
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}
