// Package types provides common type definitions for the staker daemon.
//
//nolint:revive
package types

import "fmt"

// SupportedNodeBackend represents the supported Bitcoin node backends.
type SupportedNodeBackend int

const (
	// BitcoindNodeBackend represents the bitcoind node backend.
	BitcoindNodeBackend SupportedNodeBackend = iota
	// BtcdNodeBackend represents the btcd node backend.
	BtcdNodeBackend
)

// NewNodeBackend creates a new SupportedNodeBackend from a string.
func NewNodeBackend(backend string) (SupportedNodeBackend, error) {
	switch backend {
	case "btcd":
		return BtcdNodeBackend, nil
	case "bitcoind":
		return BitcoindNodeBackend, nil
	default:
		return BtcdNodeBackend, fmt.Errorf("invalid node type: %s", backend)
	}
}
