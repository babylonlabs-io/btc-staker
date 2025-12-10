// nolint: revive
package types

import "fmt"

// SupportedWalletBackend represents the supported Bitcoin wallet backends.
type SupportedWalletBackend int

const (
	// BitcoindWalletBackend represents the bitcoind wallet backend.
	BitcoindWalletBackend SupportedWalletBackend = iota
	// BtcwalletWalletBackend represents the btcwallet backend.
	BtcwalletWalletBackend
)

// NewWalletBackend returns the supported backend
func NewWalletBackend(backend string) (SupportedWalletBackend, error) {
	switch backend {
	case "btcwallet":
		return BtcwalletWalletBackend, nil
	case "bitcoind":
		return BitcoindWalletBackend, nil
	default:
		return BtcwalletWalletBackend, fmt.Errorf("invalid wallet type: %s", backend)
	}
}
