package staker

import (
	cl "github.com/babylonlabs-io/btc-staker/babylonclient"
	ut "github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/chaincfg"
)

// Controller handles wallet and Babylon client operations used by the CLI.
type Controller struct {
	BabylonClient cl.BabylonClient
	Wc            walletcontroller.WalletController
	network       *chaincfg.Params
}

// NewStakerControllerFromClients builds a Controller from the provided wallet
// and Babylon clients.
func NewStakerControllerFromClients(
	wc walletcontroller.WalletController,
	babylonClient cl.BabylonClient,
) (*Controller, error) {
	networkName := wc.NetworkName()

	params, err := ut.GetBtcNetworkParams(networkName)

	if err != nil {
		return nil, err
	}

	return &Controller{
		Wc:            wc,
		network:       params,
		BabylonClient: babylonClient,
	}, err
}
