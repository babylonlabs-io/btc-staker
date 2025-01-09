package pop

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/babylonlabs-io/btc-staker/babylonclient/keyringcontroller"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonlabs-io/btc-staker/staker"
	"github.com/babylonlabs-io/btc-staker/types"
	ut "github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/urfave/cli"
)

const (
	msgFlag                 = "msg"
	btcNetworkFlag          = "btc-network"
	btcWalletHostFlag       = "btc-wallet-host"
	btcWalletRPCUserFlag    = "btc-wallet-rpc-user"
	btcWalletRPCPassFlag    = "btc-wallet-rpc-pass"
	btcWalletNameFlag       = "btc-wallet-name"
	btcWalletPassphraseFlag = "btc-wallet-passphrase"
	btcAddressFlag          = "btc-address"
	babyAddressFlag         = "baby-address"
	babyAddressPrefixFlag   = "baby-address-prefix"
	keyringDirFlag          = "keyring-dir"
	keyringBackendFlag      = "keyring-backend"
)

var PopCommands = []cli.Command{
	{
		Name:     "pop",
		Usage:    "Commands realted to generation and verification of the Proof of Possession",
		Category: "PoP commands",
		Subcommands: []cli.Command{
			generateCreatePopCmd,
			generateDeletePopCmd,
		},
	},
}

var generateCreatePopCmd = cli.Command{
	Name:      "generate-create-pop",
	ShortName: "gcp",
	Usage:     "stakercli pop generate-create-pop",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     btcAddressFlag,
			Usage:    "Bitcoin address to generate proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address to generate proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  btcWalletHostFlag,
			Usage: "Bitcoin wallet rpc host",
			Value: "127.0.0.1:18554",
		},
		cli.StringFlag{
			Name:  btcWalletRPCUserFlag,
			Usage: "Bitcoin wallet rpc user",
			Value: "user",
		},
		cli.StringFlag{
			Name:  btcWalletRPCPassFlag,
			Usage: "Bitcoin wallet rpc password",
			Value: "pass",
		},
		cli.StringFlag{
			Name:  btcWalletNameFlag,
			Usage: "Bitcoin wallet name",
			Value: "",
		},
		cli.StringFlag{
			Name:  btcWalletPassphraseFlag,
			Usage: "Bitcoin wallet passphrase",
			Value: "passphrase",
		},
		cli.StringFlag{
			Name:  keyringDirFlag,
			Usage: "Keyring directory",
			Value: "",
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Keyring backend",
			Value: "test",
		},
	},
	Action: generatePop,
}

func generatePop(c *cli.Context) error {
	network := c.String(btcNetworkFlag)

	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return err
	}

	rpcWalletController, err := walletcontroller.NewRPCWalletControllerFromArgs(
		c.String(btcWalletHostFlag),
		c.String(btcWalletRPCUserFlag),
		c.String(btcWalletRPCPassFlag),
		network,
		c.String(btcWalletNameFlag),
		c.String(btcWalletPassphraseFlag),
		types.BitcoindWalletBackend,
		networkParams,
		true,
		"",
		"",
	)
	if err != nil {
		return fmt.Errorf("failed to create rpc wallet controller: %w", err)
	}

	btcAddress, err := btcutil.DecodeAddress(c.String(btcAddressFlag), networkParams)
	if err != nil {
		return fmt.Errorf("failed to decode bitcoin address: %w", err)
	}

	babylonAddress := c.String(babyAddressFlag)
	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	sdkAddressBytes, err := sdk.GetFromBech32(babylonAddress, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	keyringDir := c.String(keyringDirFlag)
	keyringBackend := c.String(keyringBackendFlag)

	keyring, err := keyringcontroller.CreateKeyring(keyringDir, "babylon", keyringBackend, nil)
	if err != nil {
		return err
	}

	popCreator := staker.NewPopCreator(rpcWalletController, keyring)

	popResponse, err := popCreator.CreatePop(btcAddress, babyAddressPrefix, sdkAddress)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(popResponse)

	return nil
}

var generateDeletePopCmd = cli.Command{
	Name:      "generate-delete-pop",
	ShortName: "gpd",
	Usage:     "stakercli pop generate-delete-pop",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     btcAddressFlag,
			Usage:    "Bitcoin address to delete proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address to delete proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:     msgFlag,
			Usage:    "message to sign",
			Required: true,
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  keyringDirFlag,
			Usage: "Keyring directory",
			Value: "",
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Keyring backend",
			Value: "test",
		},
	},
	Action: generateDeletePop,
}

type DeletePopPayload struct {
	BabyAddress   string `json:"babyAddress"`
	BabySignature string `json:"babySignature"`
	BabyPublicKey string `json:"babyPublicKey"`
	BtcAddress    string `json:"btcAddress"`
}

func generateDeletePop(c *cli.Context) error {
	network := c.String(btcNetworkFlag)

	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return err
	}

	btcAddress, err := btcutil.DecodeAddress(c.String(btcAddressFlag), networkParams)
	if err != nil {
		return fmt.Errorf("failed to decode bitcoin address: %w", err)
	}

	babylonAddress := c.String(babyAddressFlag)
	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	sdkAddressBytes, err := sdk.GetFromBech32(babylonAddress, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	keyringDir := c.String(keyringDirFlag)
	keyringBackend := c.String(keyringBackendFlag)

	keyring, err := keyringcontroller.CreateKeyring(keyringDir, "babylon", keyringBackend, nil)
	if err != nil {
		return err
	}

	record, babyPubKey, err := staker.GetBabyPubKey(keyring, sdkAddress)
	if err != nil {
		return err
	}

	msg := c.String(msgFlag)

	// We are assuming we are receiving string literal with escape characters
	interpretedMsg, err := strconv.Unquote(`"` + msg + `"`)
	if err != nil {
		return err
	}

	signature, err := staker.SignCosmosAdr36(
		keyring,
		record.Name,
		sdkAddress.String(),
		[]byte(interpretedMsg),
	)

	payload := DeletePopPayload{
		BabyAddress:   sdkAddress.String(),
		BabySignature: base64.StdEncoding.EncodeToString(signature),
		BabyPublicKey: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
		BtcAddress:    btcAddress.String(),
	}

	helpers.PrintRespJSON(payload)

	return nil
}
