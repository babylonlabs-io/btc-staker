package pop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/babylonlabs-io/babylon/crypto/bip322"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/urfave/cli"

	"github.com/babylonlabs-io/btc-staker/babylonclient/keyringcontroller"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonlabs-io/btc-staker/staker"
	"github.com/babylonlabs-io/btc-staker/types"
	ut "github.com/babylonlabs-io/btc-staker/utils"
	"github.com/babylonlabs-io/btc-staker/walletcontroller"
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
	outputFileFlag          = "output-file"
)

var PopCommands = []cli.Command{
	{
		Name:     "pop",
		Usage:    "Commands about proof-of-possession generation and verification",
		Category: "PoP commands",
		Subcommands: []cli.Command{
			GenerateCreatePopCmd,
			generateDeletePopCmd,
			signCosmosAdr36Cmd,
			ValidatePopCmd,
		},
	},
}

var GenerateCreatePopCmd = cli.Command{
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
		cli.StringFlag{
			Name:  outputFileFlag,
			Usage: "Path to output JSON file",
			Value: "",
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

	if outputPath := c.String(outputFileFlag); outputPath != "" {
		// Convert response to JSON
		jsonBytes, err := json.MarshalIndent(popResponse, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal response to JSON: %w", err)
		}

		// Write to file
		if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	helpers.PrintRespJSON(popResponse)

	return nil
}

var ValidatePopCmd = cli.Command{
	Name:      "validate",
	ShortName: "vp",
	Usage:     "stakercli pop validate <path-to-pop.json>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
	},
	Action:    validatePop,
	ArgsUsage: "<path-to-pop.json>",
}

func validatePop(c *cli.Context) error {
	if c.NArg() != 1 {
		return fmt.Errorf("expected 1 argument (pop file path), got %d", c.NArg())
	}

	// Read and parse the PoP file
	popFilePath := c.Args().First()
	popFileBytes, err := os.ReadFile(popFilePath)
	if err != nil {
		return fmt.Errorf("failed to read pop file: %w", err)
	}

	var popResponse staker.Response
	if err := json.Unmarshal(popFileBytes, &popResponse); err != nil {
		return fmt.Errorf("failed to parse pop file: %w", err)
	}

	// Get network params
	network := c.String(btcNetworkFlag)
	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return fmt.Errorf("failed to get btc network params: %w", err)
	}

	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	err = ValidatePop(popResponse, networkParams, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("pop validation failed: %w", err)
	}

	fmt.Println("Proof of Possession is valid!")

	return nil
}

func ValidatePop(popResponse staker.Response, btcNetParams *chaincfg.Params, babyPrefix string) error {
	err := ValidateBTCSignBaby(popResponse.BTCAddress, popResponse.BabyAddress, popResponse.BTCSignBaby, babyPrefix, btcNetParams)
	if err != nil {
		return fmt.Errorf("invalid btcSignBaby: %w", err)
	}

	err = ValidateBabySignBTC(popResponse.BabyPublicKey, popResponse.BabyAddress, popResponse.BTCAddress, popResponse.BabySignBTC)
	if err != nil {
		return fmt.Errorf("invalid babySignBtc: %w", err)
	}

	return nil
}

func ValidateBTCSignBaby(btcAddr, babyAddr, btcSignBaby, babyPrefix string, btcNetParams *chaincfg.Params) error {
	btcAddress, err := btcutil.DecodeAddress(btcAddr, btcNetParams)
	if err != nil {
		return fmt.Errorf("failed to decode bitcoin address: %w", err)
	}

	sdkAddressBytes, err := sdk.GetFromBech32(babyAddr, babyPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	bech32cosmosAddressString, err := sdk.Bech32ifyAddressBytes(babyPrefix, sdkAddress.Bytes())
	if err != nil {
		return fmt.Errorf("failed to get babylon address bytes: %w", err)
	}

	schnorrSigBase64, err := base64.StdEncoding.DecodeString(btcSignBaby)
	if err != nil {
		return fmt.Errorf("failed to decode btcSignBaby: %w", err)
	}

	witness, err := bip322.SimpleSigToWitness(schnorrSigBase64)
	if err != nil {
		return fmt.Errorf("failed to convert btcSignBaby to witness: %w", err)
	}

	return bip322.Verify(
		[]byte(bech32cosmosAddressString),
		witness,
		btcAddress,
		btcNetParams,
	)
}

func ValidateBabySignBTC(babyPk, babyAddr, btcAddress, babySigOverBTCPk string) error {
	babyPubKeyBz, err := base64.StdEncoding.DecodeString(babyPk)
	if err != nil {
		return fmt.Errorf("failed to decode babyPublicKey: %w", err)
	}

	babyPubKey := &secp256k1.PubKey{
		Key: babyPubKeyBz,
	}

	babySignBTC := []byte(btcAddress)
	base64Bytes := base64.StdEncoding.EncodeToString(babySignBTC)
	babySignBtcDoc := staker.NewCosmosSignDoc(babyAddr, base64Bytes)
	babySignBtcMarshaled, err := json.Marshal(babySignBtcDoc)
	if err != nil {
		return fmt.Errorf("failed to marshalling cosmos sign doc: %w", err)
	}

	babySignBtcBz := sdk.MustSortJSON(babySignBtcMarshaled)

	secp256SigBase64, err := base64.StdEncoding.DecodeString(babySigOverBTCPk)
	if err != nil {
		return fmt.Errorf("failed to decode babySignBTC: %w", err)
	}

	if !babyPubKey.VerifySignature(babySignBtcBz, secp256SigBase64) {
		return fmt.Errorf("invalid babySignBtc")
	}

	return nil
}

var generateDeletePopCmd = cli.Command{
	Name:      "generate-delete-pop",
	ShortName: "gdp",
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

	if err != nil {
		return err
	}

	payload := DeletePopPayload{
		BabyAddress:   sdkAddress.String(),
		BabySignature: base64.StdEncoding.EncodeToString(signature),
		BabyPublicKey: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
		BtcAddress:    btcAddress.String(),
	}

	helpers.PrintRespJSON(payload)

	return nil
}

type SignatureResponse struct {
	BabyAddress   string `json:"babyAddress"`
	BabySignature string `json:"babySignature"`
	BabyPublicKey string `json:"babyPublicKey"`
}

var signCosmosAdr36Cmd = cli.Command{
	Name:      "sign-cosmos-adr36",
	ShortName: "sc",
	Usage:     "stakercli pop sign-cosmos-adr36",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address for which signature is to be generated",
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
	Action: signCosmosAdr36,
}

func signCosmosAdr36(c *cli.Context) error {
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

	if err != nil {
		return err
	}

	response := SignatureResponse{
		BabyAddress:   sdkAddress.String(),
		BabySignature: base64.StdEncoding.EncodeToString(signature),
		BabyPublicKey: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
	}

	helpers.PrintRespJSON(response)

	return nil
}
